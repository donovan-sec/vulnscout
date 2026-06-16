"""
Core agentic loop -- feeds code/context to Claude, parses hypotheses,
runs verifier, feeds results back. Both modes share this engine.

Independent verifier pattern: every PoC goes through a second fresh Claude
call that only sees the PoC + source context, with instructions to actively
disprove the finding. Only if it can't disprove it does the finding proceed
to binary/HTTP verification and get recorded.
"""

import re
import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()
client = anthropic.Anthropic()

REPO_SYSTEM_PROMPT = """You are an expert vulnerability researcher performing static analysis on source code.

Your goal: find real, exploitable security vulnerabilities. Focus on:
- Memory safety: use-after-free, buffer overflows, integer overflows, out-of-bounds reads/writes
- Injection: SQL, command injection, format string bugs
- Logic flaws: authentication bypasses, improper access control, race conditions
- Input validation: missing bounds checks, type confusion, unsafe deserialization

For each vulnerability you identify:
1. Explain the vulnerability clearly -- what it is, why it's exploitable
2. Cite the exact file and line/function where it occurs
3. Produce a concrete proof-of-concept input or exploit scenario wrapped in <poc> tags
4. Rate severity: CRITICAL / HIGH / MEDIUM / LOW
5. Suggest a minimal fix

If your previous hypothesis was wrong or didn't trigger, revise your approach.
Don't repeat the same hypothesis. Look at different code paths.

When you have nothing more to report, output <done/> to end the session."""

WEBAPP_SYSTEM_PROMPT = """You are an expert web application penetration tester.

Your goal: find real, exploitable vulnerabilities in a web application. Focus on:
- Broken access control / IDOR (Insecure Direct Object Reference)
- Authentication and session flaws
- Injection: SQL, NoSQL, command, SSTI, SSRF
- Business logic bypasses
- Information disclosure
- Insecure API endpoints

You will be given:
- Crawled endpoints and parameters
- Response samples
- JavaScript source snippets
- Headers and cookies

For each vulnerability hypothesis:
1. Explain what you think is exploitable and why
2. Produce a concrete HTTP test wrapped in <test_request> tags -- include method, URL, headers, body
3. Rate severity: CRITICAL / HIGH / MEDIUM / LOW
4. Describe what a successful response looks like so the verifier knows what to check

If a test came back negative, revise your hypothesis. Don't repeat failed tests.
When you have nothing more to test, output <done/> to end the session."""

REPO_VERIFIER_PROMPT = """You are an adversarial security reviewer. You have been given a claimed vulnerability
and its proof-of-concept from a separate analyst. Your job is to disprove it.

Assume the finding is a false positive until proven otherwise. Search for:
- Upstream validation or sanitization that neutralizes the input before it reaches the vulnerable site
- Authentication or authorization gates that an attacker can't bypass
- Compiler/runtime mitigations that prevent exploitation (ASLR, stack canaries, bounds checking)
- Code paths that are unreachable from attacker-controlled input
- Type constraints or invariants that make the exploit scenario impossible

After your analysis, output one of:
<verdict>CONFIRMED</verdict> -- you cannot find a reason it's a false positive
<verdict>FALSE_POSITIVE</verdict> -- you found a specific reason it's not exploitable

Follow the verdict tag with a one-paragraph explanation of your reasoning."""

WEBAPP_VERIFIER_PROMPT = """You are an adversarial security reviewer. You have been given a claimed web vulnerability
and the HTTP test request from a separate analyst. Your job is to disprove it.

Assume the finding is a false positive until proven otherwise. Search for:
- Server-side validation that rejects or sanitizes the input
- Authentication/session checks that block unauthenticated access to the endpoint
- CSRF protections, rate limits, or other controls that prevent exploitation
- Framework-level protections (ORM parameterization, output encoding, etc.)
- Whether the "successful" response criteria would actually indicate a real vulnerability

After your analysis, output one of:
<verdict>CONFIRMED</verdict> -- you cannot find a reason it's a false positive
<verdict>FALSE_POSITIVE</verdict> -- you found a specific reason it's not exploitable

Follow the verdict tag with a one-paragraph explanation of your reasoning."""


def run_independent_verifier(poc, context, mode):
    """
    Fresh Claude call that only sees the PoC + context.
    Actively tries to disprove the finding.
    Returns (confirmed: bool, reasoning: str).
    """
    if mode == "repo":
        system = REPO_VERIFIER_PROMPT
        user_msg = f"""Claimed vulnerability proof-of-concept:

{poc}

Source context the analyst was reviewing:

{context}

Try to disprove this finding. Look for mitigations, guards, or unreachable paths."""
    else:
        system = WEBAPP_VERIFIER_PROMPT
        user_msg = f"""Claimed vulnerability and HTTP test:

{poc}

Application context the analyst was reviewing:

{context}

Try to disprove this finding. Look for server-side controls that prevent exploitation."""

    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1024,
        system=system,
        messages=[{"role": "user", "content": user_msg}],
    )
    reply = response.content[0].text

    verdict_match = re.search(r"<verdict>(CONFIRMED|FALSE_POSITIVE)</verdict>", reply)
    if verdict_match:
        confirmed = verdict_match.group(1) == "CONFIRMED"
    else:
        # No verdict tag -- treat as confirmed to avoid silently dropping real findings
        confirmed = True

    return confirmed, reply


REPO_CHAIN_PROMPT = """You are an exploitation strategist. A vulnerability was just confirmed in this
codebase. Your job is to reason about what it ENABLES -- how it could be chained
with other weaknesses or escalated into greater impact.

Consider:
- Does this give a primitive (read, write, exec, auth bypass) that unlocks a bigger attack?
- Could it be combined with another finding to reach a more sensitive asset?
- Does it escalate privileges, enable lateral movement, or expand blast radius?

Be concrete and specific to this code. If there is no realistic chain, say so plainly.
Output a short paragraph (no tags)."""

WEBAPP_CHAIN_PROMPT = """You are an exploitation strategist. A vulnerability was just confirmed in this
web application. Your job is to reason about what it ENABLES -- how it could be
chained or escalated into greater impact.

Consider:
- IDOR -> mass data access or account takeover
- XSS -> session theft -> account takeover
- SSRF -> internal service access -> cloud metadata -> credential theft
- Auth bypass -> admin access -> full compromise

Be concrete and specific to this target. If there is no realistic chain, say so plainly.
Output a short paragraph (no tags)."""


def run_chain_analysis(finding_text, context, mode):
    """
    Fresh Claude call: given a confirmed finding, reason about escalation /
    chaining. Returns a short paragraph (str), or "" on failure.
    """
    system = REPO_CHAIN_PROMPT if mode == "repo" else WEBAPP_CHAIN_PROMPT
    user_msg = f"""Confirmed vulnerability:

{finding_text}

Context the analyst was reviewing:

{context}

What does this enable? How could it be chained or escalated?"""
    try:
        response = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=1024,
            system=system,
            messages=[{"role": "user", "content": user_msg}],
        )
        return response.content[0].text.strip()
    except Exception as e:
        console.print(f"[yellow]Chain analysis skipped ({e}).[/yellow]")
        return ""


def extract_tag(text, tag):
    """Extract content from a custom XML tag."""
    pattern = rf"<{tag}>(.*?)</{tag}>"
    match = re.search(pattern, text, re.DOTALL)
    return match.group(1).strip() if match else None


def is_done(text):
    return "<done/>" in text or "<done />" in text


def run_repo_loop(source_chunks, verifier_fn, max_iterations=15):
    """
    Agentic loop for source code analysis.

    source_chunks: list of dicts with 'path' and 'content'
    verifier_fn: callable(poc_string) -> (bool, str) -- confirmed, details
    """
    conversation = []
    findings = []

    # Build initial context from source chunks
    source_context = "\n\n".join(
        f"// === FILE: {chunk['path']} ===\n{chunk['content']}"
        for chunk in source_chunks
    )

    initial_message = f"""Analyze this codebase for security vulnerabilities.

{source_context}

Start with the highest-risk areas first. Focus on functions that handle
user-controlled input, memory allocation/deallocation, or authentication logic."""

    conversation.append({"role": "user", "content": initial_message})

    for i in range(max_iterations):
        console.print(f"\n[bold cyan]--- Iteration {i + 1}/{max_iterations} ---[/bold cyan]")

        response = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=4096,
            system=REPO_SYSTEM_PROMPT,
            messages=conversation,
        )
        reply = response.content[0].text
        console.print(Panel(reply[:800] + ("..." if len(reply) > 800 else ""),
                           title="Claude Analysis", border_style="blue"))

        conversation.append({"role": "assistant", "content": reply})

        if is_done(reply):
            console.print("[yellow]Claude signaled analysis complete.[/yellow]")
            break

        poc = extract_tag(reply, "poc")

        if poc:
            console.print(f"\n[bold]Testing PoC:[/bold]")
            console.print(Syntax(poc, "text", theme="monokai"))

            # Independent verifier: fresh Claude call, actively tries to disprove
            console.print("[dim]Running independent verifier...[/dim]")
            iv_confirmed, iv_reasoning = run_independent_verifier(poc, source_context, "repo")

            if not iv_confirmed:
                console.print("[yellow]Independent verifier flagged as false positive -- skipping.[/yellow]")
                console.print(Panel(iv_reasoning[:400], title="Verifier Reasoning", border_style="yellow"))
                follow_up = f"""An independent reviewer assessed your PoC and flagged it as a likely false positive:

{iv_reasoning}

Revise your hypothesis. Look for a different code path or vulnerability class."""
                conversation.append({"role": "user", "content": follow_up})
                continue

            # Independent verifier agreed -- now run binary/HTTP verifier
            confirmed, details = verifier_fn(poc)

            if confirmed:
                console.print("[bold red]VULNERABILITY CONFIRMED[/bold red]")
                console.print("[dim]Running chain analysis...[/dim]")
                chain = run_chain_analysis(f"{reply}\n\nPoC:\n{poc}", source_context, "repo")
                if chain:
                    console.print(Panel(chain[:400], title="Chain / Escalation", border_style="magenta"))
                findings.append({
                    "iteration": i + 1,
                    "analysis": reply,
                    "poc": poc,
                    "verifier_output": details,
                    "iv_reasoning": iv_reasoning,
                    "chain": chain,
                })
                follow_up = f"""Vulnerability confirmed by both independent review and verification. Output:

{details}

A chaining/escalation analysis suggested:

{chain or '(no realistic chain identified)'}

This finding has been recorded. If the chain above points to a concrete next
target, pursue it with a new <poc>. Otherwise look for additional
vulnerabilities in different parts of the codebase."""
            else:
                console.print("[yellow]Not confirmed -- feeding result back.[/yellow]")
                follow_up = f"""The PoC did not confirm the vulnerability. Verifier output:

{details}

Revise your hypothesis. Consider: different input format, different code path,
or a different vulnerability class entirely."""
        else:
            follow_up = "No PoC was included. Please provide a concrete test case in <poc> tags, or output <done/> if analysis is complete."

        conversation.append({"role": "user", "content": follow_up})

    return findings


def run_webapp_loop(app_context, verifier_fn, max_iterations=15):
    """
    Agentic loop for web application testing.
    
    app_context: dict with crawl results, endpoints, sample responses
    verifier_fn: callable(test_request_dict) -> (bool, str) -- confirmed, details
    """
    conversation = []
    findings = []

    context_summary = f"""Target: {app_context.get('base_url', 'unknown')}

Discovered endpoints:
{chr(10).join(f"  {ep['method']} {ep['url']}" for ep in app_context.get('endpoints', [])[:50])}

Sample responses and parameters:
{app_context.get('sample_data', 'None captured')}

JavaScript sources analyzed:
{app_context.get('js_summary', 'None')}

Headers observed:
{app_context.get('headers_summary', 'None')}"""

    initial_message = f"""Analyze this web application for security vulnerabilities.

{context_summary}

Start with the highest-risk endpoints. Look for authentication issues, 
access control flaws, and injection points first."""

    conversation.append({"role": "user", "content": initial_message})

    for i in range(max_iterations):
        console.print(f"\n[bold cyan]--- Iteration {i + 1}/{max_iterations} ---[/bold cyan]")

        response = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=4096,
            system=WEBAPP_SYSTEM_PROMPT,
            messages=conversation,
        )
        reply = response.content[0].text
        console.print(Panel(reply[:800] + ("..." if len(reply) > 800 else ""),
                           title="Claude Analysis", border_style="blue"))

        conversation.append({"role": "assistant", "content": reply})

        if is_done(reply):
            console.print("[yellow]Claude signaled analysis complete.[/yellow]")
            break

        test_request_raw = extract_tag(reply, "test_request")

        if test_request_raw:
            test_request = parse_test_request(test_request_raw)
            console.print(f"\n[bold]Running test:[/bold]")
            console.print(Syntax(test_request_raw, "http", theme="monokai"))

            # Independent verifier: fresh Claude call, actively tries to disprove
            console.print("[dim]Running independent verifier...[/dim]")
            iv_confirmed, iv_reasoning = run_independent_verifier(test_request_raw, context_summary, "webapp")

            if not iv_confirmed:
                console.print("[yellow]Independent verifier flagged as false positive -- skipping.[/yellow]")
                console.print(Panel(iv_reasoning[:400], title="Verifier Reasoning", border_style="yellow"))
                follow_up = f"""An independent reviewer assessed your test and flagged it as a likely false positive:

{iv_reasoning}

Revise your hypothesis. Look for a different endpoint or vulnerability class."""
                conversation.append({"role": "user", "content": follow_up})
                continue

            # Independent verifier agreed -- now run live HTTP verifier
            confirmed, details = verifier_fn(test_request)

            if confirmed:
                console.print("[bold red]VULNERABILITY CONFIRMED[/bold red]")
                console.print("[dim]Running chain analysis...[/dim]")
                chain = run_chain_analysis(f"{reply}\n\nTest:\n{test_request_raw}", context_summary, "webapp")
                if chain:
                    console.print(Panel(chain[:400], title="Chain / Escalation", border_style="magenta"))
                findings.append({
                    "iteration": i + 1,
                    "analysis": reply,
                    "test_request": test_request_raw,
                    "verifier_output": details,
                    "iv_reasoning": iv_reasoning,
                    "chain": chain,
                })
                follow_up = f"""Vulnerability confirmed by both independent review and live test. Response:

{details}

A chaining/escalation analysis suggested:

{chain or '(no realistic chain identified)'}

This finding has been recorded. If the chain above points to a concrete next
test, pursue it with a new <test_request>. Otherwise investigate other endpoints."""
            else:
                console.print("[yellow]Not confirmed -- feeding result back.[/yellow]")
                follow_up = f"""Test did not confirm the vulnerability. Response:

{details}

Revise your approach. Consider: different parameter names, different HTTP method,
authentication state, or a completely different vulnerability class."""
        else:
            follow_up = "No test request was included. Please provide a concrete HTTP test in <test_request> tags, or output <done/> if testing is complete."

        conversation.append({"role": "user", "content": follow_up})

    return findings


def parse_test_request(raw):
    """
    Parse a raw HTTP-ish test request string into a dict 
    for the web verifier to use.
    """
    lines = raw.strip().splitlines()
    result = {
        "method": "GET",
        "url": "",
        "headers": {},
        "body": None,
    }

    if not lines:
        return result

    # First line: METHOD URL
    first = lines[0].split()
    if len(first) >= 2:
        result["method"] = first[0].upper()
        result["url"] = first[1]

    # Parse headers and body (separated by blank line)
    in_body = False
    body_lines = []
    for line in lines[1:]:
        if not line.strip() and not in_body:
            in_body = True
            continue
        if in_body:
            body_lines.append(line)
        elif ":" in line:
            key, _, val = line.partition(":")
            result["headers"][key.strip()] = val.strip()

    if body_lines:
        result["body"] = "\n".join(body_lines)

    return result
