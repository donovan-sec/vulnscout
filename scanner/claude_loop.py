"""
Core agentic loop -- feeds code/context to Claude, parses hypotheses,
runs verifier, feeds results back. Both modes share this engine.
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

            confirmed, details = verifier_fn(poc)

            if confirmed:
                console.print("[bold red]VULNERABILITY CONFIRMED[/bold red]")
                findings.append({
                    "iteration": i + 1,
                    "analysis": reply,
                    "poc": poc,
                    "verifier_output": details,
                })
                follow_up = f"""Vulnerability confirmed. Verifier output:

{details}

This finding has been recorded. Now look for additional vulnerabilities 
in different parts of the codebase."""
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

            confirmed, details = verifier_fn(test_request)

            if confirmed:
                console.print("[bold red]VULNERABILITY CONFIRMED[/bold red]")
                findings.append({
                    "iteration": i + 1,
                    "analysis": reply,
                    "test_request": test_request_raw,
                    "verifier_output": details,
                })
                follow_up = f"""Vulnerability confirmed. Response details:

{details}

This finding has been recorded. Now investigate other endpoints or 
try to escalate this finding (e.g., if IDOR found, test for privilege escalation)."""
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
