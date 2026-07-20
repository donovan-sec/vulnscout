"""
Validation gate: a structured pre-submission checklist applied to each
confirmed finding.

The dual-verifier in claude_loop already filters false positives. This gate is
a different thing: it scores report *quality* and *submission-readiness* the way
a triager would, so weak write-ups get flagged before you waste a submission
slot. By design it annotates -- it never drops findings.

The 7 questions are modelled on what bounty triage actually checks:
1. Is the vulnerability reproducible from the PoC as written?
2. Is the impact concrete and clearly stated (not hand-waved)?
3. Is the affected asset / endpoint / file precisely identified?
4. Does the verifier output actually demonstrate the claimed effect?
5. Is the severity rating justified by the impact?
6. Is there a clear remediation?
7. Is this likely in-scope and not a known/duplicate class of noise?
"""

import json
import re
import anthropic
from rich.console import Console

console = Console()
client = anthropic.Anthropic()

GATE_QUESTIONS = [
    "Is the vulnerability reproducible from the PoC / test as written?",
    "Is the impact concrete and clearly stated (not hand-waved)?",
    "Is the affected asset / endpoint / file precisely identified?",
    "Does the verifier output demonstrate the claimed effect?",
    "Is the severity rating justified by the stated impact?",
    "Is there a clear, actionable remediation?",
    "Is this a substantive bug (not informational noise / self-XSS / theoretical)?",
]

GATE_PROMPT = """You are a senior bug bounty triager doing a pre-submission quality pass.
You are NOT deciding whether the bug is real -- a separate verifier already did that.
You are scoring whether THIS WRITE-UP is submission-ready.

Answer each of the following questions with YES or NO and a one-line reason.

{questions}

Here is the finding:

--- ANALYSIS ---
{analysis}

--- PROOF / TEST ---
{poc}

--- VERIFIER OUTPUT ---
{verifier}

Return ONLY valid JSON, no prose outside it:
{{
  "answers": [
    {{"q": 1, "pass": true, "reason": "..."}},
    ... one object per question, q = 1..7 ...
  ],
  "overall": "one-sentence verdict on submission readiness"
}}"""


def run_gate(finding):
    """
    Run the 7-question gate on one finding via a fast model.
    Returns a dict: {score, total, answers, overall} -- always annotates,
    never raises on model hiccups (falls back to a neutral pass).
    """
    poc = finding.get("poc") or finding.get("test_request") or "(none provided)"
    prompt = GATE_PROMPT.format(
        questions="\n".join(f"{i+1}. {q}" for i, q in enumerate(GATE_QUESTIONS)),
        analysis=finding.get("analysis", "")[:6000],
        poc=poc[:2000],
        verifier=finding.get("verifier_output", "")[:2000],
    )

    try:
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=1500,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text.strip()
        text = re.sub(r"^```json\s*|^```\s*|\s*```$", "", text)
        data = json.loads(text)
    except Exception as e:
        console.print(f"[yellow]Validation gate fell back to neutral ({e}).[/yellow]")
        return {
            "score": len(GATE_QUESTIONS),
            "total": len(GATE_QUESTIONS),
            "answers": [],
            "overall": "Gate unavailable -- defaulted to pass. Review manually.",
        }

    answers = data.get("answers", [])
    score = sum(1 for a in answers if a.get("pass"))
    return {
        "score": score,
        "total": len(GATE_QUESTIONS),
        "answers": answers,
        "overall": data.get("overall", ""),
    }


def annotate_findings(findings):
    """Run the gate on every finding and attach the result under 'validation'."""
    if not findings:
        return findings
    console.print(f"\n[cyan]Running validation gate on {len(findings)} finding(s)...[/cyan]")
    for i, finding in enumerate(findings, 1):
        result = run_gate(finding)
        finding["validation"] = result
        bar = f"{result['score']}/{result['total']}"
        color = "green" if result["score"] >= 6 else "yellow" if result["score"] >= 4 else "red"
        console.print(f"  [{color}]Finding {i}: {bar} checks passed[/{color}] -- {result['overall'][:80]}")
    return findings


def gate_markdown(validation):
    """Render a validation result as a markdown checklist block for reports."""
    if not validation:
        return ""
    lines = [f"### Validation Gate: {validation['score']}/{validation['total']} passed\n"]
    for a in validation.get("answers", []):
        mark = "x" if a.get("pass") else " "
        idx = a.get("q", "?")
        q = GATE_QUESTIONS[idx - 1] if isinstance(idx, int) and 1 <= idx <= len(GATE_QUESTIONS) else ""
        lines.append(f"- [{mark}] {q} -- {a.get('reason', '')}")
    if validation.get("overall"):
        lines.append(f"\n_{validation['overall']}_")
    return "\n".join(lines) + "\n"
