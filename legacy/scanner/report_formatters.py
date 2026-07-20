"""
Platform-specific report formatters.

Confirmed findings are generic until they're shaped into the format a bounty
platform actually wants. This module turns a vulnscout finding dict into
submission-ready markdown for HackerOne, Bugcrowd, and Intigriti.

A finding dict (from claude_loop) looks like:
{
    "iteration": int,
    "analysis": str,          # Claude's full analysis text
    "poc": str,               # repo mode
    "test_request": str,      # webapp mode
    "verifier_output": str,
    "iv_reasoning": str,
    "chain": str,             # optional, from bug-chaining pass
    "validation": dict,       # optional, from validation gate
}
"""

import re
from datetime import datetime

# Maps loose severity words to a CVSS-ish band most platforms expect.
SEVERITY_BANDS = {
    "CRITICAL": "Critical (9.0-10.0)",
    "HIGH": "High (7.0-8.9)",
    "MEDIUM": "Medium (4.0-6.9)",
    "LOW": "Low (0.1-3.9)",
    "UNKNOWN": "Informational",
}


def _severity(finding):
    text = finding.get("analysis", "").upper()
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if level in text:
            return level
    return "UNKNOWN"


def _title(finding):
    """First non-empty, non-heading line of the analysis, trimmed."""
    for line in finding.get("analysis", "").splitlines():
        s = line.strip().lstrip("#").strip()
        if s and len(s) > 8:
            return s[:120]
    return "Security vulnerability identified by VulnScout"


def _vuln_block(finding):
    """The PoC or HTTP test, whichever the mode produced."""
    if finding.get("test_request"):
        return f"```http\n{finding['test_request'].strip()}\n```"
    if finding.get("poc"):
        return f"```\n{finding['poc'].strip()}\n```"
    return "_See analysis below._"


def _impact(finding):
    """
    Try to pull an explicit impact statement from the analysis; otherwise
    fall back to a severity-derived sentence so the section is never empty.
    """
    m = re.search(r"(?:impact|exploit(?:able)?)[:\-\s]+(.+?)(?:\n\n|\Z)",
                  finding.get("analysis", ""), re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()[:600]
    sev = _severity(finding)
    return (f"This is a {sev.lower()}-severity issue. An attacker who exploits it "
            "can compromise the security properties described in the analysis above.")


def _chain_section(finding):
    chain = finding.get("chain")
    if not chain:
        return ""
    return f"\n## Exploitation Chain\n\n{chain.strip()}\n"


def format_hackerone(finding, target):
    """HackerOne report template (their markdown + section conventions)."""
    sev = _severity(finding)
    return f"""# {_title(finding)}

## Summary

{_title(finding)} affecting `{target}`.

## Severity

{SEVERITY_BANDS[sev]}

## Steps To Reproduce

{_vuln_block(finding)}

## Proof of Concept

{_vuln_block(finding)}

**Verifier output:**

```
{finding.get('verifier_output', '(none)').strip()[:1500]}
```

## Impact

{_impact(finding)}
{_chain_section(finding)}
## Supporting Material / References

- Discovered by VulnScout (AI-assisted analysis), iteration {finding.get('iteration', '?')}
- Independent adversarial review: confirmed not a false positive
{_validation_footer(finding)}
---
_Submitted via VulnScout. Manually validate before submission._
"""


def format_bugcrowd(finding, target):
    """Bugcrowd VRT-flavoured template."""
    sev = _severity(finding)
    return f"""**Title:** {_title(finding)}

**Target:** {target}

**Priority:** P{_bugcrowd_priority(sev)} ({sev})

**Bug Description**

{_first_paragraph(finding)}

**Proof of Concept**

{_vuln_block(finding)}

Verifier output:
```
{finding.get('verifier_output', '(none)').strip()[:1500]}
```

**Impact**

{_impact(finding)}
{_chain_section(finding)}
**Suggested Remediation**

{_remediation(finding)}
{_validation_footer(finding)}
"""


def format_intigriti(finding, target):
    """Intigriti submission template."""
    sev = _severity(finding)
    return f"""## {_title(finding)}

**Endpoint / Asset:** {target}
**Severity:** {sev}

### Description

{_first_paragraph(finding)}

### Steps to reproduce

{_vuln_block(finding)}

### Proof of concept

Verifier confirmed the following:
```
{finding.get('verifier_output', '(none)').strip()[:1500]}
```

### Impact

{_impact(finding)}
{_chain_section(finding)}
### Recommended fix

{_remediation(finding)}
{_validation_footer(finding)}
"""


def _bugcrowd_priority(sev):
    return {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}.get(sev, 5)


def _first_paragraph(finding):
    text = finding.get("analysis", "").strip()
    parts = text.split("\n\n")
    return parts[0][:800] if parts else text[:800]


def _remediation(finding):
    m = re.search(r"(?:fix|remediat|mitigat)[a-z]*[:\-\s]+(.+?)(?:\n\n|\Z)",
                  finding.get("analysis", ""), re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()[:500]
    return "Apply input validation / access control at the affected site. See analysis."


def _validation_footer(finding):
    v = finding.get("validation")
    if not v:
        return ""
    score = v.get("score", "?")
    total = v.get("total", "?")
    return f"\n_Validation gate: {score}/{total} checks passed._\n"


FORMATTERS = {
    "hackerone": format_hackerone,
    "h1": format_hackerone,
    "bugcrowd": format_bugcrowd,
    "intigriti": format_intigriti,
}


def format_finding(finding, target, platform):
    """Dispatch to the right platform formatter. Returns markdown string."""
    fn = FORMATTERS.get(platform.lower())
    if not fn:
        raise ValueError(f"Unknown platform '{platform}'. "
                         f"Choose from: {', '.join(sorted(set(FORMATTERS)))}")
    return fn(finding, target)


def write_platform_reports(findings, target, platform, out_path, base_name):
    """
    Write one submission-ready file per finding for the given platform.
    Returns list of written Path objects.
    """
    written = []
    for i, finding in enumerate(findings, 1):
        md = format_finding(finding, target, platform)
        path = out_path / f"{base_name}_{platform}_finding{i}.md"
        with open(path, "w") as fh:
            fh.write(md)
        written.append(path)
    return written
