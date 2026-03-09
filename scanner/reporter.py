"""
Reporter: takes findings from the Claude loop and writes
structured output -- markdown report + JSON for further processing.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()


def write_report(findings, mode, source, output_dir=None):
    """Write findings to markdown and JSON files."""
    if not findings:
        console.print("\n[yellow]No confirmed findings to report.[/yellow]")
        console.print("[dim]This doesn't mean the target is clean -- it means nothing "
                     "was confirmed in static/HTTP verification mode. Review the console "
                     "output for unconfirmed hypotheses.[/dim]")
        return

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_slug = source.replace("https://", "").replace("http://", "").replace("/", "_")[:40]
    base_name = f"vulnscout_{mode}_{target_slug}_{timestamp}"

    if output_dir:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
    else:
        out_path = Path(".")

    # --- Summary table ---
    table = Table(title=f"VulnScout Findings -- {source}", show_lines=True)
    table.add_column("ID", style="bold", width=5)
    table.add_column("Severity", width=10)
    table.add_column("Summary", width=60)
    table.add_column("Iter", width=6)

    for i, f in enumerate(findings, 1):
        severity = extract_severity(f["analysis"])
        summary = extract_summary(f["analysis"])
        table.add_row(
            str(i),
            severity_color(severity),
            summary,
            str(f["iteration"]),
        )

    console.print(table)

    # --- Markdown report ---
    md_path = out_path / f"{base_name}.md"
    with open(md_path, "w") as fh:
        fh.write(f"# VulnScout Report\n\n")
        fh.write(f"**Target:** {source}\n")
        fh.write(f"**Mode:** {mode}\n")
        fh.write(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        fh.write(f"**Confirmed findings:** {len(findings)}\n\n")
        fh.write("---\n\n")

        for i, finding in enumerate(findings, 1):
            severity = extract_severity(finding["analysis"])
            summary = extract_summary(finding["analysis"])

            fh.write(f"## Finding {i}: {summary}\n\n")
            fh.write(f"**Severity:** {severity}\n")
            fh.write(f"**Discovered at iteration:** {finding['iteration']}\n\n")
            fh.write("### Analysis\n\n")
            fh.write(finding["analysis"] + "\n\n")

            if finding.get("poc"):
                fh.write("### Proof of Concept\n\n")
                fh.write(f"```\n{finding['poc']}\n```\n\n")

            if finding.get("test_request"):
                fh.write("### HTTP Test Request\n\n")
                fh.write(f"```http\n{finding['test_request']}\n```\n\n")

            fh.write("### Verifier Output\n\n")
            fh.write(f"```\n{finding['verifier_output']}\n```\n\n")
            fh.write("---\n\n")

        fh.write("## Disclosure Notes\n\n")
        fh.write("Before publishing or using these findings:\n\n")
        fh.write("1. Manually validate each finding in your own test environment\n")
        fh.write("2. Follow responsible disclosure -- contact the maintainer privately before publishing\n")
        fh.write("3. For CVE requests: use https://cveform.mitre.org/ after coordinating with the vendor\n")
        fh.write("4. Document your authorization to test the target\n")

    console.print(f"\n[green]Markdown report saved: {md_path}[/green]")

    # --- JSON output ---
    json_path = out_path / f"{base_name}.json"
    with open(json_path, "w") as fh:
        json.dump({
            "target": source,
            "mode": mode,
            "timestamp": timestamp,
            "finding_count": len(findings),
            "findings": findings,
        }, fh, indent=2)

    console.print(f"[green]JSON data saved: {json_path}[/green]")


def extract_severity(analysis_text):
    """Pull severity rating from Claude's analysis text."""
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if level in analysis_text.upper():
            return level
    return "UNKNOWN"


def extract_summary(analysis_text):
    """Pull first meaningful sentence as a summary."""
    lines = [l.strip() for l in analysis_text.splitlines() if l.strip()]
    if lines:
        summary = lines[0][:80]
        if len(lines[0]) > 80:
            summary += "..."
        return summary
    return "See full analysis"


def severity_color(severity):
    colors = {
        "CRITICAL": "[bold red]CRITICAL[/bold red]",
        "HIGH": "[red]HIGH[/red]",
        "MEDIUM": "[yellow]MEDIUM[/yellow]",
        "LOW": "[green]LOW[/green]",
        "UNKNOWN": "[dim]UNKNOWN[/dim]",
    }
    return colors.get(severity, severity)
