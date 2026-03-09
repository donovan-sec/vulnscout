"""
scope_parser.py: Parse raw scope text from Bugcrowd or HackerOne
and generate the right vulnscout scan commands for each target.

Handles:
- Web app URLs (https://app.example.com)
- Wildcard domains (*.example.com)
- GitHub repos (github.com/org/repo)
- IP ranges (skip with warning)
- Out-of-scope exclusions
"""

import re
import json
from urllib.parse import urlparse
from typing import Optional

import anthropic
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
client = anthropic.Anthropic()

PARSE_PROMPT = """You are parsing a bug bounty scope definition from Bugcrowd or HackerOne.

Extract all in-scope targets and classify each one. Return ONLY valid JSON, no other text.

For each target return:
{
  "type": "webapp" | "github_repo" | "wildcard_domain" | "ip" | "skip",
  "value": "the raw target value",
  "url": "full URL if webapp (add https:// if missing)",
  "repo_url": "full github clone URL if github repo",
  "notes": "any relevant scope notes (auth required, specific paths, etc)"
}

Rules:
- https:// or http:// URLs → type "webapp"
- github.com/org/repo → type "github_repo", repo_url = "https://github.com/org/repo"
- *.example.com → type "wildcard_domain" (we'll handle these separately)
- Raw IP addresses or CIDR ranges → type "skip" (out of scope for this tool)
- Anything explicitly marked out of scope → omit entirely
- Mobile apps, binaries, thick clients → type "skip"

Return format:
{
  "program_name": "inferred program name if visible",
  "targets": [ ...list of target objects... ],
  "out_of_scope_notes": "any important out of scope restrictions"
}"""


def parse_scope_with_claude(raw_scope: str) -> dict:
    """Use Claude to parse raw scope text into structured targets."""
    console.print("[cyan]Parsing scope with Claude...[/cyan]")

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2000,
        messages=[
            {
                "role": "user",
                "content": f"{PARSE_PROMPT}\n\nScope text to parse:\n\n{raw_scope}"
            }
        ]
    )

    text = response.content[0].text.strip()

    # Strip markdown fences if present
    text = re.sub(r"^```json\s*", "", text)
    text = re.sub(r"^```\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        console.print(f"[red]Failed to parse Claude's response as JSON: {e}[/red]")
        console.print(f"[dim]Raw response: {text[:500]}[/dim]")
        return {"targets": [], "out_of_scope_notes": ""}


def expand_wildcard(wildcard: str) -> list:
    """
    For *.example.com, suggest common subdomains to try.
    Returns a list of URLs worth scanning.
    """
    domain = wildcard.lstrip("*.")
    common_subdomains = [
        "app", "api", "admin", "dashboard", "portal",
        "dev", "staging", "beta", "test",
        "auth", "login", "account", "accounts",
        "www", "web", "mobile",
    ]
    urls = []
    for sub in common_subdomains:
        urls.append(f"https://{sub}.{domain}")
    # Also try the root domain
    urls.append(f"https://{domain}")
    return urls


def build_scan_commands(parsed: dict, auth_token: Optional[str] = None,
                        cookie: Optional[str] = None, max_pages: int = 50,
                        iterations: int = 12) -> list:
    """
    Convert parsed scope into a list of scan command dicts.
    Each dict has: type, command, display, target
    """
    commands = []
    targets = parsed.get("targets", [])

    for target in targets:
        t = target.get("type")
        notes = target.get("notes", "")

        if t == "webapp":
            url = target.get("url") or target.get("value")
            if not url:
                continue
            if not url.startswith("http"):
                url = f"https://{url}"

            cmd = ["./vs", "webapp", url,
                   "--max-pages", str(max_pages),
                   "--iterations", str(iterations)]

            if auth_token:
                cmd += ["--auth-token", auth_token]
            if cookie:
                cmd += ["--cookie", cookie]

            commands.append({
                "type": "webapp",
                "target": url,
                "command": " ".join(cmd),
                "notes": notes,
            })

        elif t == "github_repo":
            repo_url = target.get("repo_url") or target.get("value")
            if not repo_url:
                continue

            cmd = ["./vs", "repo", repo_url,
                   "--iterations", str(iterations)]

            commands.append({
                "type": "repo",
                "target": repo_url,
                "command": " ".join(cmd),
                "notes": notes,
            })

        elif t == "wildcard_domain":
            value = target.get("value", "")
            expanded = expand_wildcard(value)

            for url in expanded[:5]:  # cap at 5 per wildcard
                cmd = ["./vs", "webapp", url,
                       "--max-pages", str(max_pages // 2),
                       "--iterations", str(iterations)]

                if auth_token:
                    cmd += ["--auth-token", auth_token]
                if cookie:
                    cmd += ["--cookie", cookie]

                commands.append({
                    "type": "webapp",
                    "target": url,
                    "command": " ".join(cmd),
                    "notes": f"Expanded from wildcard {value}. Verify this subdomain exists before scanning.",
                })

        elif t == "skip":
            console.print(f"[dim]Skipping: {target.get('value')} (not supported by vulnscout)[/dim]")

    return commands


def display_commands(commands: list, parsed: dict):
    """Print a summary table of what will be run."""
    program = parsed.get("program_name", "Unknown Program")
    oos = parsed.get("out_of_scope_notes", "")

    console.print(Panel(
        f"[bold]Program:[/bold] {program}\n"
        f"[bold]Targets found:[/bold] {len(commands)}\n"
        + (f"[bold yellow]Out of scope:[/bold yellow] {oos}" if oos else ""),
        title="Scope Parse Results",
        border_style="cyan",
    ))

    table = Table(show_lines=True)
    table.add_column("#", width=4)
    table.add_column("Type", width=10)
    table.add_column("Target", width=50)
    table.add_column("Notes", width=35)

    for i, cmd in enumerate(commands, 1):
        type_color = "[cyan]webapp[/cyan]" if cmd["type"] == "webapp" else "[green]repo[/green]"
        table.add_row(
            str(i),
            type_color,
            cmd["target"][:49],
            (cmd.get("notes") or "")[:34],
        )

    console.print(table)


def generate_script(commands: list, output_path: str = "run_scope.sh"):
    """Write a shell script that runs all scans sequentially."""
    lines = [
        "#!/bin/zsh",
        "# Auto-generated by vulnscout scope parser",
        "# Review targets before running -- confirm you have authorization",
        "",
        'cd "$(dirname "$0")"',
        "",
    ]

    for i, cmd in enumerate(commands, 1):
        lines.append(f"# Target {i}: {cmd['target']}")
        if cmd.get("notes"):
            lines.append(f"# Note: {cmd['notes']}")
        lines.append(cmd["command"])
        lines.append("")

    script = "\n".join(lines)

    with open(output_path, "w") as fh:
        fh.write(script)

    import os
    os.chmod(output_path, 0o755)

    return output_path


def parse_scope(raw_scope: str, auth_token: Optional[str] = None,
                cookie: Optional[str] = None, max_pages: int = 50,
                iterations: int = 12, write_script: bool = True,
                output_script: str = "run_scope.sh") -> list:
    """
    Main entry point.

    raw_scope: paste directly from Bugcrowd or HackerOne scope tab
    auth_token: optional bearer token for authenticated scanning
    cookie: optional cookie string
    max_pages: crawler depth per webapp target
    iterations: Claude loop iterations per target
    write_script: if True, writes run_scope.sh with all commands
    """
    # Parse
    parsed = parse_scope_with_claude(raw_scope)

    if not parsed.get("targets"):
        console.print("[red]No targets extracted. Check the scope text and try again.[/red]")
        return []

    # Build commands
    commands = build_scan_commands(
        parsed,
        auth_token=auth_token,
        cookie=cookie,
        max_pages=max_pages,
        iterations=iterations,
    )

    if not commands:
        console.print("[yellow]No scannable targets found (all were IPs, mobile apps, or skipped).[/yellow]")
        return []

    # Display
    display_commands(commands, parsed)

    # Write script
    if write_script:
        script_path = generate_script(commands, output_script)
        console.print(f"\n[green]Script written to: {script_path}[/green]")
        console.print(f"[dim]Review it, then run: bash {script_path}[/dim]")

    # Print individual commands
    console.print("\n[bold]Individual commands:[/bold]")
    for cmd in commands:
        console.print(f"[dim]{cmd['command']}[/dim]")

    return commands
