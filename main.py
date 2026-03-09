#!/usr/bin/env python3
"""
vulnscout -- AI-powered vulnerability scanner
Uses Claude in an agentic loop to find novel security vulnerabilities.

Usage:
  # Scan a git repo (static analysis)
  python main.py repo https://github.com/org/target-repo

  # Scan a local directory
  python main.py repo ./path/to/source --language python

  # Scan a repo with a built ASAN binary for hard verification
  python main.py repo https://github.com/org/target --binary ./target_asan

  # Scan a web app (unauthenticated)
  python main.py webapp https://target.example.com

  # Scan a web app (authenticated with a token)
  python main.py webapp https://api.example.com --auth-token eyJ...

  # Scan a web app with cookies (grab from browser devtools)
  python main.py webapp https://app.example.com --cookie "session=abc123; csrf=xyz"
"""

import sys
import os
import click
from rich.console import Console
from rich.panel import Panel

console = Console()

BANNER = """
╦  ╦┬ ┬┬  ┌┐┌┌─┐┌─┐┌─┐┬ ┬┌┬┐
╚╗╔╝│ ││  │││└─┐│  │ ││ │ │ 
 ╚╝ └─┘┴─┘┘└┘└─┘└─┘└─┘└─┘ ┴ 
AI-powered vulnerability research
"""


def check_api_key():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        console.print("[bold red]Error: ANTHROPIC_API_KEY not set.[/bold red]")
        console.print("Export it: export ANTHROPIC_API_KEY=sk-ant-...")
        sys.exit(1)


@click.group()
def cli():
    """VulnScout: AI-powered vulnerability scanner using Claude."""
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    check_api_key()


@cli.command()
@click.argument("source")
@click.option("--language", "-l",
              type=click.Choice(["c_cpp", "python", "javascript", "go", "rust", "java", "php", "ruby"]),
              default=None,
              help="Filter to a specific language (default: all supported)")
@click.option("--binary", "-b", default=None,
              help="Path to ASAN-instrumented binary for crash verification")
@click.option("--focus", "-f", default=None,
              help="Focus on files matching this keyword (e.g. 'auth', 'parser')")
@click.option("--iterations", "-i", default=15, show_default=True,
              help="Max Claude loop iterations per chunk")
@click.option("--output", "-o", default="./findings",
              help="Output directory for reports")
def repo(source, language, binary, focus, iterations, output):
    """
    Scan a git repository or local source directory.

    SOURCE can be a git URL or a local path.

    Examples:

    \b
      python main.py repo https://github.com/nicowillis/libpng
      python main.py repo ./my-project --language python --focus auth
      python main.py repo https://github.com/org/repo --binary ./target_asan
    """
    console.print(Panel(
        f"[bold]Source:[/bold] {source}\n"
        f"[bold]Language:[/bold] {language or 'auto-detect'}\n"
        f"[bold]Binary harness:[/bold] {binary or 'static mode'}\n"
        f"[bold]Focus:[/bold] {focus or 'none'}\n"
        f"[bold]Iterations:[/bold] {iterations}",
        title="Repo Scan Configuration",
        border_style="cyan",
    ))

    if binary and not os.path.isfile(binary):
        console.print(f"[red]Binary not found: {binary}[/red]")
        sys.exit(1)

    from scanner.repo_scanner import scan_repo
    findings = scan_repo(
        source=source,
        language=language,
        binary_path=binary,
        max_iterations=iterations,
        focus_area=focus,
        output_dir=output,
    )

    console.print(f"\n[bold green]Scan complete. {len(findings)} confirmed finding(s).[/bold green]")
    if findings:
        console.print(f"[green]Reports saved to: {output}/[/green]")


@cli.command()
@click.argument("url")
@click.option("--auth-token", "-t", default=None,
              help="Bearer token for authenticated scanning")
@click.option("--cookie", "-c", default=None,
              help="Cookie string (e.g. 'session=abc123; other=val')")
@click.option("--header", "-H", multiple=True,
              help="Custom header (repeatable): 'X-Api-Key: abc123'")
@click.option("--max-pages", "-p", default=100, show_default=True,
              help="Max pages to crawl")
@click.option("--iterations", "-i", default=15, show_default=True,
              help="Max Claude loop iterations")
@click.option("--output", "-o", default="./findings",
              help="Output directory for reports")
def webapp(url, auth_token, cookie, header, max_pages, iterations, output):
    """
    Scan a web application by crawling and testing with Claude.

    URL should be the base URL of the target application.

    Examples:

    \b
      python main.py webapp https://target.example.com
      python main.py webapp https://api.example.com --auth-token eyJ...
      python main.py webapp https://app.example.com --cookie "session=abc"
      python main.py webapp https://app.example.com -H "X-Api-Key: key123"
    """
    # Parse cookies
    cookies = {}
    if cookie:
        for pair in cookie.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, _, v = pair.partition("=")
                cookies[k.strip()] = v.strip()

    # Parse headers
    headers = {}
    for h in header:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()

    console.print(Panel(
        f"[bold]Target:[/bold] {url}\n"
        f"[bold]Auth:[/bold] {'token provided' if auth_token else 'none'}\n"
        f"[bold]Cookies:[/bold] {list(cookies.keys()) or 'none'}\n"
        f"[bold]Custom headers:[/bold] {list(headers.keys()) or 'none'}\n"
        f"[bold]Max pages:[/bold] {max_pages}\n"
        f"[bold]Iterations:[/bold] {iterations}",
        title="Web App Scan Configuration",
        border_style="cyan",
    ))

    # Safety check -- don't scan things you don't own
    console.print(Panel(
        "[bold yellow]Authorization reminder[/bold yellow]\n\n"
        "Only scan applications you own or have explicit written permission to test.\n"
        "Unauthorized scanning may be illegal under the CFAA and equivalent laws.",
        border_style="yellow",
    ))

    proceed = click.confirm("Do you have authorization to scan this target?", default=False)
    if not proceed:
        console.print("[red]Scan cancelled.[/red]")
        sys.exit(0)

    from scanner.webapp_scanner import scan_webapp
    findings = scan_webapp(
        url=url,
        cookies=cookies if cookies else None,
        headers=headers if headers else None,
        auth_token=auth_token,
        max_pages=max_pages,
        max_iterations=iterations,
        output_dir=output,
    )

    console.print(f"\n[bold green]Scan complete. {len(findings)} confirmed finding(s).[/bold green]")
    if findings:
        console.print(f"[green]Reports saved to: {output}/[/green]")


if __name__ == "__main__":
    cli()
