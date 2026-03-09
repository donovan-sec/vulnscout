"""
GitHub hunter: searches for repos matching a query, clones each one,
runs the scanner, saves findings, and moves on. Fully automated.
"""

import os
import time
import shutil
import tempfile
import requests
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

GITHUB_API = "https://api.github.com/search/repositories"
CLONE_DELAY = 2  # seconds between clones to be polite


def search_github(query, language=None, min_stars=50, max_stars=2000,
                  pushed_after="2024-01-01", max_results=20):
    """
    Search GitHub for repos matching the query.
    Returns list of dicts with name, url, stars, description, language.
    """
    # Build the query string
    q = query
    if language:
        q += f" language:{language}"
    q += f" stars:{min_stars}..{max_stars}"
    q += f" pushed:>{pushed_after}"

    headers = {"Accept": "application/vnd.github.v3+json"}

    # Use token if available for higher rate limits
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    else:
        console.print("[yellow]Tip: set GITHUB_TOKEN for higher GitHub API rate limits[/yellow]")

    params = {
        "q": q,
        "sort": "stars",
        "order": "desc",
        "per_page": min(max_results, 30),
    }

    console.print(f"[cyan]Searching GitHub: {q}[/cyan]")

    try:
        resp = requests.get(GITHUB_API, headers=headers, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        console.print(f"[red]GitHub search failed: {e}[/red]")
        return []

    repos = []
    for item in data.get("items", []):
        repos.append({
            "name": item["full_name"],
            "clone_url": item["clone_url"],
            "stars": item["stargazers_count"],
            "description": item.get("description", ""),
            "language": item.get("language", "unknown"),
            "topics": item.get("topics", []),
            "has_security_policy": item.get("has_issues", False),
            "pushed_at": item.get("pushed_at", ""),
        })

    console.print(f"[green]Found {len(repos)} repos[/green]")
    return repos


def display_repo_table(repos):
    """Show what we're about to scan."""
    table = Table(title="Repos queued for scanning", show_lines=True)
    table.add_column("#", width=4)
    table.add_column("Repo", width=35)
    table.add_column("Lang", width=12)
    table.add_column("Stars", width=8)
    table.add_column("Description", width=45)

    for i, r in enumerate(repos, 1):
        table.add_row(
            str(i),
            r["name"],
            r["language"] or "?",
            str(r["stars"]),
            (r["description"] or "")[:44],
        )
    console.print(table)


def already_scanned(repo_name, output_dir):
    """Check if we already have findings for this repo."""
    slug = repo_name.replace("/", "_")
    out = Path(output_dir)
    existing = list(out.glob(f"vulnscout_repo_{slug[:20]}*.md"))
    return len(existing) > 0


def hunt(query, language=None, min_stars=50, max_stars=2000,
         pushed_after="2024-01-01", max_repos=10, iterations=15,
         focus=None, output_dir="./findings", skip_scanned=True,
         language_filter=None):
    """
    Main hunt loop:
    1. Search GitHub for repos
    2. For each repo: clone → scan → save findings → delete clone → next
    """
    from scanner.repo_scanner import scan_repo

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Search
    repos = search_github(
        query=query,
        language=language,
        min_stars=min_stars,
        max_stars=max_stars,
        pushed_after=pushed_after,
        max_results=max_repos,
    )

    if not repos:
        console.print("[red]No repos found. Try a broader query.[/red]")
        return

    display_repo_table(repos)

    # Summary before starting
    console.print(Panel(
        f"[bold]Query:[/bold] {query}\n"
        f"[bold]Repos to scan:[/bold] {len(repos)}\n"
        f"[bold]Iterations per repo:[/bold] {iterations}\n"
        f"[bold]Focus:[/bold] {focus or 'none'}\n"
        f"[bold]Output:[/bold] {output_dir}\n"
        f"[bold]Estimated API cost:[/bold] ~${len(repos) * 1.5:.2f}-${len(repos) * 4:.2f}",
        title="Hunt Configuration",
        border_style="magenta",
    ))

    all_findings = []
    scanned = 0
    skipped = 0

    for i, repo in enumerate(repos):
        console.print(f"\n[bold magenta]═══ Repo {i+1}/{len(repos)}: {repo['name']} ═══[/bold magenta]")

        # Skip if already scanned
        if skip_scanned and already_scanned(repo["name"], output_dir):
            console.print(f"[dim]Already scanned, skipping.[/dim]")
            skipped += 1
            continue

        tmp_dir = tempfile.mkdtemp(prefix="vulnscout_hunt_")

        try:
            # Clone
            findings = scan_repo(
                source=repo["clone_url"],
                language=language_filter,
                binary_path=None,
                max_iterations=iterations,
                focus_area=focus,
                output_dir=output_dir,
            )

            if findings:
                console.print(f"[bold red]★ {len(findings)} finding(s) in {repo['name']}[/bold red]")
                all_findings.extend([{**f, "repo": repo["name"]} for f in findings])
            else:
                console.print(f"[dim]No confirmed findings in {repo['name']}[/dim]")

            scanned += 1

        except Exception as e:
            console.print(f"[red]Error scanning {repo['name']}: {e}[/red]")

        finally:
            # Always clean up the clone
            if os.path.exists(tmp_dir):
                shutil.rmtree(tmp_dir, ignore_errors=True)

        # Polite delay between repos
        if i < len(repos) - 1:
            console.print(f"[dim]Waiting {CLONE_DELAY}s before next repo...[/dim]")
            time.sleep(CLONE_DELAY)

    # Final summary
    console.print(Panel(
        f"[bold]Repos scanned:[/bold] {scanned}\n"
        f"[bold]Repos skipped:[/bold] {skipped}\n"
        f"[bold]Total confirmed findings:[/bold] {len(all_findings)}\n"
        f"[bold]Reports saved to:[/bold] {output_dir}",
        title="Hunt Complete",
        border_style="green" if all_findings else "yellow",
    ))

    if all_findings:
        console.print("\n[bold green]Repos with findings:[/bold green]")
        for repo_name in set(f["repo"] for f in all_findings):
            count = sum(1 for f in all_findings if f["repo"] == repo_name)
            console.print(f"  [red]★[/red] {repo_name} -- {count} finding(s)")

    return all_findings
