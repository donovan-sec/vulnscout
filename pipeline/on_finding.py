#!/usr/bin/env python3
"""
core/ -> submit/ bridge (post-scan direction).

Strix has no external plugin/callback API -- vulnerability_found_callback
(core/strix/report/state.py) is wired internally to its own CLI display and
isn't something an outside script can register against without patching
Strix's source. Instead of forking Strix to add a hook, this reads the
stable on-disk artifact Strix already writes during and after every scan:
strix_runs/<run_name>/vulnerabilities.json (a JSON array of report dicts,
written atomically on every new finding -- see write_vulnerabilities() in
core/strix/report/writer.py).

For each confirmed finding, cross-references h1-brain's local disclosed-
reports dataset (submit/disclosed_reports.db, FTS5-searchable) for
similar past write-ups on the same program -- calibrates severity/style
expectations before you write the real report. This does not file
anything; h1-brain has no write path to HackerOne (see VS-3 backlog).

Usage:
    core/.venv/bin/python pipeline/on_finding.py <run_name> [--program <handle>]

    # or point it at an arbitrary run directory directly:
    core/.venv/bin/python pipeline/on_finding.py --run-dir ./strix_runs/run-abc123
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DISCLOSED_DB = REPO_ROOT / "submit" / "disclosed_reports.db"


def load_vulnerabilities(run_dir: Path) -> list[dict]:
    vuln_path = run_dir / "vulnerabilities.json"
    if not vuln_path.exists():
        raise SystemExit(
            f"No vulnerabilities.json in {run_dir} -- either the run hasn't produced "
            f"any confirmed findings yet, or this isn't a real Strix run directory."
        )
    try:
        data = json.loads(vuln_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SystemExit(f"{vuln_path} is not valid JSON: {e}") from e
    if not isinstance(data, list):
        raise SystemExit(f"{vuln_path} must be a JSON array of finding objects (Strix's own format)")
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise SystemExit(f"{vuln_path} entry {i} is not an object")
    return data


def find_similar(conn: sqlite3.Connection, finding: dict, program: str | None, limit: int = 5) -> list[dict]:
    """FTS5 search over title+body using the finding's own title as the query."""
    title = finding.get("title") or ""
    if not isinstance(title, str) or not title:
        return []

    # FTS5 MATCH needs a query expression, not free text with punctuation.
    # Keep alnum tokens only, and double-quote each one so reserved FTS5
    # operator words (AND/OR/NOT) that happen to appear in a Strix-generated
    # title are treated as literal search terms instead of breaking the
    # query -- unquoted tokens raised "fts5: syntax error" on titles like
    # "AND-based SQL injection" (Forge review, 2026-07-20).
    raw_tokens = [t for t in "".join(c if c.isalnum() else " " for c in title).split() if len(t) > 2]
    if not raw_tokens:
        return []
    quoted_tokens = ['"' + t.replace('"', '""') + '"' for t in raw_tokens[:8]]
    match_query = " OR ".join(quoted_tokens)

    sql = """
        SELECT dr.id, dr.title, dr.weakness_name, dr.program_handle, dr.bounty_amount
        FROM disclosed_reports_fts
        JOIN disclosed_reports dr ON dr.id = disclosed_reports_fts.rowid
        WHERE disclosed_reports_fts MATCH ?
    """
    params: list = [match_query]
    if program:
        sql += " AND dr.program_handle = ?"
        params.append(program)
    sql += " ORDER BY rank LIMIT ?"
    params.append(limit)

    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError as e:
        print(f"  (FTS query failed for this finding, skipping: {e})", file=sys.stderr)
        return []
    return [dict(r) for r in rows]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run_name", nargs="?", help="Strix run name (looks in ./strix_runs/<run_name>)")
    parser.add_argument("--run-dir", help="Explicit path to a run directory, overrides run_name")
    parser.add_argument("--program", help="HackerOne program handle to scope the disclosed-report search to")
    args = parser.parse_args()

    if args.run_dir:
        run_dir = Path(args.run_dir)
    elif args.run_name:
        if "/" in args.run_name or "\\" in args.run_name or args.run_name in (".", ".."):
            parser.error("run_name must be a bare name, not a path -- use --run-dir to point at an arbitrary directory")
        run_dir = Path.cwd() / "strix_runs" / args.run_name
    else:
        parser.error("provide either run_name or --run-dir")

    if not run_dir.is_dir():
        raise SystemExit(f"Run directory not found: {run_dir}")

    if not DISCLOSED_DB.exists():
        raise SystemExit(
            f"{DISCLOSED_DB} not found. h1-brain's disclosed-reports dataset is required "
            f"for this script -- see submit/README.md."
        )

    findings = load_vulnerabilities(run_dir)
    if not findings:
        print("No findings in this run yet.", file=sys.stderr)
        return

    conn = sqlite3.connect(f"file:{DISCLOSED_DB}?mode=ro", uri=True)

    for finding in findings:
        title = finding.get("title") or "(untitled)"
        severity = (finding.get("severity") or "?").upper()
        print(f"\n{'=' * 70}")
        print(f"[{severity}] {title}  ({finding.get('id', '?')})")
        if finding.get("cwe"):
            print(f"CWE: {finding['cwe']}")

        similar = find_similar(conn, finding, args.program)
        if not similar:
            print("No similar disclosed reports found for calibration.")
            continue

        print(f"Similar disclosed reports ({'program: ' + args.program if args.program else 'all programs'}):")
        for s in similar:
            bounty = f"${s['bounty_amount']:,.0f}" if s.get("bounty_amount") else "no bounty listed"
            weak = s.get("weakness_name") or "unknown weakness type"
            print(f"  - #{s['id']} [{s['program_handle']}] {s['title']} — {weak} — {bounty}")

    conn.close()


if __name__ == "__main__":
    main()
