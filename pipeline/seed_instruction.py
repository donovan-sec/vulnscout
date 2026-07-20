#!/usr/bin/env python3
"""
submit/ -> core/ bridge (pre-scan direction).

Calls h1-brain's hack(handle) directly -- same function the MCP server
exposes as a tool, just invoked in-process instead of over MCP -- and writes
the resulting attack briefing to a file Strix can consume via
--instruction-file.

hack(handle) does a live HackerOne API call to refresh scope data, so this
needs real H1_USERNAME / H1_API_TOKEN credentials (same .env as submit/ on
its own). It is not a pure offline read like recon-to-targets.ts's scope
check -- it's meant to be run once at the start of a session, not on every
pipeline invocation.

Usage:
    submit/.venv/bin/python pipeline/seed_instruction.py <program-handle> [--out instructions.md]
"""

import argparse
import asyncio
import sys
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
SUBMIT_DIR = REPO_ROOT / "submit"


def _load_hack():
    """Import submit/server.py's hack() without triggering mcp.run()."""
    sys.path.insert(0, str(SUBMIT_DIR))
    try:
        import server  # submit/server.py; guarded __main__ block, safe to import
    except KeyError as e:
        raise SystemExit(
            f"Missing credential: {e}. h1-brain needs H1_USERNAME and H1_API_TOKEN "
            f"set (see .env.example at the repo root)."
        ) from e
    return server.hack


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("handle", help="HackerOne program handle")
    parser.add_argument(
        "--out",
        default=None,
        help="Output path for the instruction file (default: pipeline/<handle>-instructions.md)",
    )
    args = parser.parse_args()

    out_path = Path(args.out) if args.out else Path(__file__).parent / f"{args.handle}-instructions.md"

    hack = _load_hack()
    print(f"Fetching fresh scope + building briefing for '{args.handle}'...", file=sys.stderr)
    try:
        briefing = await hack(args.handle)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            raise SystemExit(
                "HackerOne rejected H1_USERNAME/H1_API_TOKEN (401 Unauthorized). "
                "Check the token hasn't expired or been revoked."
            ) from e
        if e.response.status_code == 404:
            raise SystemExit(
                f"Program '{args.handle}' not found on HackerOne (404). Check the handle is correct."
            ) from e
        raise SystemExit(f"HackerOne API error: {e}") from e

    # server.py's _api_get retries a 429 three times then returns the
    # response WITHOUT raise_for_status() -- hack() can silently proceed on
    # a rate-limited/empty response, wipe cached scope rows for this handle,
    # and produce a briefing that looks normal but has no real scope data
    # behind it (Forge review, 2026-07-20). "No scopes found for this
    # program." (server.py) fires on both a genuinely scope-less program
    # AND a 429-degraded empty response -- can't tell them apart from the
    # briefing text alone, so warn loudly rather than claim false certainty.
    if "No scopes found for this program." in briefing:
        print(
            "WARNING: the briefing has no scope section. This can mean the program "
            "genuinely has no bounty-eligible scope right now, OR it can mean the "
            "HackerOne API call was rate-limited (429) and hack() silently proceeded "
            "on an empty response. Verify manually before trusting this briefing.",
            file=sys.stderr,
        )

    out_path.write_text(briefing, encoding="utf-8")
    print(f"Wrote briefing to {out_path}", file=sys.stderr)
    print(f"\nRun Strix with:\n  core/.venv/bin/strix --target-list <targets> --instruction-file {out_path}")


if __name__ == "__main__":
    asyncio.run(main())
