# pipeline/

Three small scripts bridging `recon/`, `core/`, and `submit/`. Deliberately not one orchestrator — see VS-3 in the backlog for why (short version: use these manually a few times before locking in a workflow shape as a single CLI).

## `recon-to-targets.ts`

`recon/` → `core/`. Filters mailrecon's JSON output down to domains worth a Strix scan, checks each against h1-brain's local scope data (`submit/h1_data.db`) if a program handle is given, and writes a `--target-list` file `core/` can consume directly.

**This is the scope-safety piece — build/run this first.** Without `--program`, no scope check happens and you are the scope authority for that run.

```bash
bun run recon/src/cli.ts audit example.com --format json > recon-output.json
bun pipeline/recon-to-targets.ts recon-output.json --program <h1-handle> --min-severity MEDIUM --out targets.txt
core/.venv/bin/strix --target-list targets.txt
```

## `seed_instruction.py`

`submit/` → `core/`, pre-scan. Calls h1-brain's `hack(handle)` directly (in-process, not over MCP — same function the MCP server exposes as a tool) to build an attack briefing from program scope, your past reports, and public disclosures, then writes it to a file for Strix's `--instruction-file`.

Needs real `H1_USERNAME`/`H1_API_TOKEN` (same as `submit/` on its own) — it makes a live HackerOne API call to refresh scope data.

```bash
submit/.venv/bin/python pipeline/seed_instruction.py <h1-handle> --out instructions.md
core/.venv/bin/strix --target-list targets.txt --instruction-file instructions.md
```

## `on_finding.py`

`core/` → `submit/`, post-scan. Strix has no external callback API (`vulnerability_found_callback` is wired internally to its own CLI display), so this reads the stable on-disk artifact Strix writes during every scan instead: `strix_runs/<run_name>/vulnerabilities.json`. For each finding, cross-references h1-brain's disclosed-reports dataset (FTS5 search) for similar past write-ups — calibrates severity/style expectations before you write the real report.

Does not file anything anywhere — h1-brain has no HackerOne write path (see VS-3).

```bash
core/.venv/bin/python pipeline/on_finding.py <run_name> --program <h1-handle>
```
