# pipeline/

Four small scripts bridging `recon/`, `core/`, and `submit/`. Deliberately not one orchestrator — see VS-3 in the backlog for why (short version: use these manually a few times before locking in a workflow shape as a single CLI).

## `recon-to-targets.ts`

`recon/` → `core/`. Filters mailrecon's JSON output down to domains worth a Strix scan, checks each against h1-brain's local scope data (`submit/h1_data.db`) if a program handle is given, and writes a `--target-list` file `core/` can consume directly.

**This is the scope-safety piece — build/run this first.** Without `--program`, no scope check happens and you are the scope authority for that run.

```bash
bun run recon/src/cli.ts audit example.com --format json > recon-output.json
bun pipeline/recon-to-targets.ts recon-output.json --program <h1-handle> --min-severity MEDIUM --out targets.txt
core/.venv/bin/strix --target-list targets.txt
```

## `crawl-targets.ts`

`recon/` → `core/`, content-discovery pass. Runs [cariddi](https://github.com/edoardottt/cariddi) against `recon-to-targets.ts`'s **already scope-checked** output, hunting for secrets/juicy endpoints/errors/info-leaks before Strix spends agent time on active exploitation. A leaked API key found here is already a disclosable finding on its own; a URL with errors/info matches but no secrets gets bucketed as a Strix follow-up candidate at URL granularity, not just domain.

**External dependency, managed not vendored.** cariddi is GPL-3.0 — installed by `install.sh` as a pinned binary (`go install .../cariddi@v1.4.6`, not `@latest`) and invoked here via subprocess only. Nothing from cariddi is vendored or linked into this repo's own code, so `vulnscout`'s own codebase stays Apache-2.0-clean. Bump the pinned version deliberately (a schema change in a newer release would silently break the JSONL parsing here) — see `install.sh`'s `CARIDDI_VERSION`.

**Behavior worth knowing before pointing this at anything** (both intentional cariddi design choices, not bugs, confirmed by reading `pkg/crawler/colly.go`): it **ignores robots.txt unconditionally** (no flag to change it) and **skips TLS certificate verification unconditionally**. Standard for a pentesting crawler, but only run this against explicitly authorized scope — same rule as `core/`. It does respect a `DomainGlob` restriction to the target's own host, so it won't wander off to arbitrary externally-linked sites.

```bash
bun pipeline/recon-to-targets.ts recon-output.json --program <h1-handle> --out targets.txt
bun pipeline/crawl-targets.ts targets.txt --out-findings crawl-findings.md --out-targets crawl-followup.txt
core/.venv/bin/strix --target-list crawl-followup.txt
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
