# mailrecon

Email-authentication and subdomain-takeover recon for bug bounty triage and security assessments. Finds the silent DNS failures almost nobody checks: registrable DMARC report destinations (the "register the typo, receive the reports" attack), duplicate DMARC records that quietly void enforcement, wide-open SPF, and dangling CNAMEs ripe for subdomain takeover.

**Passive by default.** With no scope file, mailrecon sends zero traffic to the target — it only queries public DNS resolvers, RDAP, and certificate-transparency logs. Active checks are gated behind an explicit, logged authorization file.

## Install

```bash
cd ~/Git/mailrecon
bun install
```

Requires [bun](https://bun.sh). No other dependencies.

## Usage

```bash
# Single-domain client report (markdown)
bun run src/cli.ts audit example.com

# Include subdomain-takeover detection (still passive)
bun run src/cli.ts audit example.com --takeover

# Bulk triage a scope file → ranked CSV
bun run src/cli.ts bulk scope-domains.txt --format csv --out triage.csv

# Confirm takeovers via HTTP (light-active — requires authorized scope)
bun run src/cli.ts audit example.com --verify --scope scope.json
```

## Traffic classes & safety

Every check is one of three classes. The mode banner prints to stderr on every run so you always know what you're sending.

| Class | Touches | Default |
|---|---|---|
| **passive** | Public DNS / RDAP / crt.sh only — never the target | always on |
| **light-active** | One unauthenticated GET to a dangling target (takeover `--verify`) | off; needs authorized `--scope` |
| **active** | Probing the target's infra (brute enum) | off; needs `--active` + authorized `--scope` |

### Scope file

```json
{
  "engagement": "acme-2026-q2",
  "authorized": true,
  "inScope": ["*.acme.com", "acme.com"],
  "outOfScope": ["legacy.acme.com"]
}
```

- No scope file → **passive-only**. Run it against anything.
- `authorized: false` → active checks refuse to run (safe staging state).
- `outOfScope` hosts are dropped from output **entirely**, even passively.
- Active checks only run against hosts matching `inScope`.

This is what keeps you inside bounty rules and SOW boundaries: an out-of-scope active probe can void a bounty or breach a contract, so the safe path is the default path.

## What it finds

**CRITICAL**
- DMARC `rua`/`ruf` pointing at an **unregistered, claimable domain** (confirmed via RDAP) — register it and receive the target's reports. Flagged `provable`.
- Confirmed subdomain takeover (fingerprint match + unclaimed-error body via `--verify`).

**HIGH**
- Multiple DMARC records → RFC 7489 treats domain as having none (full spoofability).
- DMARC `p=none`, or no DMARC on a domain with MX.
- SPF `+all` / `?all`.
- Takeover candidate with a dangling (no live A record) fingerprint match.

**MEDIUM / LOW / INFO**
- `p=quarantine` where reject fits, `pct<100`, SPF softfail on senders, >10 SPF lookups (permerror), missing DKIM/MTA-STS, unlocked non-sending domains.

Findings are ranked **provable-first within severity** — bounty programs pay for demonstrated impact, and the provable ones are what you can actually prove.

## Architecture

```
src/
  cli.ts            entrypoint: audit + bulk commands, arg parsing, concurrency pool
  lib/
    types.ts        Finding / DomainProfile / ScopeConfig + severity ranks
    scope.ts        authorization engine (the safety gate)
    dns.ts          passive DNS (DoH) + RDAP registrability
    audit.ts        single-domain orchestrator
    report.ts       csv / json / markdown formatters + ranking
  checks/
    dmarc.ts        DMARC parse, multiple-records, registrable-destination (crown jewel)
    spf.ts          SPF mechanisms, +all/?all, 10-lookup limit
    mx.ts           MX profiling + non-sending lockdown
    takeover.ts     crt.sh enum + runtime fingerprints + verify
```

## Fingerprint data

Subdomain-takeover fingerprints are fetched at runtime from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz), cached for 24h at `~/.cache/mailrecon/`, with a vendored fallback so a broken upstream never kills a run.

## License

MIT
