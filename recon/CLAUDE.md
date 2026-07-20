# CLAUDE.md — mailrecon

Email-auth + subdomain-takeover recon CLI for bug bounty and security assessments. bun/TypeScript, standalone, portable to client VMs.

## Hard invariants
- **bun/bunx only.** Never npm/npx. TypeScript only.
- **Passive is the default and must stay that way.** Any new check defaults to `traffic: "passive"`. Anything that touches the target's infra MUST be classed `light-active` or `active` and gated through `Scope.blockReason()` / `Scope.allows()` before it runs. Never send target traffic without checking scope first.
- **Out-of-scope is a hard exclude**, even passively — respect `Scope.isExcluded()` everywhere a host is processed.
- **Findings carry their traffic class.** Never emit a finding without setting `traffic`.
- `provable: true` means impact is demonstrable (e.g. RDAP-confirmed unregistered destination). Don't set it on inference-only results.

## Architecture
- `src/lib/scope.ts` is the safety gate — the most important file. Changes here need care.
- `src/lib/dns.ts` — all DNS via DoH (dns.google), registrability via RDAP (rdap.org). All passive.
- `src/checks/*` — one file per check family. Each returns `Finding[]`.
- `src/lib/audit.ts` orchestrates one domain; `src/cli.ts` handles many.

## Adding a check
1. New file in `src/checks/` returning `Finding[]`.
2. Default `traffic: "passive"`. If it touches the target, gate it via the passed `Scope`.
3. Wire it into `auditDomain()` in `src/lib/audit.ts`.
4. Test against real domains before claiming it works (dralyx.co has a known duplicate-DMARC bug — good regression target).

## Verification before claiming done
- `bun --bun tsc --noEmit` must pass.
- Run `bun run src/cli.ts bulk` against dralyx.co/trendverse.io/dorkjobs.com — must flag the duplicate-DMARC on the first two.
- Confirm scope gates: `--verify` without `--scope` must print the "skipped" note and send no HTTP.

## Git
Standalone repo. Not part of PAI. Commit directly to main is fine here.
