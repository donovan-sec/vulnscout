# VulnScout

An offensive-security toolkit for active web app and network pentesting, built for bug bounty work. VulnScout is the umbrella project — it merges a proven autonomous exploitation engine with two purpose-built companion tools covering recon and submission, so a target can move end to end from discovery to a filed report without switching tools.

## Structure

| Directory | What it is | Role |
|---|---|---|
| `core/` | [Strix](https://github.com/usestrix/strix) (forked as [donovan-sec/strix](https://github.com/donovan-sec/strix)) | The exploitation engine. Graph-of-agents architecture that chains vulnerabilities and validates every finding by producing a working proof-of-concept exploit before reporting it — no finding ships without proof. Sandboxed via Docker. |
| `recon/` | [mailrecon](https://github.com/donovan-sec/mailrecon) | Passive-by-default email-authentication and subdomain-takeover recon. Finds the DNS/DMARC/SPF failures and dangling CNAMEs almost nobody checks, before `core/` ever touches the target. |
| `submit/` | [h1-brain](https://github.com/donovan-sec/h1-brain) | HackerOne-integrated MCP server. Pulls program scope, past findings, and public disclosures into a briefing, and is the natural last stop once `core/` confirms something worth filing. |
| `legacy/` | Retired original VulnScout | The original Python/Claude-agentic-loop scanner this project started as. Kept for reference and history, not under active development. See `legacy/README.md` for its own docs. |
| `pipeline/` | Original work | Scripts bridging `recon/` → `core/` → `submit/` into one workflow, plus a content-discovery pass via [cariddi](https://github.com/edoardottt/cariddi) (external, pinned, GPL-3.0 — see below). See `pipeline/README.md`. |

## Getting started

```bash
./install.sh
```

Sets up an isolated Python 3.12 venv for `core/` and `submit/`, installs `recon/`'s bun dependencies, installs a pinned [cariddi](https://github.com/edoardottt/cariddi) binary via Go, and scaffolds a root `.env` from `.env.example`. Fill in your keys before running `core/` or `submit/` — see `.env.example` for what's required. Each subdirectory also has its own README with usage instructions specific to that piece.

## License

`core/` (Strix) is Apache 2.0. `recon/`, `submit/`, and `pipeline/` are original work.

`pipeline/crawl-targets.ts` invokes [cariddi](https://github.com/edoardottt/cariddi) (GPL-3.0) as an external pinned binary via subprocess — no cariddi source is vendored or linked into this repo. Managed as an arm's-length dependency the same way `core/` shells out to Caido, not merged in the way `core/`/`recon/`/`submit/` were. See `pipeline/README.md` for the exact pinned version and how to bump it.

See each subdirectory for its own LICENSE file.

## Legal

Only use against targets you own or have explicit written authorization to test.
