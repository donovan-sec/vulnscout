# VulnScout

An offensive-security toolkit for active web app and network pentesting, built for bug bounty work. VulnScout is the umbrella project — it merges a proven autonomous exploitation engine with two purpose-built companion tools covering recon and submission, so a target can move end to end from discovery to a filed report without switching tools.

## Structure

| Directory | What it is | Role |
|---|---|---|
| `core/` | [Strix](https://github.com/usestrix/strix) (forked as [donovan-sec/strix](https://github.com/donovan-sec/strix)) | The exploitation engine. Graph-of-agents architecture that chains vulnerabilities and validates every finding by producing a working proof-of-concept exploit before reporting it — no finding ships without proof. Sandboxed via Docker. |
| `recon/` | [mailrecon](https://github.com/donovan-sec/mailrecon) | Passive-by-default email-authentication and subdomain-takeover recon. Finds the DNS/DMARC/SPF failures and dangling CNAMEs almost nobody checks, before `core/` ever touches the target. |
| `submit/` | [h1-brain](https://github.com/donovan-sec/h1-brain) | HackerOne-integrated MCP server. Pulls program scope, past findings, and public disclosures into a briefing, and is the natural last stop once `core/` confirms something worth filing. |
| `legacy/` | Retired original VulnScout | The original Python/Claude-agentic-loop scanner this project started as. Kept for reference and history, not under active development. See `legacy/README.md` for its own docs. |


## Getting started

```bash
./install.sh
```

Sets up an isolated Python 3.12 venv for `core/` and `submit/`, installs `recon/`'s bun dependencies, and scaffolds a root `.env` from `.env.example`. Fill in your keys before running `core/` or `submit/` — see `.env.example` for what's required. Each subdirectory also has its own README with usage instructions specific to that piece.

## License

`core/` (Strix) is Apache 2.0. `recon/` and `submit/` are original work. See each subdirectory for its own LICENSE file.

## Legal

Only use against targets you own or have explicit written authorization to test.
