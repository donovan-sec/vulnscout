# VulnScout

An offensive-security toolkit for active web app and network pentesting, built for bug bounty work. VulnScout is the umbrella project — it merges a proven autonomous exploitation engine with two purpose-built companion tools covering recon and submission, so a target can move end to end from discovery to a filed report without switching tools.

## Structure

| Directory | What it is | Role |
|---|---|---|
| `core/` | [Strix](https://github.com/usestrix/strix) (forked as [donovan-sec/strix](https://github.com/donovan-sec/strix)) | The exploitation engine. Graph-of-agents architecture that chains vulnerabilities and validates every finding by producing a working proof-of-concept exploit before reporting it — no finding ships without proof. Sandboxed via Docker. |
| `recon/` | [mailrecon](https://github.com/donovan-sec/mailrecon) | Passive-by-default email-authentication and subdomain-takeover recon. Finds the DNS/DMARC/SPF failures and dangling CNAMEs almost nobody checks, before `core/` ever touches the target. |
| `submit/` | [h1-brain](https://github.com/donovan-sec/h1-brain) | HackerOne-integrated MCP server. Pulls program scope, past findings, and public disclosures into a briefing, and is the natural last stop once `core/` confirms something worth filing. |
| `legacy/` | Retired original VulnScout | The original Python/Claude-agentic-loop scanner this project started as. Kept for reference and history, not under active development. See `legacy/README.md` for its own docs. |

## Why this shape

VulnScout was originally a standalone Python tool using Claude in an agentic loop for CVE-hunting in C/C++ libraries (see `legacy/`). That approach is retired in favor of adopting [Strix](https://github.com/usestrix/strix) as the core engine and pivoting the whole project toward active web app + occasional network pentesting for bug bounty — a better match for where the value actually is.

Strix was chosen over several alternatives (T3MP3ST, Pentagi, HexStrike AI, PentestGPT, CAI, hackingBuddyGPT) after direct comparison on three things that mattered most: a real Docker sandbox (not bolted on), proof-by-execution validation (a finding must produce a working exploit, not just an LLM's opinion that it's real), and a permissive Apache 2.0 license with no commercial-use restriction.

`recon/` and `submit/` were folded in because they're the same workflow's other two phases, not separate projects: recon feeds targets into `core/`, `core/` produces validated findings, `submit/` turns those into a filed report.

## Getting started

Each subdirectory is self-contained with its own dependencies and setup — see the README in `core/`, `recon/`, and `submit/` for install and usage instructions specific to that piece. There is no unified install/build step across all three yet.

## License

`core/` (Strix) is Apache 2.0. `recon/` and `submit/` are original work. See each subdirectory for its own LICENSE file.

## Legal

Only use against targets you own or have explicit written authorization to test.
