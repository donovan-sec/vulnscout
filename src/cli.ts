#!/usr/bin/env bun
// mailrecon CLI. Two commands:
//   audit <domain>        single-domain deep audit → markdown (client report)
//   bulk <file|domains>   ranked triage of many domains → csv/json
//
// Passive by default. Active checks require --scope <file> with authorized=true.

import { Scope } from "./lib/scope.ts";
import { auditDomain } from "./lib/audit.ts";
import { toCsv, toJson, toMarkdown } from "./lib/report.ts";
import type { DomainProfile } from "./lib/types.ts";

interface Args {
  command: string;
  targets: string[];
  scope?: string;
  format: "md" | "csv" | "json";
  takeover: boolean;
  verify: boolean;
  active: boolean;
  out?: string;
  concurrency: number;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    command: argv[0] ?? "",
    targets: [],
    format: "md",
    takeover: false,
    verify: false,
    active: false,
    concurrency: 8,
  };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i]!;
    switch (a) {
      case "--scope": args.scope = argv[++i]; break;
      case "--format": args.format = argv[++i] as Args["format"]; break;
      case "--takeover": args.takeover = true; break;
      case "--verify": args.verify = true; args.takeover = true; break;
      case "--active": args.active = true; break;
      case "--out": args.out = argv[++i]; break;
      case "--concurrency": args.concurrency = parseInt(argv[++i] ?? "8", 10); break;
      default: args.targets.push(a);
    }
  }
  return args;
}

async function loadTargets(targets: string[]): Promise<string[]> {
  const out = new Set<string>();
  for (const t of targets) {
    // A file of domains, one per line?
    const f = Bun.file(t);
    if (await f.exists()) {
      const text = await f.text();
      for (const line of text.split("\n")) {
        const d = line.trim().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
        if (d && !d.startsWith("#")) out.add(d);
      }
    } else {
      out.add(t.replace(/^https?:\/\//, "").replace(/\/.*$/, ""));
    }
  }
  return [...out];
}

/** Bounded-concurrency map. */
async function mapPool<T, R>(items: T[], n: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let idx = 0;
  async function worker() {
    while (idx < items.length) {
      const cur = idx++;
      results[cur] = await fn(items[cur]!);
    }
  }
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  return results;
}

const HELP = `mailrecon — email-auth + subdomain-takeover recon

USAGE
  mailrecon audit <domain> [options]        single-domain client report (markdown)
  mailrecon bulk  <file|domain...> [options] ranked triage (csv/json)

OPTIONS
  --scope <file>     authorization file; required to enable active checks
  --takeover         include subdomain-takeover detection (passive)
  --verify           confirm takeovers via HTTP (light-active, scope-gated)
  --active           allow active checks (brute enum); requires authorized scope
  --format md|csv|json   output format (audit defaults md, bulk defaults csv)
  --out <file>       write output to file instead of stdout
  --concurrency <n>  parallel domains for bulk (default 8)

SCOPE FILE (JSON)
  { "engagement": "acme-2026", "authorized": true,
    "inScope": ["*.acme.com"], "outOfScope": ["legacy.acme.com"] }

Passive by default: with no --scope, mailrecon sends zero traffic to the target.
`;

async function main() {
  const args = parseArgs(Bun.argv.slice(2));

  if (!args.command || args.command === "help" || args.command === "--help") {
    console.log(HELP);
    process.exit(0);
  }
  if (args.command !== "audit" && args.command !== "bulk") {
    console.error(`Unknown command: ${args.command}\n`);
    console.log(HELP);
    process.exit(1);
  }

  const scope = args.scope ? await Scope.fromFile(args.scope) : Scope.passiveOnly();
  const targets = await loadTargets(args.targets);
  if (targets.length === 0) {
    console.error("No targets. Pass a domain or a file of domains.");
    process.exit(1);
  }

  // Scope-mode banner to stderr (keeps stdout clean for piping).
  console.error(`[mailrecon] engagement: ${scope.engagement}`);
  console.error(`[mailrecon] mode: ${args.scope ? "scope-authorized" : "PASSIVE-ONLY"} | targets: ${targets.length}`);
  if (args.verify && !args.scope) {
    console.error(`[mailrecon] note: --verify is light-active and will be skipped without an authorized --scope`);
  }

  const opts = { scope, takeover: args.takeover, verify: args.verify };
  const profiles: DomainProfile[] = await mapPool(targets, args.concurrency, async (d) => {
    if (scope.isExcluded(d)) {
      console.error(`[mailrecon] skip (out of scope): ${d}`);
      return { domain: d, hasMx: false, sends: false, findings: [] };
    }
    process.stderr.write(`  scanning ${d} ...\n`);
    return auditDomain(d, opts);
  });

  let output: string;
  if (args.command === "audit") {
    const fmt = args.format === "md" && Bun.argv.includes("--format") ? args.format : args.format ?? "md";
    output =
      fmt === "csv" ? toCsv(profiles) :
      fmt === "json" ? toJson(profiles) :
      toMarkdown(profiles, scope.engagement);
  } else {
    output =
      args.format === "json" ? toJson(profiles) :
      args.format === "md" ? toMarkdown(profiles, scope.engagement) :
      toCsv(profiles);
  }

  if (args.out) {
    await Bun.write(args.out, output);
    console.error(`[mailrecon] wrote ${args.out}`);
  } else {
    console.log(output);
  }
}

main().catch((e) => {
  console.error(`[mailrecon] fatal: ${e?.message ?? e}`);
  process.exit(1);
});
