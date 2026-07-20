#!/usr/bin/env bun
// recon/ -> core/ bridge.
//
// Reads mailrecon's JSON output, keeps only findings worth a Strix scan, and
// writes a --target-list file core/ can consume directly.
//
// Scope safety is the point of this script, not an afterthought: a domain
// with real findings still isn't a valid Strix target unless it's actually
// in scope for the bounty program you're working. If a HackerOne program
// handle is given, every candidate domain is checked against h1-brain's
// local scopes table (submit/h1_data.db) and anything not explicitly
// eligible_for_submission is dropped, not silently included.
//
// Usage:
//   bun pipeline/recon-to-targets.ts <recon-output.json> [--program <handle>] [--min-severity MEDIUM] [--out targets.txt]
//
// If --program is omitted, scope checking is skipped entirely and every
// candidate domain passes through -- this is intentional for non-bounty
// engagements (e.g. your own infra) where there is no HackerOne program to
// check against, but it means YOU are the scope authority in that mode.

import { Database } from "bun:sqlite";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

interface Finding {
  id: string;
  domain: string;
  host?: string;
  severity: Severity;
  provable?: boolean;
}

interface DomainProfile {
  domain: string;
  hasMx: boolean;
  sends: boolean;
  findings: Finding[];
}

interface ScopeRow {
  asset_identifier: string;
  asset_type: string | null;
  eligible_for_submission: number;
  eligible_for_bounty: number;
  max_severity: string | null;
}

// Asset types HackerOne uses for actual DNS/web hostnames. Anything else
// (mobile app IDs, source code repos, hardware, etc.) must not authorize a
// domain target just because the identifier string happens to match.
const DOMAIN_ASSET_TYPES = new Set([
  "URL",
  "WILDCARD",
  "CIDR", // matched by exact string only today -- see domainInScope note
  null, // some programs leave asset_type unset for plain domain rows
]);

const KNOWN_FLAGS = new Set(["--program", "--min-severity", "--out"]);

function parseArgs(argv: string[]) {
  const args: {
    input?: string;
    program?: string;
    minSeverity: Severity;
    out: string;
  } = { minSeverity: "MEDIUM", out: "targets.txt" };

  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--") && !KNOWN_FLAGS.has(a)) {
      usageAndExit(`unknown flag: ${a}`);
    }
    if (a === "--program") {
      if (i + 1 >= argv.length || argv[i + 1].startsWith("--")) {
        usageAndExit("--program requires a value");
      }
      args.program = argv[++i];
    } else if (a === "--min-severity") {
      if (i + 1 >= argv.length) usageAndExit("--min-severity requires a value");
      args.minSeverity = argv[++i] as Severity;
    } else if (a === "--out") {
      if (i + 1 >= argv.length) usageAndExit("--out requires a value");
      args.out = argv[++i];
    } else {
      positional.push(a);
    }
  }
  args.input = positional[0];
  return args;
}

function usageAndExit(msg?: string): never {
  if (msg) console.error(`Error: ${msg}\n`);
  console.error(
    "Usage: bun pipeline/recon-to-targets.ts <recon-output.json> [--program <handle>] [--min-severity MEDIUM] [--out targets.txt]",
  );
  process.exit(1);
}

// Domain-level match against a wildcard scope entry like "*.example.com" or
// "example.com". Deliberately conservative in both directions:
//   - a bare apex entry does NOT cover arbitrary subdomains unless the
//     program explicitly listed a wildcard
//   - a wildcard-only entry ("*.example.com") does NOT cover the apex
//     ("example.com") -- HackerOne's own scope semantics treat these as
//     distinct assets, and conflating them was a real false-positive bug
//     (Forge review, 2026-07-20): a domain not actually in scope could pass
//     the gate.
// Does not handle non-hostname scope shapes (URL paths, CIDR ranges) --
// those fail closed (return false) rather than guess, see DOMAIN_ASSET_TYPES.
function domainInScope(domain: string, assetIdentifier: string): boolean {
  const d = domain.toLowerCase();
  const a = assetIdentifier.toLowerCase().trim();
  if (a === d) return true;
  if (a.startsWith("*.")) {
    const suffix = a.slice(1); // ".example.com"
    return d.endsWith(suffix) && d !== suffix.slice(1);
  }
  return false;
}

function loadScopeRows(program: string): ScopeRow[] {
  const dbPath = resolve(import.meta.dir, "../submit/h1_data.db");
  if (!existsSync(dbPath)) {
    usageAndExit(
      `--program was given but submit/h1_data.db doesn't exist yet. ` +
        `Run h1-brain's fetch_program_scopes('${program}') tool at least once first.`,
    );
  }
  const db = new Database(dbPath, { readonly: true });
  try {
    const rows = db
      .query<ScopeRow, [string]>(
        "SELECT asset_identifier, asset_type, eligible_for_submission, eligible_for_bounty, max_severity FROM scopes WHERE program_handle = ?",
      )
      .all(program);
    if (rows.length === 0) {
      usageAndExit(
        `No scope rows found for program '${program}' in submit/h1_data.db. ` +
          `Run h1-brain's fetch_program_scopes('${program}') tool first, then retry.`,
      );
    }
    return rows;
  } finally {
    db.close();
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.input) usageAndExit("missing <recon-output.json> argument");

  const inputPath = resolve(args.input);
  if (!existsSync(inputPath)) usageAndExit(`input file not found: ${inputPath}`);

  let parsed: unknown;
  try {
    parsed = JSON.parse(await Bun.file(inputPath).text());
  } catch (e) {
    usageAndExit(`input file is not valid JSON: ${(e as Error).message}`);
  }
  if (!Array.isArray(parsed)) {
    usageAndExit("input file must be a JSON array of DomainProfile objects (mailrecon's --format json output)");
  }
  for (const [i, p] of parsed.entries()) {
    if (typeof p !== "object" || p === null || typeof (p as any).domain !== "string" || !Array.isArray((p as any).findings)) {
      usageAndExit(`input file entry ${i} is not a valid DomainProfile (needs "domain": string and "findings": array)`);
    }
  }
  const profiles = parsed as DomainProfile[];

  const minRank = SEVERITY_RANK[args.minSeverity];
  if (!minRank) usageAndExit(`invalid --min-severity: ${args.minSeverity}`);

  const scopeRows = args.program ? loadScopeRows(args.program) : null;

  const kept: string[] = [];
  const droppedOutOfScope: string[] = [];
  const droppedBelowThreshold: string[] = [];

  for (const profile of profiles) {
    const worthInvestigating = profile.findings.some((f) => {
      const rank = SEVERITY_RANK[f.severity];
      if (rank === undefined) {
        usageAndExit(
          `finding "${f.id}" on ${profile.domain} has unrecognized severity "${f.severity}" -- expected one of ${Object.keys(SEVERITY_RANK).join(", ")}`,
        );
      }
      return rank >= minRank || f.provable === true;
    });
    if (!worthInvestigating) {
      droppedBelowThreshold.push(profile.domain);
      continue;
    }

    if (scopeRows) {
      const inScope = scopeRows.some(
        (row) =>
          row.eligible_for_submission &&
          DOMAIN_ASSET_TYPES.has(row.asset_type) &&
          domainInScope(profile.domain, row.asset_identifier),
      );
      if (!inScope) {
        droppedOutOfScope.push(profile.domain);
        continue;
      }
    }

    kept.push(profile.domain);
  }

  const outPath = resolve(args.out);
  const header = [
    `# Generated by pipeline/recon-to-targets.ts from ${args.input}`,
    `# min-severity=${args.minSeverity} program=${args.program ?? "(none — scope check skipped)"}`,
    `# ${kept.length} target(s), ${droppedBelowThreshold.length} dropped below threshold, ${droppedOutOfScope.length} dropped out of scope`,
    "",
  ].join("\n");
  await Bun.write(outPath, header + kept.join("\n") + (kept.length ? "\n" : ""));

  console.log(`Wrote ${kept.length} target(s) to ${outPath}`);
  if (droppedBelowThreshold.length) {
    console.log(`Dropped (below ${args.minSeverity} / not provable): ${droppedBelowThreshold.join(", ")}`);
  }
  if (droppedOutOfScope.length) {
    console.log(`Dropped (out of scope for '${args.program}'): ${droppedOutOfScope.join(", ")}`);
  }
  if (!args.program) {
    console.log("No --program given — scope check was skipped. You are the scope authority for this run.");
  }
  if (kept.length === 0) {
    console.log("No targets to scan — nothing written beyond the header.");
  }
}

main();
