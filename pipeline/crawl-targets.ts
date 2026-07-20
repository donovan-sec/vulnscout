#!/usr/bin/env bun
// recon/ -> core/ bridge, content-discovery pass.
//
// Runs cariddi (github.com/edoardottt/cariddi, pinned in install.sh to a
// specific tag) against an already scope-checked target list, hunting for
// secrets/juicy endpoints/errors/info-leaks before Strix spends agent time
// on active exploitation. Deliberately reads recon-to-targets.ts's OUTPUT
// (already scope-checked against h1-brain), not raw recon JSON -- the scope
// gate applies once, upstream, and is never duplicated or bypassable by
// skipping a step.
//
// cariddi is GPL-3.0. It is invoked here as an external pinned binary via
// subprocess, never vendored or linked into this repo's own code -- keeps
// vulnscout's own codebase Apache-2.0-clean. See pipeline/README.md.
//
// cariddi behavior worth knowing before pointing this at anything (both
// intentional design choices in cariddi itself, not bugs):
//   - ignores robots.txt unconditionally (no flag to change this)
//   - skips TLS certificate verification unconditionally
// Both are standard for a pentesting crawler but should be a deliberate
// choice, not a surprise -- only run this against explicitly authorized
// scope, same as core/.
//
// Usage:
//   bun pipeline/crawl-targets.ts <targets.txt> [--out-findings crawl-findings.md] [--out-targets crawl-targets.txt] [--also-http]
//
// <targets.txt> is recon-to-targets.ts's own output file (bare domains,
// one per line, # comments allowed).

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

const CARIDDI_VERSION = "v1.4.6"; // keep in sync with install.sh's CARIDDI_VERSION

interface MatcherResult {
  name: string;
  match: string;
}

interface CariddiLine {
  url: string;
  method: string;
  status_code: number;
  words: number;
  lines: number;
  content_type?: string;
  content_length?: number;
  matches?: {
    filetype?: unknown;
    parameters?: unknown[];
    errors?: MatcherResult[];
    infos?: MatcherResult[];
    secrets?: MatcherResult[];
  };
}

function usageAndExit(msg?: string): never {
  if (msg) console.error(`Error: ${msg}\n`);
  console.error(
    "Usage: bun pipeline/crawl-targets.ts <targets.txt> [--out-findings crawl-findings.md] [--out-targets crawl-targets.txt] [--also-http]",
  );
  process.exit(1);
}

const KNOWN_FLAGS = new Set(["--out-findings", "--out-targets", "--also-http"]);

function parseArgs(argv: string[]) {
  const args: {
    input?: string;
    outFindings: string;
    outTargets: string;
    alsoHttp: boolean;
  } = { outFindings: "crawl-findings.md", outTargets: "crawl-targets.txt", alsoHttp: false };

  const positional: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--") && !KNOWN_FLAGS.has(a)) usageAndExit(`unknown flag: ${a}`);
    if (a === "--out-findings") {
      if (i + 1 >= argv.length) usageAndExit("--out-findings requires a value");
      args.outFindings = argv[++i];
    } else if (a === "--out-targets") {
      if (i + 1 >= argv.length) usageAndExit("--out-targets requires a value");
      args.outTargets = argv[++i];
    } else if (a === "--also-http") {
      args.alsoHttp = true;
    } else {
      positional.push(a);
    }
  }
  args.input = positional[0];
  return args;
}

function readTargetDomains(inputPath: string): string[] {
  const text = readFileSync(inputPath, "utf-8");
  return text
    .split("\n")
    .map((l: string) => l.trim())
    .filter((l: string) => l && !l.startsWith("#"));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.input) usageAndExit("missing <targets.txt> argument");

  const inputPath = resolve(args.input);
  if (!existsSync(inputPath)) usageAndExit(`input file not found: ${inputPath}`);

  const domains = readTargetDomains(inputPath);
  if (domains.length === 0) {
    console.log("No targets in input file — nothing to crawl.");
    return;
  }

  const urls = domains.flatMap((d) => (args.alsoHttp ? [`https://${d}`, `http://${d}`] : [`https://${d}`]));

  console.error(`Crawling ${urls.length} URL(s) with cariddi...`);

  let proc: ReturnType<typeof Bun.spawn>;
  try {
    proc = Bun.spawn(["cariddi", "-json", "-s", "-e", "-err", "-info"], {
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
    });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      usageAndExit(
        "cariddi not found on PATH. Install it via install.sh, or manually: " +
          `go install github.com/edoardottt/cariddi/cmd/cariddi@${CARIDDI_VERSION} ` +
          "(and make sure $(go env GOPATH)/bin is on your PATH).",
      );
    }
    throw e;
  }

  // Writing to stdin can throw EPIPE if cariddi exits early (panic, bad
  // input, OOM) before reading everything -- same failure class as the
  // ENOENT case above, just a different trigger (Forge review, 2026-07-20).
  // Swallow it here and let the stdout/stderr/exitCode handling below
  // produce the real diagnosis instead of an uncaught stack trace.
  try {
    proc.stdin.write(urls.join("\n") + "\n");
    proc.stdin.end();
  } catch {
    // fall through -- exitCode/stderr below will explain what happened
  }

  const [stdout, stderr, exitCode] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
    proc.exited,
  ]);

  // Parse whatever cariddi produced BEFORE checking exit code. A late
  // crash (panic/OOM/timeout) after finding real secrets must not discard
  // those secrets -- for a tool whose whole job is not losing secrets,
  // silently throwing away already-found ones on a nonzero exit is the
  // wrong failure mode (Forge review, 2026-07-20). Findings are written
  // either way; a nonzero exit is surfaced as a loud warning afterward,
  // not treated as "nothing happened."
  const findingLines: string[] = [];
  const followupTargets: string[] = [];
  let secretsCount = 0;
  let followupCount = 0;
  let crawledCount = 0;

  for (const line of stdout.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    crawledCount++;

    let parsed: CariddiLine;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      console.error(`Skipping unparseable cariddi output line: ${trimmed.slice(0, 100)}`);
      continue;
    }

    const matches = parsed.matches;
    if (!matches) continue;

    const secrets = matches.secrets ?? [];
    const errors = matches.errors ?? [];
    const infos = matches.infos ?? [];

    if (secrets.length > 0) {
      secretsCount++;
      findingLines.push(`### ${parsed.url}\n`);
      findingLines.push(`Status: ${parsed.status_code} | Content-Type: ${parsed.content_type ?? "unknown"}\n`);
      findingLines.push("**Secrets found:**");
      for (const s of secrets) {
        findingLines.push(`- **${s.name}**: \`${s.match}\``);
      }
      findingLines.push("");
    } else if (errors.length > 0 || infos.length > 0) {
      followupCount++;
      followupTargets.push(parsed.url);
    }
  }

  // cariddi emits no stdout line at all for unreachable/dead targets (dead
  // hosts, timeouts) -- crawledCount is "URLs that responded", not "URLs
  // attempted". Label it accurately rather than implying full coverage
  // (Forge review, 2026-07-20).
  const crashNote = exitCode !== 0 ? `\n# WARNING: cariddi exited with code ${exitCode} -- results above may be incomplete.\n` : "";
  const findingsHeader = [
    `# Cariddi crawl findings — ${new Date().toISOString()}`,
    `# Source: ${args.input}`,
    `# ${urls.length} URL(s) submitted, ${crawledCount} returned a result, ${secretsCount} with secrets found, ${followupCount} flagged for Strix follow-up (errors/info, no secrets)`,
    crashNote,
    "",
  ].join("\n");
  await Bun.write(resolve(args.outFindings), findingsHeader + (findingLines.length ? findingLines.join("\n") : "No secrets found.\n"));

  const targetsHeader = [
    `# Generated by pipeline/crawl-targets.ts from ${args.input}`,
    `# URL-level targets flagged for Strix follow-up (errors/info matches, no secrets -- those are already in ${args.outFindings})`,
    `# ${followupTargets.length} target(s)`,
    crashNote,
    "",
  ].join("\n");
  await Bun.write(resolve(args.outTargets), targetsHeader + followupTargets.join("\n") + (followupTargets.length ? "\n" : ""));

  console.log(`${urls.length} URL(s) submitted, ${crawledCount} returned a result.`);
  console.log(`${secretsCount} URL(s) with secrets -> ${args.outFindings}`);
  console.log(`${followupCount} URL(s) flagged for Strix follow-up -> ${args.outTargets}`);
  if (secretsCount > 0) {
    console.log("Secrets found -- review crawl-findings.md before any disclosure or further automated action.");
  }
  if (exitCode !== 0) {
    console.error(
      `WARNING: cariddi exited with code ${exitCode} before finishing -- results above may be incomplete. stderr:\n${stderr}`,
    );
  }
}

main();
