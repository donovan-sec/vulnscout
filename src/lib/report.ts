// Output formatters. bulk → ranked CSV/JSON for triage; audit → markdown for
// a client-ready writeup.

import type { DomainProfile, Finding, Severity } from "./types.ts";
import { SEVERITY_RANK } from "./types.ts";

const SEV_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function topSeverity(p: DomainProfile): Severity {
  let top: Severity = "INFO";
  for (const f of p.findings) {
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[top]) top = f.severity;
  }
  return top;
}

/** Rank domains for triage: worst + provable + most findings first. */
export function rankProfiles(profiles: DomainProfile[]): DomainProfile[] {
  return [...profiles].sort((a, b) => {
    const sev = SEVERITY_RANK[topSeverity(b)] - SEVERITY_RANK[topSeverity(a)];
    if (sev !== 0) return sev;
    const prov = Number(b.findings.some((f) => f.provable)) - Number(a.findings.some((f) => f.provable));
    if (prov !== 0) return prov;
    return b.findings.length - a.findings.length;
  });
}

function csvCell(s: string): string {
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

export function toCsv(profiles: DomainProfile[]): string {
  const header = ["domain", "top_severity", "provable", "finding_count", "finding_id", "severity", "title"];
  const rows: string[] = [header.join(",")];
  for (const p of rankProfiles(profiles)) {
    const top = topSeverity(p);
    const provable = p.findings.some((f) => f.provable);
    if (p.findings.length === 0) {
      rows.push([p.domain, "INFO", "false", "0", "", "", "no findings"].map(csvCell).join(","));
      continue;
    }
    for (const f of p.findings) {
      rows.push(
        [p.domain, top, String(provable), String(p.findings.length), f.id, f.severity, f.title]
          .map(csvCell)
          .join(","),
      );
    }
  }
  return rows.join("\n");
}

export function toJson(profiles: DomainProfile[]): string {
  return JSON.stringify(rankProfiles(profiles), null, 2);
}

const SEV_EMOJI: Record<Severity, string> = {
  CRITICAL: "🔴",
  HIGH: "🟠",
  MEDIUM: "🟡",
  LOW: "🔵",
  INFO: "⚪",
};

function findingMd(f: Finding): string {
  const lines: string[] = [];
  const tag = f.provable ? " **[PROVABLE]**" : "";
  lines.push(`#### ${SEV_EMOJI[f.severity]} ${f.severity}${tag} — ${f.title}`);
  lines.push("");
  lines.push(`- **Host:** ${f.host ?? f.domain}`);
  lines.push(`- **Traffic class:** ${f.traffic}`);
  if (f.reference) lines.push(`- **Reference:** ${f.reference}`);
  lines.push("");
  lines.push(f.detail);
  if (f.evidence) {
    lines.push("");
    lines.push("```");
    lines.push(f.evidence);
    lines.push("```");
  }
  if (f.remediation) {
    lines.push("");
    lines.push(`**Remediation:** ${f.remediation}`);
  }
  lines.push("");
  return lines.join("\n");
}

/** Client-ready markdown report for a single domain (or several). */
export function toMarkdown(profiles: DomainProfile[], engagement: string): string {
  const out: string[] = [];
  out.push(`# Email Authentication & Takeover Assessment`);
  out.push("");
  out.push(`**Engagement:** ${engagement}  `);
  out.push(`**Generated:** ${new Date().toISOString()}  `);
  out.push(`**Domains assessed:** ${profiles.length}`);
  out.push("");

  // Executive summary table.
  out.push(`## Summary`);
  out.push("");
  out.push(`| Domain | Top severity | Findings | Provable |`);
  out.push(`|---|---|---|---|`);
  for (const p of rankProfiles(profiles)) {
    const top = topSeverity(p);
    const provable = p.findings.some((f) => f.provable) ? "yes" : "—";
    out.push(`| ${p.domain} | ${SEV_EMOJI[top]} ${top} | ${p.findings.length} | ${provable} |`);
  }
  out.push("");

  for (const p of rankProfiles(profiles)) {
    out.push(`## ${p.domain}`);
    out.push("");
    out.push(`Profile: ${p.hasMx ? "receives mail (MX present)" : "no MX"}, ${p.sends ? "sends mail" : "no sending mechanisms"}.`);
    out.push("");
    if (p.findings.length === 0) {
      out.push("_No findings._");
      out.push("");
      continue;
    }
    for (const sev of SEV_ORDER) {
      const group = p.findings.filter((f) => f.severity === sev);
      for (const f of group) out.push(findingMd(f));
    }
  }

  return out.join("\n");
}
