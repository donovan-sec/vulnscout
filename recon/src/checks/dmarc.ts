// DMARC checks. Encodes the severity model: the crown jewel is a registrable
// rua/ruf destination (the "Alex attack" — register the typo'd domain, receive
// the victim's aggregate reports). Also: multiple records (RFC 7489 → treated
// as none), p=none, weak enforcement.

import type { Finding } from "../lib/types.ts";
import { txt, isRegistered, registrableDomain } from "../lib/dns.ts";

const RFC = "RFC 7489";

interface DmarcTags {
  p?: string;
  sp?: string;
  pct?: string;
  rua?: string[];
  ruf?: string[];
  adkim?: string;
  aspf?: string;
}

function parseDmarc(record: string): DmarcTags {
  const tags: DmarcTags = {};
  for (const part of record.split(";")) {
    const [k, v] = part.split("=").map((s) => s?.trim());
    if (!k || v === undefined) continue;
    switch (k.toLowerCase()) {
      case "p": tags.p = v.toLowerCase(); break;
      case "sp": tags.sp = v.toLowerCase(); break;
      case "pct": tags.pct = v; break;
      case "adkim": tags.adkim = v.toLowerCase(); break;
      case "aspf": tags.aspf = v.toLowerCase(); break;
      case "rua": tags.rua = extractMailtos(v); break;
      case "ruf": tags.ruf = extractMailtos(v); break;
    }
  }
  return tags;
}

function extractMailtos(v: string): string[] {
  return v
    .split(",")
    .map((u) => u.trim().replace(/^mailto:/i, ""))
    .filter(Boolean);
}

/** Check every rua/ruf destination domain for registrability. The crown jewel. */
async function checkReportDestinations(
  domain: string,
  tags: DmarcTags,
  findings: Finding[],
): Promise<void> {
  const dests = [...(tags.rua ?? []), ...(tags.ruf ?? [])];
  const seen = new Set<string>();
  for (const dest of dests) {
    const destDomain = dest.split("@")[1];
    if (!destDomain) continue;
    const apex = registrableDomain(destDomain);
    if (seen.has(apex)) continue;
    seen.add(apex);

    // Same registrable domain as the target → not a third-party takeover vector.
    if (apex === registrableDomain(domain)) continue;

    const status = await isRegistered(destDomain);
    if (!status.registered) {
      findings.push({
        id: "dmarc.registrable-report-destination",
        domain,
        severity: "CRITICAL",
        traffic: "passive",
        provable: status.confident,
        title: `DMARC report destination "${destDomain}" is unregistered and claimable`,
        detail:
          `The DMARC record routes aggregate/forensic reports to ${dest}, but the ` +
          `destination domain ${apex} appears unregistered (${status.source}: ${status.raw}). ` +
          `Anyone can register ${apex}, stand up that mailbox, and begin receiving the ` +
          `domain's DMARC reports from every major mailbox provider — a complete census ` +
          `of sending infrastructure, including internal systems not in SPF. This is the ` +
          `"register the typo" attack: silent, no intrusion, and reportable under GDPR.`,
        evidence: `rua/ruf destination: ${dest}`,
        remediation:
          `Fix the typo in the report address and confirm the destination domain is one ` +
          `you or your provider controls. Prefer a destination on your own domain.`,
        reference: RFC,
      });
    }
  }
}

export async function checkDmarc(domain: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const records = (await txt(`_dmarc.${domain}`)).filter((r) =>
    r.toLowerCase().startsWith("v=dmarc1"),
  );

  if (records.length === 0) {
    findings.push({
      id: "dmarc.missing",
      domain,
      severity: "HIGH",
      traffic: "passive",
      title: "No DMARC record",
      detail:
        `No DMARC policy is published at _dmarc.${domain}. Receivers apply no ` +
        `DMARC-based handling, so the domain can be freely spoofed.`,
      remediation: `Publish a DMARC record, starting at p=none with rua= for visibility, then ramp to quarantine/reject.`,
      reference: RFC,
    });
    return findings;
  }

  if (records.length > 1) {
    // RFC 7489 §6.6.3: multiple records → receivers treat domain as having none.
    findings.push({
      id: "dmarc.multiple-records",
      domain,
      severity: "HIGH",
      traffic: "passive",
      provable: true,
      title: `Multiple DMARC records (${records.length}) — policy is effectively OFF`,
      detail:
        `${records.length} DMARC records are published at _dmarc.${domain}. Per RFC 7489 ` +
        `§6.6.3, when a receiver finds more than one DMARC record it MUST treat the domain ` +
        `as having no DMARC record at all. Whatever policy each record names (even p=reject) ` +
        `does not apply — the domain is fully spoofable.`,
      evidence: records.map((r, i) => `[${i + 1}] ${r}`).join("\n"),
      remediation: `Delete all but one DMARC record so exactly one remains at _dmarc.${domain}.`,
      reference: RFC,
    });
    // Still scan every record's destinations for the crown-jewel finding.
    for (const r of records) await checkReportDestinations(domain, parseDmarc(r), findings);
    return findings;
  }

  const record = records[0]!;
  const tags = parseDmarc(record);
  await checkReportDestinations(domain, tags, findings);

  const policy = tags.p ?? "none";
  const hasRua = (tags.rua?.length ?? 0) > 0;

  if (policy === "none" && !hasRua) {
    findings.push({
      id: "dmarc.none-no-rua",
      domain,
      severity: "HIGH",
      traffic: "passive",
      title: "DMARC p=none with no rua — no enforcement and no visibility",
      detail:
        `The policy is p=none (monitor only, no enforcement) and there is no rua= address, ` +
        `so no aggregate reports are collected either. The domain is spoofable and the owner is blind to it.`,
      evidence: record,
      remediation: `Add rua= for visibility, then ramp the policy to quarantine and reject.`,
      reference: RFC,
    });
  } else if (policy === "none") {
    findings.push({
      id: "dmarc.policy-none",
      domain,
      severity: "HIGH",
      traffic: "passive",
      title: "DMARC p=none — monitoring only, no spoofing protection",
      detail: `Policy is p=none: receivers take no action on failing mail. The domain remains spoofable.`,
      evidence: record,
      remediation: `After confirming legitimate mail aligns via rua reports, ramp to p=quarantine then p=reject.`,
      reference: RFC,
    });
  } else if (policy === "quarantine") {
    findings.push({
      id: "dmarc.policy-quarantine",
      domain,
      severity: "MEDIUM",
      traffic: "passive",
      title: "DMARC p=quarantine — spoofed mail is foldered, not rejected",
      detail: `Policy is p=quarantine. Failing mail lands in spam rather than being rejected; reject is the hardened end state.`,
      evidence: record,
      remediation: `After a clean reporting period, move to p=reject.`,
      reference: RFC,
    });
  }

  const pct = tags.pct ? parseInt(tags.pct, 10) : 100;
  if (!Number.isNaN(pct) && pct < 100) {
    findings.push({
      id: "dmarc.partial-pct",
      domain,
      severity: "MEDIUM",
      traffic: "passive",
      title: `DMARC pct=${pct} — policy applied to only ${pct}% of failing mail`,
      detail: `pct=${pct} means ${100 - pct}% of failing messages slip through with no policy applied.`,
      evidence: record,
      remediation: `Set pct=100 (or remove the tag) once confident in alignment.`,
      reference: RFC,
    });
  }

  return findings;
}
