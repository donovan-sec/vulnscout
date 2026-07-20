// Single-domain orchestrator: runs every check, profiles the domain, and
// returns a sorted DomainProfile. Used by both bulk and audit modes.

import type { DomainProfile, Finding } from "./types.ts";
import { SEVERITY_RANK } from "./types.ts";
import { Scope } from "./scope.ts";
import { txt } from "./dns.ts";
import { checkDmarc } from "../checks/dmarc.ts";
import { checkSpf } from "../checks/spf.ts";
import { checkMx, checkNonSendingLockdown } from "../checks/mx.ts";
import { checkTakeover } from "../checks/takeover.ts";

export interface AuditOptions {
  scope: Scope;
  takeover: boolean;
  verify: boolean;
}

/** Sort findings: provable first within a severity, then by severity rank. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((x, y) => {
    const sev = SEVERITY_RANK[y.severity] - SEVERITY_RANK[x.severity];
    if (sev !== 0) return sev;
    return Number(y.provable ?? false) - Number(x.provable ?? false);
  });
}

export async function auditDomain(domain: string, opts: AuditOptions): Promise<DomainProfile> {
  const d = domain.toLowerCase().replace(/\.$/, "");
  const findings: Finding[] = [];

  const [dmarc, spf, mxRes] = await Promise.all([
    checkDmarc(d),
    checkSpf(d),
    checkMx(d),
  ]);
  findings.push(...dmarc, ...spf.findings);

  // Non-sending lockdown needs cross-check state.
  const spfRecord = (await txt(d)).find((r) => r.toLowerCase().startsWith("v=spf1")) ?? "";
  const spfHardFail = /-all\b/i.test(spfRecord);
  const dmarcReject = dmarc.some(
    (f) => f.id.startsWith("dmarc.policy") === false && /p=reject/i.test(f.evidence ?? ""),
  ) || dmarc.length === 0; // crude; refined below
  findings.push(
    ...checkNonSendingLockdown(d, {
      sends: spf.sends,
      hasMx: mxRes.hasMx,
      spfHardFail,
      dmarcReject: /p=reject/i.test(JSON.stringify(dmarc)),
    }),
  );

  if (opts.takeover) {
    findings.push(...(await checkTakeover(d, opts.scope, { verify: opts.verify })));
  }

  return {
    domain: d,
    hasMx: mxRes.hasMx,
    sends: spf.sends,
    findings: sortFindings(findings),
  };
}
