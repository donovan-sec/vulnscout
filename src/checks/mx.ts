// MX + non-sending-domain hygiene. A domain with MX receives mail (real
// spoofing target). A domain that sends nothing should be locked shut with
// "v=spf1 -all", p=reject, and a null MX so it can't be abused for phishing.

import type { Finding } from "../lib/types.ts";
import { mx } from "../lib/dns.ts";

export interface MxResult {
  findings: Finding[];
  hasMx: boolean;
}

export async function checkMx(domain: string): Promise<MxResult> {
  const records = await mx(domain);
  // Null MX = "0 ." — explicitly declares the domain receives no mail (RFC 7505).
  const nullMx = records.length === 1 && /\s\.$/.test(records[0]!.trim());
  const hasMx = records.length > 0 && !nullMx;
  return { findings: [], hasMx };
}

/**
 * Non-sending-domain finding. Call after SPF/DMARC/MX are known: if the domain
 * neither sends nor receives, flag that it isn't locked down for phishing.
 */
export function checkNonSendingLockdown(
  domain: string,
  opts: { sends: boolean; hasMx: boolean; spfHardFail: boolean; dmarcReject: boolean },
): Finding[] {
  if (opts.sends || opts.hasMx) return [];
  if (opts.spfHardFail && opts.dmarcReject) return []; // already locked shut
  return [
    {
      id: "domain.unlocked-non-sender",
      domain,
      severity: "LOW",
      traffic: "passive",
      title: "Non-sending domain not locked against phishing",
      detail:
        `${domain} neither sends nor receives mail, but lacks the hardened non-sender posture ` +
        `("v=spf1 -all" SPF, p=reject DMARC, null MX). It can be spoofed for phishing under your brand ` +
        `with no legitimate mail to protect.`,
      remediation: `Publish SPF "v=spf1 -all", DMARC "v=DMARC1; p=reject", and a null MX ("0 .").`,
      reference: "RFC 7505",
    },
  ];
}
