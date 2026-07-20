// SPF checks. Flags wide-open mechanisms (+all/?all), softfail on senders, and
// the >10 DNS-lookup limit (RFC 7208 §4.6.4 → permerror → SPF silently fails
// for everyone, which can break legit mail or be argued as a finding).

import type { Finding } from "../lib/types.ts";
import { txt } from "../lib/dns.ts";

const RFC = "RFC 7208";

const SEND_MECHANISMS = /(^|\s)[?~+-]?(include:|a[:\s]|a$|mx[:\s]|mx$|ip4:|ip6:|exists:)/i;
const LOOKUP_MECHANISMS = /(include:|[?~+-]?a[:\s]|[?~+-]?a$|[?~+-]?mx[:\s]|[?~+-]?mx$|ptr|exists:|redirect=)/gi;

export interface SpfResult {
  findings: Finding[];
  /** Whether SPF declares any sending mechanism (drives domain profiling). */
  sends: boolean;
}

/** Count DNS-lookup-incurring mechanisms one level deep + recurse includes (cap). */
async function countLookups(record: string, depth = 0, seen = new Set<string>()): Promise<number> {
  if (depth > 10) return 11; // already over budget; stop recursing
  let count = 0;
  const includes: string[] = [];
  for (const term of record.split(/\s+/)) {
    const m = term.match(/^[?~+-]?include:(.+)$/i);
    if (m && m[1]) {
      count++;
      includes.push(m[1]);
      continue;
    }
    if (/^[?~+-]?(a|mx)([:\s]|$)/i.test(term) || /^(ptr|exists:|redirect=)/i.test(term)) {
      count++;
    }
  }
  for (const inc of includes) {
    if (seen.has(inc)) continue;
    seen.add(inc);
    const recs = (await txt(inc)).filter((r) => r.toLowerCase().startsWith("v=spf1"));
    if (recs[0]) count += await countLookups(recs[0], depth + 1, seen);
  }
  return count;
}

export async function checkSpf(domain: string): Promise<SpfResult> {
  const findings: Finding[] = [];
  const records = (await txt(domain)).filter((r) => r.toLowerCase().startsWith("v=spf1"));

  if (records.length === 0) {
    findings.push({
      id: "spf.missing",
      domain,
      severity: "MEDIUM",
      traffic: "passive",
      title: "No SPF record",
      detail: `No SPF record published for ${domain}. Receivers cannot authorize sending IPs via SPF.`,
      remediation: `Publish an SPF record. For a non-sending domain, use "v=spf1 -all".`,
      reference: RFC,
    });
    return { findings, sends: false };
  }

  if (records.length > 1) {
    findings.push({
      id: "spf.multiple-records",
      domain,
      severity: "MEDIUM",
      traffic: "passive",
      title: `Multiple SPF records (${records.length}) — SPF permerror`,
      detail: `More than one SPF record causes a permerror (RFC 7208 §3.2); SPF evaluation fails for the domain.`,
      evidence: records.join("\n"),
      remediation: `Merge into a single v=spf1 record.`,
      reference: RFC,
    });
  }

  const record = records[0]!;
  const sends = SEND_MECHANISMS.test(record);

  if (/[?~+-]?all/i.test(record)) {
    if (/(^|\s)\+?all\b/i.test(record) && !/[~?-]all/i.test(record)) {
      findings.push({
        id: "spf.plus-all",
        domain,
        severity: "HIGH",
        traffic: "passive",
        title: 'SPF ends in "+all" — every sender passes',
        detail: `"+all" authorizes any IP on the internet to send as ${domain}. SPF provides no protection.`,
        evidence: record,
        remediation: `Replace "+all" with "-all" (hard fail) and enumerate legitimate senders.`,
        reference: RFC,
      });
    } else if (/\?all\b/i.test(record)) {
      findings.push({
        id: "spf.neutral-all",
        domain,
        severity: "MEDIUM",
        traffic: "passive",
        title: 'SPF ends in "?all" (neutral) — no enforcement',
        detail: `"?all" is neutral: receivers treat all senders as unspecified, giving SPF no enforcement value.`,
        evidence: record,
        remediation: `Use "-all" once legitimate senders are enumerated.`,
        reference: RFC,
      });
    } else if (/~all\b/i.test(record) && sends) {
      findings.push({
        id: "spf.softfail",
        domain,
        severity: "LOW",
        traffic: "passive",
        title: 'SPF ends in "~all" (softfail) on a sending domain',
        detail: `Softfail marks unauthorized mail suspicious but still accepts it. With DMARC enforcing, "-all" is stronger.`,
        evidence: record,
        remediation: `Move to "-all" once confident all senders are listed.`,
        reference: RFC,
      });
    }
  }

  const lookups = await countLookups(record);
  if (lookups > 10) {
    findings.push({
      id: "spf.too-many-lookups",
      domain,
      severity: "MEDIUM",
      traffic: "passive",
      title: `SPF exceeds 10 DNS lookups (${lookups}) — permerror`,
      detail:
        `SPF evaluation incurs ${lookups} DNS lookups; RFC 7208 §4.6.4 caps it at 10. Over the limit, ` +
        `receivers return permerror and SPF fails — which both breaks deliverability for legitimate mail ` +
        `and removes the SPF leg of DMARC alignment for everyone.`,
      evidence: record,
      remediation: `Flatten includes or remove unused senders to get under 10 lookups.`,
      reference: RFC,
    });
  }

  return { findings, sends };
}
