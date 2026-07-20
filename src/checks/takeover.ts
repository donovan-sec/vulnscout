// Subdomain takeover detection. Two phases:
//   1. PASSIVE: enumerate subdomains (crt.sh CT logs), resolve CNAMEs, match
//      targets against a fingerprint dataset fetched at runtime from upstream
//      (can-i-take-over-xyz), cached daily, with a vendored fallback.
//   2. LIGHT-ACTIVE (--verify, scope-gated): fetch the dangling target and look
//      for the service's "unclaimed" error body to confirm.

import type { Finding } from "../lib/types.ts";
import { cname, a } from "../lib/dns.ts";
import { Scope } from "../lib/scope.ts";

interface Fingerprint {
  service: string;
  cnames: string[];
  /** Strings that appear on the unclaimed/error page. */
  fingerprints: string[];
  /** Whether the service is currently considered vulnerable upstream. */
  vulnerable: boolean;
}

const UPSTREAM =
  "https://raw.githubusercontent.com/EdOverflow/can-i-take-over-xyz/master/fingerprints.json";
const CACHE = `${process.env.HOME}/.cache/mailrecon/fingerprints.json`;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

// Minimal vendored fallback so a broken upstream never kills a run.
const VENDORED: Fingerprint[] = [
  { service: "GitHub Pages", cnames: ["github.io"], fingerprints: ["There isn't a GitHub Pages site here."], vulnerable: true },
  { service: "AWS/S3", cnames: ["amazonaws.com"], fingerprints: ["NoSuchBucket", "The specified bucket does not exist"], vulnerable: true },
  { service: "Heroku", cnames: ["herokuapp.com", "herokudns.com"], fingerprints: ["No such app", "herokucdn.com/error-pages/no-such-app.html"], vulnerable: true },
  { service: "Fastly", cnames: ["fastly.net"], fingerprints: ["Fastly error: unknown domain"], vulnerable: true },
  { service: "Shopify", cnames: ["myshopify.com"], fingerprints: ["Sorry, this shop is currently unavailable"], vulnerable: true },
  { service: "Azure", cnames: ["azurewebsites.net", "cloudapp.net", "trafficmanager.net", "blob.core.windows.net"], fingerprints: ["404 Web Site not found"], vulnerable: true },
  { service: "Pantheon", cnames: ["pantheonsite.io"], fingerprints: ["The gods are wise", "404 error unknown site"], vulnerable: true },
  { service: "Tumblr", cnames: ["domains.tumblr.com"], fingerprints: ["Whatever you were looking for doesn't currently exist at this address"], vulnerable: true },
];

async function loadFingerprints(): Promise<Fingerprint[]> {
  // Fresh cache?
  try {
    const f = Bun.file(CACHE);
    if (await f.exists()) {
      const stat = await f.stat();
      if (Date.now() - stat.mtimeMs < CACHE_TTL_MS) {
        return normalize(await f.json());
      }
    }
  } catch { /* fall through */ }

  // Fetch upstream.
  try {
    const res = await fetch(UPSTREAM, { signal: AbortSignal.timeout(10000) });
    if (res.ok) {
      const data = await res.json();
      await Bun.write(CACHE, JSON.stringify(data));
      return normalize(data);
    }
  } catch { /* fall through */ }

  // Stale cache beats vendored.
  try {
    const f = Bun.file(CACHE);
    if (await f.exists()) return normalize(await f.json());
  } catch { /* fall through */ }

  return VENDORED;
}

function normalize(data: unknown): Fingerprint[] {
  if (!Array.isArray(data)) return VENDORED;
  return data
    .map((d: any) => ({
      service: d.service ?? "unknown",
      cnames: d.cname ?? d.cnames ?? [],
      fingerprints: d.fingerprint ?? d.fingerprints ?? [],
      vulnerable: d.status ? /vulnerable|edge case/i.test(d.status) : d.vulnerable !== false,
    }))
    .filter((f: Fingerprint) => f.cnames.length > 0);
}

/** crt.sh certificate-transparency subdomain enumeration. Passive. */
export async function enumerateSubdomains(domain: string): Promise<string[]> {
  try {
    const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return [];
    const rows = (await res.json()) as { name_value: string }[];
    const hosts = new Set<string>();
    for (const row of rows) {
      for (const name of row.name_value.split("\n")) {
        const h = name.trim().toLowerCase().replace(/^\*\./, "");
        if (h.endsWith(domain) && h !== domain) hosts.add(h);
      }
    }
    return [...hosts].sort();
  } catch {
    return [];
  }
}

function matchFingerprint(target: string, fps: Fingerprint[]): Fingerprint | null {
  for (const fp of fps) {
    if (!fp.vulnerable) continue;
    if (fp.cnames.some((c) => target.endsWith(c))) return fp;
  }
  return null;
}

/** Light-active: fetch the dangling target and look for the unclaimed-error body. */
async function verifyUnclaimed(host: string, fp: Fingerprint): Promise<boolean> {
  for (const scheme of ["https", "http"]) {
    try {
      const res = await fetch(`${scheme}://${host}`, {
        signal: AbortSignal.timeout(8000),
        redirect: "manual",
      });
      const body = await res.text();
      if (fp.fingerprints.some((f) => body.includes(f))) return true;
    } catch { /* try next scheme */ }
  }
  return false;
}

export async function checkTakeover(
  domain: string,
  scope: Scope,
  opts: { verify: boolean; subdomains?: string[] },
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const fps = await loadFingerprints();
  const hosts = opts.subdomains ?? (await enumerateSubdomains(domain));

  for (const host of hosts) {
    if (scope.isExcluded(host)) continue;
    const target = await cname(host);
    if (!target) continue;

    const fp = matchFingerprint(target, fps);
    if (!fp) continue;

    // A dangling pointer is most interesting when the host no longer resolves
    // to a live A record (service was torn down).
    const aRecs = await a(host);
    const dangling = aRecs.length === 0;

    let verified = false;
    let verifyNote = "";
    if (opts.verify) {
      const reason = scope.blockReason(host, "light-active");
      if (reason) {
        verifyNote = ` (verification skipped: ${reason})`;
      } else {
        verified = await verifyUnclaimed(host, fp);
        verifyNote = verified
          ? " Confirmed: unclaimed-service error body present."
          : " HTTP verification did not confirm an unclaimed error body.";
      }
    }

    findings.push({
      id: "takeover.candidate",
      domain,
      host,
      severity: verified ? "CRITICAL" : dangling ? "HIGH" : "MEDIUM",
      traffic: opts.verify ? "light-active" : "passive",
      provable: verified,
      title: `Possible subdomain takeover: ${host} → ${fp.service}`,
      detail:
        `${host} has a CNAME to ${target} (${fp.service}), a service with a known takeover ` +
        `fingerprint.${dangling ? " The host has no live A record, consistent with a torn-down resource." : ""}` +
        verifyNote +
        ` If the underlying ${fp.service} resource is unclaimed, an attacker can register it and serve ` +
        `content on ${host}, enabling phishing and (if cookies are scoped to the parent domain) cookie theft.`,
      evidence: `${host} CNAME ${target}`,
      remediation:
        `Either reclaim the ${fp.service} resource or delete the dangling CNAME for ${host}. ` +
        `Deprovision DNS records in the same motion as tearing down the resource they point at.`,
      reference: "can-i-take-over-xyz",
    });
  }

  return findings;
}
