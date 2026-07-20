// Passive DNS + RDAP primitives. Everything here is passive: queries go to
// public resolvers (DoH) and the public RDAP system, never to the target.

const DOH = "https://dns.google/resolve";

type DnsType = "A" | "AAAA" | "TXT" | "MX" | "CNAME" | "NS" | "SOA";

interface DohAnswer {
  name: string;
  type: number;
  data: string;
}

const TYPE_NUM: Record<DnsType, number> = {
  A: 1,
  NS: 2,
  SOA: 6,
  AAAA: 28,
  CNAME: 5,
  MX: 15,
  TXT: 16,
};

async function doh(name: string, type: DnsType): Promise<DohAnswer[]> {
  const url = `${DOH}?name=${encodeURIComponent(name)}&type=${type}`;
  try {
    const res = await fetch(url, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return [];
    const json = (await res.json()) as { Answer?: DohAnswer[] };
    return (json.Answer ?? []).filter((a) => a.type === TYPE_NUM[type]);
  } catch {
    return [];
  }
}

/** TXT records, with the per-string quoting stripped and chunks joined. */
export async function txt(name: string): Promise<string[]> {
  const ans = await doh(name, "TXT");
  return ans.map((a) =>
    a.data
      .replace(/^"(.*)"$/, "$1")
      .replace(/" "/g, "")
      .replace(/\\"/g, '"'),
  );
}

export async function mx(name: string): Promise<string[]> {
  return (await doh(name, "MX")).map((a) => a.data);
}

export async function cname(name: string): Promise<string | null> {
  const ans = await doh(name, "CNAME");
  return ans[0]?.data.replace(/\.$/, "") ?? null;
}

export async function a(name: string): Promise<string[]> {
  return (await doh(name, "A")).map((a) => a.data);
}

export async function ns(name: string): Promise<string[]> {
  return (await doh(name, "NS")).map((a) => a.data);
}

export async function soa(name: string): Promise<string[]> {
  return (await doh(name, "SOA")).map((a) => a.data);
}

/** Registrable-domain reducer: strip a hostname down to its registrable apex. */
export function registrableDomain(host: string): string {
  const parts = host.toLowerCase().replace(/\.$/, "").split(".");
  if (parts.length <= 2) return parts.join(".");
  // Handle common two-label public suffixes (co.uk, com.au, co.nz, etc).
  const twoLabelTlds = new Set([
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au",
    "co.nz", "co.za", "com.br", "co.jp",
  ]);
  const lastTwo = parts.slice(-2).join(".");
  if (twoLabelTlds.has(lastTwo)) return parts.slice(-3).join(".");
  return parts.slice(-2).join(".");
}

export interface RegistrableStatus {
  registered: boolean;
  /** True when we got a definitive answer (vs network failure / unsupported TLD). */
  confident: boolean;
  source: "rdap" | "dns-inference";
  raw?: string;
}

/**
 * Confirm whether a domain is registered. DNS inference first (NS/SOA presence),
 * then RDAP to confirm — RDAP 404 is a strong "unregistered" signal, which is
 * the crown-jewel finding (a claimable rua/CNAME destination).
 */
export async function isRegistered(domain: string): Promise<RegistrableStatus> {
  const apex = registrableDomain(domain);

  // RDAP is authoritative when available.
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(apex)}`, {
      headers: { accept: "application/rdap+json" },
      signal: AbortSignal.timeout(8000),
      redirect: "follow",
    });
    if (res.status === 404) {
      return { registered: false, confident: true, source: "rdap", raw: "RDAP 404" };
    }
    if (res.ok) {
      return { registered: true, confident: true, source: "rdap", raw: "RDAP 200" };
    }
    // 429/5xx/unsupported TLD bootstrap → fall through to DNS inference.
  } catch {
    // network error → fall through
  }

  // DNS inference fallback: a registered domain almost always has NS + SOA.
  const [nsRecs, soaRecs] = await Promise.all([ns(apex), soa(apex)]);
  const looksRegistered = nsRecs.length > 0 || soaRecs.length > 0;
  return {
    registered: looksRegistered,
    confident: false,
    source: "dns-inference",
    raw: `NS=${nsRecs.length} SOA=${soaRecs.length}`,
  };
}
