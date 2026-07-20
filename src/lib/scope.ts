// Scope / authorization engine. The thing that keeps mailrecon bounty- and
// client-safe: it gates every non-passive check behind an explicit, logged
// authorization file and enforces in/out-of-scope rules on every host.

import type { ScopeConfig, TrafficClass } from "./types.ts";

/** Match a host against a scope pattern. Supports leading "*." wildcards. */
export function hostMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, "");
  const p = pattern.toLowerCase().replace(/\.$/, "");
  if (p.startsWith("*.")) {
    const base = p.slice(2);
    return h === base || h.endsWith("." + base);
  }
  return h === p;
}

export class Scope {
  constructor(private readonly cfg: ScopeConfig | null) {}

  /** No scope file → passive-only mode. */
  static passiveOnly(): Scope {
    return new Scope(null);
  }

  static async fromFile(path: string): Promise<Scope> {
    const raw = await Bun.file(path).json();
    const cfg: ScopeConfig = {
      engagement: raw.engagement ?? "unnamed",
      authorized: raw.authorized === true,
      inScope: raw.inScope ?? raw.in_scope ?? [],
      outOfScope: raw.outOfScope ?? raw.out_of_scope ?? [],
    };
    return new Scope(cfg);
  }

  get engagement(): string {
    return this.cfg?.engagement ?? "(passive, no scope file)";
  }

  /** Out-of-scope hosts are excluded from output entirely. */
  isExcluded(host: string): boolean {
    if (!this.cfg) return false;
    return this.cfg.outOfScope.some((p) => hostMatches(host, p));
  }

  /**
   * Decide whether a check of the given traffic class may run against host.
   * Returns a reason string when blocked (for logging), or null when allowed.
   */
  blockReason(host: string, traffic: TrafficClass): string | null {
    if (this.isExcluded(host)) return `${host} is explicitly out of scope`;
    if (traffic === "passive") return null; // passive is always allowed

    if (!this.cfg) {
      return `no --scope file: ${traffic} checks disabled (passive-only run)`;
    }
    if (!this.cfg.authorized) {
      return `scope file present but authorized=false: ${traffic} checks disabled`;
    }
    const inScope = this.cfg.inScope.some((p) => hostMatches(host, p));
    if (!inScope) return `${host} not in scope: ${traffic} check skipped`;
    return null;
  }

  allows(host: string, traffic: TrafficClass): boolean {
    return this.blockReason(host, traffic) === null;
  }
}
