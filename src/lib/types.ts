// Core types shared across mailrecon.

/** Traffic class of a check. Determines whether scope authorization is required. */
export type TrafficClass = "passive" | "light-active" | "active";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFO: 1,
};

export interface Finding {
  /** Stable machine id, e.g. "dmarc.multiple-records". */
  id: string;
  domain: string;
  /** Specific host the finding applies to (subdomain takeover etc). Defaults to domain. */
  host?: string;
  severity: Severity;
  traffic: TrafficClass;
  title: string;
  /** One-paragraph explanation of the issue and why it matters. */
  detail: string;
  /** Raw evidence: the record/value that proves it. */
  evidence?: string;
  /** Concrete remediation, ready to hand a client. */
  remediation?: string;
  /**
   * True when impact is demonstrable (e.g. a registrable rua domain you can
   * actually claim). Bounty programs pay for proven impact — this floats to top.
   */
  provable?: boolean;
  /** RFC / reference for the writeup. */
  reference?: string;
}

export interface DomainProfile {
  domain: string;
  /** Has MX records → receives mail → real spoofing target. */
  hasMx: boolean;
  /** SPF declares sending mechanisms (include/a/mx/ip4/ip6). */
  sends: boolean;
  findings: Finding[];
}

export interface ScopeConfig {
  engagement: string;
  /** Master kill switch for any non-passive traffic. */
  authorized: boolean;
  /** In-scope hosts/wildcards, e.g. ["*.example.com", "example.com"]. */
  inScope: string[];
  /** Hard excludes — dropped from output entirely, even passively. */
  outOfScope: string[];
}
