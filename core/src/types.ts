// Shared domain types for sec-scan.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

export type ScanCategory =
  | "sast"
  | "sca"
  | "secrets"
  | "iac"
  | "container"
  | "sbom"
  | "dast";

/** Categories that perform active/network interaction and require authorization. */
export const ACTIVE_CATEGORIES: ScanCategory[] = ["dast"];

export interface Location {
  file?: string;
  startLine?: number;
  endLine?: number;
  uri?: string; // for dast/network findings
}

export interface Finding {
  id: string; // stable fingerprint
  ruleId: string;
  tool: string;
  category: ScanCategory;
  severity: Severity;
  title: string;
  message: string;
  location: Location;
  references?: string[];
  // validation metadata, filled by the agent harness
  validated?: boolean;
  falsePositive?: boolean;
  reachability?: "reachable" | "unreachable" | "unknown";
  remediation?: Remediation;
}

export interface Remediation {
  summary: string;
  diff?: string; // unified diff, human-reviewed before apply
  applied?: boolean;
}

export interface ScanResult {
  tool: string;
  category: ScanCategory;
  ok: boolean;
  skipped?: boolean;
  reason?: string; // why skipped (e.g. binary absent, not authorized)
  findings: Finding[];
  durationMs?: number; // wall-clock time this scanner took
}

export interface Delta {
  added: string[]; // fingerprints present now but not in the baseline
  resolved: string[]; // baseline fingerprints no longer found
}

export interface RunManifest {
  startedAt: string;
  finishedAt?: string;
  target: string;
  categories: ScanCategory[];
  harness: "claude-code" | "codex" | "none";
  toolVersions: Record<string, string>;
  durations?: Record<string, number>; // per-scanner wall-clock ms
  scopeRef?: string;
  delta?: Delta; // vs baseline, when a baseline was applied
}

export interface AuthorizationScope {
  authorizedBy: string;
  authorizedAt: string;
  note?: string;
  targets: string[]; // allow-list of hosts/urls/CIDRs for active checks
}
