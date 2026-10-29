// Orchestration engine: identify -> validate -> remediate.

import { createHash } from "node:crypto";
import type {
  AuthorizationScope,
  Finding,
  RunManifest,
  ScanCategory,
  ScanResult,
  Severity,
} from "./types.js";
import { SEVERITY_ORDER, ACTIVE_CATEGORIES } from "./types.js";
import { assertInScope } from "./scope.js";
import { audit } from "./audit.js";

export interface Scanner {
  readonly tool: string;
  readonly category: ScanCategory;
  version(): Promise<string | null>; // null when binary absent
  scan(target: string): Promise<ScanResult>;
}

export interface Harness {
  readonly name: "claude-code" | "codex" | "none";
  /** Triage findings as data: mark false positives, reachability. */
  validate(findings: Finding[]): Promise<Finding[]>;
  /** Propose remediations (diffs) for validated findings. */
  remediate(findings: Finding[]): Promise<Finding[]>;
}

export interface IdentifyOptions {
  target: string;
  categories: ScanCategory[];
  scanners: Scanner[];
  scope?: AuthorizationScope;
}

export function fingerprint(parts: (string | number | undefined)[]): string {
  return createHash("sha256").update(parts.filter(Boolean).join("|")).digest("hex").slice(0, 16);
}

export async function identify(opts: IdentifyOptions): Promise<ScanResult[]> {
  const chosen = opts.scanners.filter((s) => opts.categories.includes(s.category));
  const results: ScanResult[] = [];
  for (const scanner of chosen) {
    // Gate active categories behind authorization scope.
    if (ACTIVE_CATEGORIES.includes(scanner.category)) {
      if (!opts.scope) {
        results.push({
          tool: scanner.tool,
          category: scanner.category,
          ok: false,
          skipped: true,
          reason: "Active scan requires an authorization scope (sec-scan scope). Skipped.",
          findings: [],
        });
        continue;
      }
      try {
        assertInScope(opts.scope, opts.target);
      } catch (e) {
        results.push({
          tool: scanner.tool,
          category: scanner.category,
          ok: false,
          skipped: true,
          reason: (e as Error).message,
          findings: [],
        });
        continue;
      }
      // Scope passed: record the active scan before any network interaction.
      audit({
        action: "active-scan",
        target: opts.target,
        detail: `${scanner.tool}/${scanner.category}`,
        authorizedBy: opts.scope.authorizedBy,
        scopeRef: opts.scope.authorizedAt,
      });
    }
    results.push(await scanner.scan(opts.target));
  }
  return results;
}

/** Merge, dedupe by fingerprint, keep the highest severity per fingerprint. */
export function mergeFindings(results: ScanResult[]): Finding[] {
  const byId = new Map<string, Finding>();
  for (const r of results) {
    for (const f of r.findings) {
      const existing = byId.get(f.id);
      if (!existing || severityRank(f.severity) < severityRank(existing.severity)) {
        byId.set(f.id, f);
      }
    }
  }
  return [...byId.values()].sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}

export function severityRank(s: Severity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/** Highest severity among non-false-positive findings, or null. */
export function topSeverity(findings: Finding[]): Severity | null {
  const live = findings.filter((f) => !f.falsePositive);
  if (live.length === 0) return null;
  return live.reduce((top, f) => (severityRank(f.severity) < severityRank(top) ? f.severity : top), "info" as Severity);
}

export function newManifest(target: string, categories: ScanCategory[], harness: Harness): RunManifest {
  return {
    startedAt: new Date().toISOString(),
    target,
    categories,
    harness: harness.name,
    toolVersions: {},
  };
}

/** Collect real version strings for the scanners in the selected categories. */
export async function collectToolVersions(
  scanners: Scanner[],
  categories: ScanCategory[],
): Promise<Record<string, string>> {
  const picked = scanners.filter((s) => categories.includes(s.category));
  const out: Record<string, string> = {};
  await Promise.all(
    picked.map(async (s) => {
      const v = await s.version();
      out[s.tool] = v ?? "absent";
    }),
  );
  return out;
}
