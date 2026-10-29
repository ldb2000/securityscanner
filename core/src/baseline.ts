// Baseline & suppressions: hide known/accepted findings from reports.
//
// A baseline file is versionable JSON:
// {
//   "suppressions": [
//     { "fingerprint": "ab12…", "reason": "accepted risk", "expires": "2026-12-31" }
//   ]
// }
// A finding is suppressed when a suppression matches its fingerprint (id) and is
// not expired. Expired suppressions are ignored, so the finding reappears.

import { readFileSync } from "node:fs";
import type { Finding } from "./types.js";

export interface Suppression {
  fingerprint: string;
  reason?: string;
  expires?: string; // ISO date/datetime; absent = never expires
}

export interface Baseline {
  suppressions: Suppression[];
}

export class BaselineError extends Error {}

export function loadBaseline(path: string): Baseline {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    throw new BaselineError(`Cannot read baseline file: ${path}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new BaselineError(`Baseline file is not valid JSON: ${path}`);
  }
  const b = parsed as Partial<Baseline>;
  if (!Array.isArray(b.suppressions)) {
    throw new BaselineError("Baseline must contain a `suppressions` array.");
  }
  for (const s of b.suppressions) {
    if (!s || typeof s.fingerprint !== "string" || !s.fingerprint) {
      throw new BaselineError("Each suppression needs a non-empty `fingerprint`.");
    }
  }
  return { suppressions: b.suppressions };
}

function isExpired(s: Suppression, now: Date): boolean {
  if (!s.expires) return false;
  const t = Date.parse(s.expires);
  if (Number.isNaN(t)) return false; // unparseable = treat as non-expiring
  return t <= now.getTime();
}

/** Set of fingerprints that are actively suppressed right now. */
export function activeSuppressions(baseline: Baseline, now = new Date()): Set<string> {
  const set = new Set<string>();
  for (const s of baseline.suppressions) {
    if (!isExpired(s, now)) set.add(s.fingerprint);
  }
  return set;
}

export interface ApplyResult {
  kept: Finding[];
  suppressed: Finding[];
}

/** Partition findings into kept vs suppressed by the (non-expired) baseline. */
export function applyBaseline(findings: Finding[], baseline: Baseline, now = new Date()): ApplyResult {
  const active = activeSuppressions(baseline, now);
  const kept: Finding[] = [];
  const suppressed: Finding[] = [];
  for (const f of findings) (active.has(f.id) ? suppressed : kept).push(f);
  return { kept, suppressed };
}

/** Build a baseline that suppresses every given finding (for `baseline` command). */
export function baselineFromFindings(findings: Finding[], reason = "baselined"): Baseline {
  return {
    suppressions: findings.map((f) => ({ fingerprint: f.id, reason })),
  };
}
