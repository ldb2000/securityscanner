// Append-only audit log for sensitive operations: active (DAST) scans and
// applied remediations. Supports the defensive-use requirements in SPEC.md §5.

import { appendFileSync } from "node:fs";

export interface AuditEntry {
  at: string;
  action: "active-scan" | "fix-apply";
  target: string;
  detail: string;
  authorizedBy?: string;
  scopeRef?: string;
}

const DEFAULT_LOG = process.env.SEC_SCAN_AUDIT_LOG ?? ".sec-scan-audit.log";

export function audit(entry: Omit<AuditEntry, "at">, logPath = DEFAULT_LOG): void {
  const line = JSON.stringify({ at: new Date().toISOString(), ...entry });
  try {
    appendFileSync(logPath, line + "\n");
  } catch {
    // Never fail a run because the audit sink is unwritable; surface to stderr.
    process.stderr.write(`audit: could not write to ${logPath}\n`);
  }
}
