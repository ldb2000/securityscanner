// SAST adapter: Semgrep CE. Static, local, no authorization gate.

import type { Scanner } from "../../../core/src/engine.js";
import { fingerprint } from "../../../core/src/engine.js";
import type { Finding, ScanResult, Severity } from "../../../core/src/types.js";
import { detect, run } from "../exec.js";

function mapSeverity(s: string): Severity {
  switch ((s || "").toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    case "INFO":
      return "info";
    default:
      return "low";
  }
}

export const semgrep: Scanner = {
  tool: "semgrep",
  category: "sast",
  version: () => detect("semgrep"),
  async scan(target: string): Promise<ScanResult> {
    const v = await detect("semgrep");
    if (!v) {
      return {
        tool: "semgrep",
        category: "sast",
        ok: false,
        skipped: true,
        reason: "semgrep not found on PATH (install: pip install semgrep).",
        findings: [],
      };
    }
    const res = await run("semgrep", ["scan", "--json", "--quiet", "--config", "auto", target]);
    const findings: Finding[] = [];
    try {
      const parsed = JSON.parse(res.stdout) as {
        results?: Array<{
          check_id: string;
          path: string;
          start: { line: number };
          end: { line: number };
          extra: { severity: string; message: string; metadata?: { references?: string[] } };
        }>;
      };
      for (const r of parsed.results ?? []) {
        findings.push({
          id: fingerprint(["semgrep", r.check_id, r.path, r.start?.line]),
          ruleId: r.check_id,
          tool: "semgrep",
          category: "sast",
          severity: mapSeverity(r.extra.severity),
          title: r.check_id,
          message: r.extra.message,
          location: { file: r.path, startLine: r.start?.line, endLine: r.end?.line },
          references: r.extra.metadata?.references,
        });
      }
    } catch {
      return { tool: "semgrep", category: "sast", ok: false, reason: "Failed to parse semgrep JSON.", findings: [] };
    }
    return { tool: "semgrep", category: "sast", ok: true, findings };
  },
};
