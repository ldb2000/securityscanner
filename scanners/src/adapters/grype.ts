// SCA adapter: Grype (Anchore). Static, local.

import type { Scanner } from "../../../core/src/engine.js";
import { fingerprint } from "../../../core/src/engine.js";
import type { Finding, ScanResult, Severity } from "../../../core/src/types.js";
import { detect, run } from "../exec.js";

function mapSeverity(s: string): Severity {
  switch ((s || "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

export const grype: Scanner = {
  tool: "grype",
  category: "sca",
  version: () => detect("grype", ["version"]),
  async scan(target: string): Promise<ScanResult> {
    const v = await detect("grype", ["version"]);
    if (!v) {
      return {
        tool: "grype",
        category: "sca",
        ok: false,
        skipped: true,
        reason: "grype not found on PATH (install: scripts/install-tools.sh grype).",
        findings: [],
      };
    }
    const res = await run("grype", [`dir:${target}`, "-o", "json", "-q"]);
    const findings: Finding[] = [];
    try {
      const parsed = JSON.parse(res.stdout) as {
        matches?: Array<{
          vulnerability: { id: string; severity: string; dataSource?: string; description?: string };
          artifact: { name: string; version?: string };
        }>;
      };
      for (const m of parsed.matches ?? []) {
        findings.push({
          id: fingerprint(["grype", m.vulnerability.id, m.artifact.name, m.artifact.version]),
          ruleId: m.vulnerability.id,
          tool: "grype",
          category: "sca",
          severity: mapSeverity(m.vulnerability.severity),
          title: `${m.vulnerability.id} in ${m.artifact.name}${m.artifact.version ? `@${m.artifact.version}` : ""}`,
          message: m.vulnerability.description ?? "",
          location: { file: m.artifact.name },
          references: m.vulnerability.dataSource ? [m.vulnerability.dataSource] : undefined,
        });
      }
    } catch {
      return { tool: "grype", category: "sca", ok: false, reason: "Failed to parse grype JSON.", findings: [] };
    }
    return { tool: "grype", category: "sca", ok: true, findings };
  },
};
