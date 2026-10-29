// SCA / dependency adapter: Trivy filesystem scan. Static, local.

import type { Scanner } from "../../../core/src/engine.js";
import { fingerprint } from "../../../core/src/engine.js";
import type { Finding, ScanResult, Severity } from "../../../core/src/types.js";
import { detect, run } from "../exec.js";

function mapSeverity(s: string): Severity {
  switch ((s || "").toUpperCase()) {
    case "CRITICAL":
      return "critical";
    case "HIGH":
      return "high";
    case "MEDIUM":
      return "medium";
    case "LOW":
      return "low";
    default:
      return "info";
  }
}

export const trivy: Scanner = {
  tool: "trivy",
  category: "sca",
  version: () => detect("trivy"),
  async scan(target: string): Promise<ScanResult> {
    const v = await detect("trivy");
    if (!v) {
      return {
        tool: "trivy",
        category: "sca",
        ok: false,
        skipped: true,
        reason: "trivy not found on PATH (see https://trivy.dev).",
        findings: [],
      };
    }
    const res = await run("trivy", ["fs", "--quiet", "--format", "json", "--scanners", "vuln", target]);
    const findings: Finding[] = [];
    try {
      const parsed = JSON.parse(res.stdout) as {
        Results?: Array<{
          Target: string;
          Vulnerabilities?: Array<{
            VulnerabilityID: string;
            PkgName: string;
            Severity: string;
            Title?: string;
            Description?: string;
            PrimaryURL?: string;
          }>;
        }>;
      };
      for (const r of parsed.Results ?? []) {
        for (const vuln of r.Vulnerabilities ?? []) {
          findings.push({
            id: fingerprint(["trivy", vuln.VulnerabilityID, vuln.PkgName, r.Target]),
            ruleId: vuln.VulnerabilityID,
            tool: "trivy",
            category: "sca",
            severity: mapSeverity(vuln.Severity),
            title: vuln.Title ?? `${vuln.VulnerabilityID} in ${vuln.PkgName}`,
            message: vuln.Description ?? "",
            location: { file: r.Target },
            references: vuln.PrimaryURL ? [vuln.PrimaryURL] : undefined,
          });
        }
      }
    } catch {
      return { tool: "trivy", category: "sca", ok: false, reason: "Failed to parse trivy JSON.", findings: [] };
    }
    return { tool: "trivy", category: "sca", ok: true, findings };
  },
};
