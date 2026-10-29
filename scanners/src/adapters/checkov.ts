// IaC adapter: Checkov (Bridgecrew/Prisma). Static, local.

import type { Scanner } from "../../../core/src/engine.js";
import { fingerprint } from "../../../core/src/engine.js";
import type { Finding, ScanResult, Severity } from "../../../core/src/types.js";
import { detect, run } from "../exec.js";

function mapSeverity(s: string | undefined): Severity {
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
      return "medium"; // Checkov CE often omits severity; treat failed checks as medium
  }
}

interface CheckovCheck {
  check_id: string;
  check_name: string;
  file_path: string;
  file_line_range?: [number, number];
  severity?: string;
  guideline?: string;
}

export const checkov: Scanner = {
  tool: "checkov",
  category: "iac",
  version: () => detect("checkov", ["--version"]),
  async scan(target: string): Promise<ScanResult> {
    const v = await detect("checkov", ["--version"]);
    if (!v) {
      return {
        tool: "checkov",
        category: "iac",
        ok: false,
        skipped: true,
        reason: "checkov not found on PATH (install: scripts/install-tools.sh checkov).",
        findings: [],
      };
    }
    const res = await run("checkov", ["-d", target, "-o", "json", "--compact", "--quiet"]);
    const findings: Finding[] = [];
    try {
      // Checkov emits a single object, or an array of framework result objects.
      const raw = JSON.parse(res.stdout) as unknown;
      const blocks = Array.isArray(raw) ? raw : [raw];
      for (const block of blocks as Array<{ results?: { failed_checks?: CheckovCheck[] } }>) {
        for (const c of block.results?.failed_checks ?? []) {
          findings.push({
            id: fingerprint(["checkov", c.check_id, c.file_path, c.file_line_range?.[0]]),
            ruleId: c.check_id,
            tool: "checkov",
            category: "iac",
            severity: mapSeverity(c.severity),
            title: c.check_name,
            message: c.check_name,
            location: {
              file: c.file_path,
              startLine: c.file_line_range?.[0],
              endLine: c.file_line_range?.[1],
            },
            references: c.guideline ? [c.guideline] : undefined,
          });
        }
      }
    } catch {
      return { tool: "checkov", category: "iac", ok: false, reason: "Failed to parse checkov JSON.", findings: [] };
    }
    return { tool: "checkov", category: "iac", ok: true, findings };
  },
};
