// DAST adapter: Nuclei. ACTIVE/network — only reached after the engine's
// authorization-scope gate has passed (see core/src/engine.ts + scope.ts).

import type { Scanner } from "../../../core/src/engine.js";
import { fingerprint } from "../../../core/src/engine.js";
import type { Finding, ScanResult, Severity } from "../../../core/src/types.js";
import { detect, run } from "../exec.js";
import { activeLimits } from "../limits.js";

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

export const nuclei: Scanner = {
  tool: "nuclei",
  category: "dast",
  version: () => detect("nuclei", ["-version"]),
  async scan(target: string): Promise<ScanResult> {
    const v = await detect("nuclei", ["-version"]);
    if (!v) {
      return {
        tool: "nuclei",
        category: "dast",
        ok: false,
        skipped: true,
        reason: "nuclei not found on PATH (see https://github.com/projectdiscovery/nuclei).",
        findings: [],
      };
    }
    // -jsonl: one JSON object per line. Non-intrusive template set only.
    // Rate-limited and time-boxed for authorized, scoped engagements.
    const { rateLimit, timeoutMs } = activeLimits();
    const res = await run(
      "nuclei",
      ["-target", target, "-jsonl", "-silent", "-rate-limit", String(rateLimit), "-severity", "low,medium,high,critical"],
      { timeoutMs },
    );
    const findings: Finding[] = [];
    for (const line of res.stdout.split("\n")) {
      if (!line.trim()) continue;
      try {
        const r = JSON.parse(line) as {
          "template-id": string;
          info: { name: string; severity: string; description?: string; reference?: string[] };
          "matched-at": string;
        };
        findings.push({
          id: fingerprint(["nuclei", r["template-id"], r["matched-at"]]),
          ruleId: r["template-id"],
          tool: "nuclei",
          category: "dast",
          severity: mapSeverity(r.info.severity),
          title: r.info.name,
          message: r.info.description ?? "",
          location: { uri: r["matched-at"] },
          references: r.info.reference,
        });
      } catch {
        /* skip malformed line */
      }
    }
    return { tool: "nuclei", category: "dast", ok: true, findings };
  },
};
