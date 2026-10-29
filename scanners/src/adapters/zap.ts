// DAST adapter: OWASP ZAP baseline (passive) scan. ACTIVE/network — only
// reached after the engine's authorization-scope gate has passed
// (see core/src/engine.ts + scope.ts). Baseline mode is passive by default.

import { readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Scanner } from "../../../core/src/engine.js";
import { fingerprint } from "../../../core/src/engine.js";
import type { Finding, ScanResult, Severity } from "../../../core/src/types.js";
import { detect, run } from "../exec.js";

// ZAP riskcode: 3=High, 2=Medium, 1=Low, 0=Informational.
function mapRisk(code: string): Severity {
  switch (code) {
    case "3":
      return "high";
    case "2":
      return "medium";
    case "1":
      return "low";
    default:
      return "info";
  }
}

/** Prefer zap-baseline.py; fall back to zap.sh with the baseline automation. */
async function resolveBin(): Promise<{ bin: string; baseArgs: string[] } | null> {
  if (await detect("zap-baseline.py", ["--help"])) return { bin: "zap-baseline.py", baseArgs: [] };
  if (await detect("zap.sh", ["-version"])) return { bin: "zap.sh", baseArgs: ["-cmd"] };
  return null;
}

export const zap: Scanner = {
  tool: "zap",
  category: "dast",
  version: async () => {
    const r = await resolveBin();
    return r ? r.bin : null;
  },
  async scan(target: string): Promise<ScanResult> {
    const resolved = await resolveBin();
    if (!resolved) {
      return {
        tool: "zap",
        category: "dast",
        ok: false,
        skipped: true,
        reason: "OWASP ZAP not found (zap-baseline.py / zap.sh). install: scripts/install-tools.sh zap.",
        findings: [],
      };
    }
    const out = join(tmpdir(), `sec-scan-zap-${process.pid}-${Date.now()}.json`);
    // -J writes a JSON report; baseline is passive (no active attack) by default.
    await run(resolved.bin, [...resolved.baseArgs, "-t", target, "-J", out]);
    const findings: Finding[] = [];
    try {
      const report = JSON.parse(readFileSync(out, "utf8")) as {
        site?: Array<{ alerts?: Array<{ alert: string; pluginid?: string; riskcode: string; desc?: string; instances?: Array<{ uri?: string }> }> }>;
      };
      for (const site of report.site ?? []) {
        for (const a of site.alerts ?? []) {
          const uri = a.instances?.[0]?.uri ?? target;
          findings.push({
            id: fingerprint(["zap", a.pluginid ?? a.alert, uri]),
            ruleId: a.pluginid ?? a.alert,
            tool: "zap",
            category: "dast",
            severity: mapRisk(a.riskcode),
            title: a.alert,
            message: (a.desc ?? "").replace(/<[^>]+>/g, "").trim(),
            location: { uri },
          });
        }
      }
    } catch {
      return { tool: "zap", category: "dast", ok: false, reason: "Failed to read ZAP JSON report.", findings: [] };
    } finally {
      try {
        rmSync(out, { force: true });
      } catch {
        /* ignore */
      }
    }
    return { tool: "zap", category: "dast", ok: true, findings };
  },
};
