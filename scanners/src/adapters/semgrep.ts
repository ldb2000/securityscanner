// SAST adapter: Semgrep CE. Static, local, no authorization gate.
// Uses Semgrep's native SARIF output and the unified SARIF ingestion path.

import type { Scanner } from "../../../core/src/engine.js";
import type { ScanResult } from "../../../core/src/types.js";
import { ingestSarif } from "../../../core/src/sarif-ingest.js";
import { detect, run } from "../exec.js";

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
        reason: "semgrep not found on PATH (install: scripts/install-tools.sh semgrep).",
        findings: [],
      };
    }
    const res = await run("semgrep", ["scan", "--sarif", "--quiet", "--config", "auto", target]);
    try {
      const findings = ingestSarif(res.stdout, { tool: "semgrep", category: "sast" });
      return { tool: "semgrep", category: "sast", ok: true, findings };
    } catch {
      return { tool: "semgrep", category: "sast", ok: false, reason: "Failed to parse semgrep SARIF.", findings: [] };
    }
  },
};
