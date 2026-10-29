// Secrets adapter: Gitleaks. Static, local.

import type { Scanner } from "../../../core/src/engine.js";
import { fingerprint } from "../../../core/src/engine.js";
import type { Finding, ScanResult } from "../../../core/src/types.js";
import { detect, run } from "../exec.js";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync, rmSync } from "node:fs";

export const gitleaks: Scanner = {
  tool: "gitleaks",
  category: "secrets",
  version: () => detect("gitleaks", ["version"]),
  async scan(target: string): Promise<ScanResult> {
    const v = await detect("gitleaks", ["version"]);
    if (!v) {
      return {
        tool: "gitleaks",
        category: "secrets",
        ok: false,
        skipped: true,
        reason: "gitleaks not found on PATH (see https://github.com/gitleaks/gitleaks).",
        findings: [],
      };
    }
    const out = join(tmpdir(), `gitleaks-${process.pid}-${Date.now()}.json`);
    await run("gitleaks", ["detect", "--no-git", "--report-format", "json", "--report-path", out, "--source", target]);
    const findings: Finding[] = [];
    try {
      const parsed = JSON.parse(readFileSync(out, "utf8")) as Array<{
        RuleID: string;
        Description: string;
        File: string;
        StartLine: number;
        EndLine: number;
      }>;
      for (const r of parsed) {
        findings.push({
          id: fingerprint(["gitleaks", r.RuleID, r.File, r.StartLine]),
          ruleId: r.RuleID,
          tool: "gitleaks",
          category: "secrets",
          severity: "high",
          title: `Potential secret: ${r.RuleID}`,
          message: r.Description,
          location: { file: r.File, startLine: r.StartLine, endLine: r.EndLine },
        });
      }
    } catch {
      // empty/missing report means no findings
    } finally {
      try {
        rmSync(out, { force: true });
      } catch {
        /* ignore */
      }
    }
    return { tool: "gitleaks", category: "secrets", ok: true, findings };
  },
};
