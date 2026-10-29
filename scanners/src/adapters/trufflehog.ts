// Secrets adapter: TruffleHog. Static, local. Line-delimited JSON output.

import type { Scanner } from "../../../core/src/engine.js";
import { fingerprint } from "../../../core/src/engine.js";
import type { Finding, ScanResult } from "../../../core/src/types.js";
import { detect, run } from "../exec.js";

interface TrufflehogResult {
  DetectorName?: string;
  Verified?: boolean;
  SourceMetadata?: { Data?: { Filesystem?: { file?: string; line?: number } } };
}

export const trufflehog: Scanner = {
  tool: "trufflehog",
  category: "secrets",
  version: () => detect("trufflehog", ["--version"]),
  async scan(target: string): Promise<ScanResult> {
    const v = await detect("trufflehog", ["--version"]);
    if (!v) {
      return {
        tool: "trufflehog",
        category: "secrets",
        ok: false,
        skipped: true,
        reason: "trufflehog not found on PATH (install: scripts/install-tools.sh trufflehog).",
        findings: [],
      };
    }
    const res = await run("trufflehog", ["filesystem", target, "--json", "--no-update"]);
    const findings: Finding[] = [];
    for (const line of res.stdout.split("\n")) {
      if (!line.trim()) continue;
      try {
        const r = JSON.parse(line) as TrufflehogResult;
        if (!r.DetectorName) continue; // skip log/non-finding lines
        const fs = r.SourceMetadata?.Data?.Filesystem;
        findings.push({
          id: fingerprint(["trufflehog", r.DetectorName, fs?.file, fs?.line]),
          ruleId: r.DetectorName,
          tool: "trufflehog",
          category: "secrets",
          severity: r.Verified ? "critical" : "high",
          title: `Potential secret: ${r.DetectorName}${r.Verified ? " (verified)" : ""}`,
          message: r.Verified ? "Verified live credential detected." : "Unverified potential credential.",
          location: { file: fs?.file, startLine: fs?.line },
        });
      } catch {
        /* skip malformed line */
      }
    }
    return { tool: "trufflehog", category: "secrets", ok: true, findings };
  },
};
