// SBOM adapter: Syft (Anchore). Emits a CycloneDX SBOM and an informational
// finding summarizing it. Static, local.

import { writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Scanner } from "../../../core/src/engine.js";
import { fingerprint } from "../../../core/src/engine.js";
import type { Finding, ScanResult } from "../../../core/src/types.js";
import { detect, run } from "../exec.js";

/** Where the last SBOM was written (for the reporter / CLI to surface). */
export function sbomPathFor(target: string): string {
  return join(tmpdir(), `sec-scan-sbom-${fingerprint([target, Date.now()])}.cdx.json`);
}

export const syft: Scanner = {
  tool: "syft",
  category: "sbom",
  version: () => detect("syft", ["version"]),
  async scan(target: string): Promise<ScanResult> {
    const v = await detect("syft", ["version"]);
    if (!v) {
      return {
        tool: "syft",
        category: "sbom",
        ok: false,
        skipped: true,
        reason: "syft not found on PATH (install: scripts/install-tools.sh syft).",
        findings: [],
      };
    }
    const res = await run("syft", [`dir:${target}`, "-o", "cyclonedx-json", "-q"]);
    let componentCount = 0;
    let sbomPath: string | undefined;
    try {
      const sbom = JSON.parse(res.stdout) as { components?: unknown[]; bomFormat?: string };
      if (sbom.bomFormat !== "CycloneDX") {
        return { tool: "syft", category: "sbom", ok: false, reason: "Syft output is not CycloneDX JSON.", findings: [] };
      }
      componentCount = Array.isArray(sbom.components) ? sbom.components.length : 0;
      sbomPath = sbomPathFor(target);
      writeFileSync(sbomPath, res.stdout);
    } catch {
      return { tool: "syft", category: "sbom", ok: false, reason: "Failed to parse syft SBOM JSON.", findings: [] };
    }
    const finding: Finding = {
      id: fingerprint(["syft", "sbom", target]),
      ruleId: "sbom.generated",
      tool: "syft",
      category: "sbom",
      severity: "info",
      title: `SBOM generated: ${componentCount} components (CycloneDX)`,
      message: `CycloneDX SBOM written to ${sbomPath}`,
      location: { file: sbomPath },
    };
    return { tool: "syft", category: "sbom", ok: true, findings: [finding] };
  },
};
