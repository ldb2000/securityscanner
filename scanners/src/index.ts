// Scanner registry. Add new adapters here.

import type { Scanner } from "../../core/src/engine.js";
import { semgrep } from "./adapters/semgrep.js";
import { trivy } from "./adapters/trivy.js";
import { grype } from "./adapters/grype.js";
import { gitleaks } from "./adapters/gitleaks.js";
import { trufflehog } from "./adapters/trufflehog.js";
import { checkov } from "./adapters/checkov.js";
import { syft } from "./adapters/syft.js";
import { nuclei } from "./adapters/nuclei.js";
import { zap } from "./adapters/zap.js";

export const ALL_SCANNERS: Scanner[] = [
  semgrep, // sast
  trivy, // sca
  grype, // sca
  gitleaks, // secrets
  trufflehog, // secrets
  checkov, // iac
  syft, // sbom
  nuclei, // dast (gated)
  zap, // dast (gated)
];

export function scannersFor(categories: string[]): Scanner[] {
  return ALL_SCANNERS.filter((s) => categories.includes(s.category));
}

export { semgrep, trivy, grype, gitleaks, trufflehog, checkov, syft, nuclei, zap };
