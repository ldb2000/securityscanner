// Unified SARIF 2.1.0 ingestion: convert a scanner's native SARIF output into
// the internal Finding model. Preferred over ad-hoc JSON parsing whenever a
// tool can emit SARIF, so all adapters share one normalization path.

import { fingerprint } from "./engine.js";
import type { Finding, ScanCategory, Severity } from "./types.js";

interface SarifRegion {
  startLine?: number;
  endLine?: number;
}
interface SarifLocation {
  physicalLocation?: {
    artifactLocation?: { uri?: string };
    region?: SarifRegion;
  };
}
interface SarifResult {
  ruleId?: string;
  level?: string;
  message?: { text?: string };
  locations?: SarifLocation[];
  properties?: { severity?: string };
}
interface SarifRun {
  tool?: { driver?: { name?: string; rules?: Array<{ id?: string; name?: string; helpUri?: string }> } };
  results?: SarifResult[];
}
interface SarifLog {
  runs?: SarifRun[];
}

/** SARIF `level` -> internal severity. `properties.severity` wins when present. */
function mapLevel(result: SarifResult): Severity {
  const explicit = (result.properties?.severity ?? "").toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(explicit)) return explicit as Severity;
  switch ((result.level ?? "").toLowerCase()) {
    case "error":
      return "high";
    case "warning":
      return "medium";
    case "note":
      return "low";
    case "none":
      return "info";
    default:
      return "medium";
  }
}

export interface IngestOptions {
  tool: string; // overrides the SARIF driver name when set
  category: ScanCategory;
}

/** Parse a SARIF document (string or object) into Findings. */
export function ingestSarif(sarif: string | SarifLog, opts: IngestOptions): Finding[] {
  let log: SarifLog;
  try {
    log = typeof sarif === "string" ? (JSON.parse(sarif) as SarifLog) : sarif;
  } catch {
    return [];
  }
  const findings: Finding[] = [];
  for (const run of log.runs ?? []) {
    const tool = opts.tool || run.tool?.driver?.name || "sarif";
    const ruleUris = new Map<string, string>();
    for (const r of run.tool?.driver?.rules ?? []) {
      if (r.id && r.helpUri) ruleUris.set(r.id, r.helpUri);
    }
    for (const res of run.results ?? []) {
      const loc = res.locations?.[0]?.physicalLocation;
      const file = loc?.artifactLocation?.uri;
      const startLine = loc?.region?.startLine;
      const ruleId = res.ruleId ?? "unknown";
      const helpUri = ruleUris.get(ruleId);
      findings.push({
        id: fingerprint([tool, ruleId, file, startLine]),
        ruleId,
        tool,
        category: opts.category,
        severity: mapLevel(res),
        title: ruleId,
        message: res.message?.text ?? "",
        location: { file, startLine, endLine: loc?.region?.endLine },
        references: helpUri ? [helpUri] : undefined,
      });
    }
  }
  return findings;
}
