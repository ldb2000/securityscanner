// Reporters: SARIF 2.1.0 (canonical), JSON, and Markdown.

import type { Finding, RunManifest } from "../../core/src/types.js";

const SARIF_LEVEL: Record<string, string> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

export function toSarif(findings: Finding[], manifest: RunManifest): string {
  const byTool = new Map<string, Finding[]>();
  for (const f of findings) {
    if (!byTool.has(f.tool)) byTool.set(f.tool, []);
    byTool.get(f.tool)!.push(f);
  }
  const runs = [...byTool.entries()].map(([tool, fs]) => ({
    tool: { driver: { name: tool, rules: [] as unknown[] } },
    results: fs
      .filter((f) => !f.falsePositive)
      .map((f) => ({
        ruleId: f.ruleId,
        level: SARIF_LEVEL[f.severity] ?? "note",
        message: { text: f.message || f.title },
        properties: { category: f.category, severity: f.severity, reachability: f.reachability },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: f.location.file ?? f.location.uri ?? "" },
              region: f.location.startLine
                ? { startLine: f.location.startLine, endLine: f.location.endLine ?? f.location.startLine }
                : undefined,
            },
          },
        ],
      })),
  }));
  return JSON.stringify(
    { $schema: "https://json.schemastore.org/sarif-2.1.0.json", version: "2.1.0", properties: { manifest }, runs },
    null,
    2,
  );
}

export function toJson(findings: Finding[], manifest: RunManifest): string {
  return JSON.stringify({ manifest, findings }, null, 2);
}

export function toMarkdown(findings: Finding[], manifest: RunManifest): string {
  const live = findings.filter((f) => !f.falsePositive);
  const lines: string[] = [];
  lines.push(`# sec-scan report`);
  lines.push("");
  lines.push(`- **Target:** \`${manifest.target}\``);
  lines.push(`- **Harness:** ${manifest.harness}`);
  lines.push(`- **Categories:** ${manifest.categories.join(", ")}`);
  if (manifest.scopeRef) lines.push(`- **Authorization scope:** ${manifest.scopeRef}`);
  lines.push(`- **Findings:** ${live.length} (after false-positive filtering)`);
  lines.push("");
  if (live.length === 0) {
    lines.push("No findings. ✅");
    return lines.join("\n");
  }
  lines.push("| Severity | Tool | Rule | Location | Title |");
  lines.push("|---|---|---|---|---|");
  for (const f of live) {
    const loc = f.location.file
      ? `${f.location.file}${f.location.startLine ? `:${f.location.startLine}` : ""}`
      : f.location.uri ?? "";
    lines.push(`| ${f.severity} | ${f.tool} | \`${f.ruleId}\` | ${loc} | ${f.title.replace(/\|/g, "\\|")} |`);
  }
  return lines.join("\n");
}
