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

  // Delta vs baseline.
  if (manifest.delta) {
    lines.push(`- **New since baseline:** ${manifest.delta.added.length}`);
    lines.push(`- **Resolved since baseline:** ${manifest.delta.resolved.length}`);
    lines.push("");
  }

  // Summary by severity.
  const bySeverity = new Map<string, number>();
  const byCategory = new Map<string, number>();
  for (const f of live) {
    bySeverity.set(f.severity, (bySeverity.get(f.severity) ?? 0) + 1);
    byCategory.set(f.category, (byCategory.get(f.category) ?? 0) + 1);
  }
  if (live.length > 0) {
    lines.push("## Summary by severity");
    lines.push("");
    lines.push("| Severity | Count |");
    lines.push("|---|---|");
    for (const sev of ["critical", "high", "medium", "low", "info"]) {
      if (bySeverity.has(sev)) lines.push(`| ${sev} | ${bySeverity.get(sev)} |`);
    }
    lines.push("");
    lines.push("## Summary by category");
    lines.push("");
    lines.push("| Category | Count |");
    lines.push("|---|---|");
    for (const [cat, n] of [...byCategory.entries()].sort()) lines.push(`| ${cat} | ${n} |`);
    lines.push("");
  }

  // Per-scanner durations.
  if (manifest.durations && Object.keys(manifest.durations).length > 0) {
    lines.push("## Scanner durations");
    lines.push("");
    lines.push("| Scanner | Duration (ms) |");
    lines.push("|---|---|");
    for (const [tool, ms] of Object.entries(manifest.durations)) lines.push(`| ${tool} | ${ms} |`);
    lines.push("");
  }

  if (live.length === 0) {
    lines.push("No findings. ✅");
    return lines.join("\n");
  }
  lines.push("## Findings");
  lines.push("");
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
