#!/usr/bin/env node
// sec-scan CLI: identify -> validate -> remediate.

import { Command } from "commander";
import { readFileSync, writeFileSync } from "node:fs";
import type { ScanCategory, Severity } from "../../core/src/types.js";
import { SEVERITY_ORDER } from "../../core/src/types.js";
import { identify, mergeFindings, newManifest, severityRank, topSeverity } from "../../core/src/engine.js";
import { loadScope, ScopeError } from "../../core/src/scope.js";
import { ALL_SCANNERS } from "../../scanners/src/index.js";
import { selectHarness } from "../../agent/src/index.js";
import { toJson, toMarkdown, toSarif } from "../../report/src/index.js";

const ALL_CATEGORIES: ScanCategory[] = ["sast", "sca", "secrets", "iac", "container", "sbom", "dast"];

function parseCategories(only: string | undefined): ScanCategory[] {
  if (!only) return ALL_CATEGORIES.filter((c) => c !== "dast"); // active checks opt-in
  return only
    .split(",")
    .map((s) => s.trim())
    .filter((s): s is ScanCategory => (ALL_CATEGORIES as string[]).includes(s));
}

function render(findings: ReturnType<typeof mergeFindings>, manifest: ReturnType<typeof newManifest>, format: string): string {
  switch (format) {
    case "json":
      return toJson(findings, manifest);
    case "md":
      return toMarkdown(findings, manifest);
    default:
      return toSarif(findings, manifest);
  }
}

const program = new Command();
program.name("sec-scan").description("Defensive security-audit CLI (identify -> validate -> remediate)").version("0.1.0");

program
  .command("scan")
  .argument("<path>", "target path, image, or URL")
  .option("--only <categories>", "comma list: sast,sca,secrets,iac,container,sbom,dast")
  .option("--format <fmt>", "sarif|json|md", "sarif")
  .option("--scope <file>", "authorization scope file (required for dast)")
  .option("--out <file>", "write report to file instead of stdout")
  .option("--harness <name>", "claude-code|codex|none", "none")
  .action(async (path: string, opts) => {
    const categories = parseCategories(opts.only);
    const harness = selectHarness(opts.harness);
    const manifest = newManifest(path, categories, harness);
    let scope;
    if (opts.scope) {
      try {
        scope = loadScope(opts.scope);
        manifest.scopeRef = opts.scope;
      } catch (e) {
        console.error((e as ScopeError).message);
        process.exit(2);
      }
    }
    const results = await identify({ target: path, categories, scanners: ALL_SCANNERS, scope });
    for (const r of results) if (r.skipped) console.error(`skip ${r.tool}/${r.category}: ${r.reason}`);
    const findings = mergeFindings(results);
    manifest.finishedAt = new Date().toISOString();
    const output = render(findings, manifest, opts.format);
    if (opts.out) {
      writeFileSync(opts.out, output);
      console.error(`wrote ${findings.length} findings to ${opts.out}`);
    } else {
      process.stdout.write(output + "\n");
    }
  });

program
  .command("audit")
  .description("scan -> validate -> remediate, end to end")
  .argument("<path>")
  .option("--only <categories>")
  .option("--scope <file>")
  .option("--harness <name>", "claude-code|codex|none", "none")
  .option("--format <fmt>", "sarif|json|md", "md")
  .action(async (path: string, opts) => {
    const categories = parseCategories(opts.only);
    const harness = selectHarness(opts.harness);
    const manifest = newManifest(path, categories, harness);
    let scope;
    if (opts.scope) {
      try {
        scope = loadScope(opts.scope);
        manifest.scopeRef = opts.scope;
      } catch (e) {
        console.error((e as ScopeError).message);
        process.exit(2);
      }
    }
    const results = await identify({ target: path, categories, scanners: ALL_SCANNERS, scope });
    for (const r of results) if (r.skipped) console.error(`skip ${r.tool}/${r.category}: ${r.reason}`);
    let findings = mergeFindings(results);
    findings = await harness.validate(findings);
    findings = await harness.remediate(findings);
    manifest.finishedAt = new Date().toISOString();
    process.stdout.write(render(findings, manifest, opts.format) + "\n");
  });

program
  .command("scope")
  .description("inspect/validate an authorization scope file")
  .argument("<file>")
  .action((file: string) => {
    try {
      const s = loadScope(file);
      console.log(`Authorized by: ${s.authorizedBy}`);
      console.log(`Authorized at: ${s.authorizedAt}`);
      console.log(`Targets (${s.targets.length}): ${s.targets.join(", ")}`);
      if (s.note) console.log(`Note: ${s.note}`);
    } catch (e) {
      console.error((e as ScopeError).message);
      process.exit(2);
    }
  });

program
  .command("report")
  .description("re-render a findings JSON file")
  .argument("<findings.json>")
  .option("--format <fmt>", "sarif|json|md", "md")
  .action((file: string, opts) => {
    const data = JSON.parse(readFileSync(file, "utf8")) as { manifest: ReturnType<typeof newManifest>; findings: ReturnType<typeof mergeFindings> };
    process.stdout.write(render(data.findings, data.manifest, opts.format) + "\n");
  });

program
  .command("ci")
  .description("non-interactive scan; exit non-zero over threshold")
  .argument("<path>")
  .option("--only <categories>")
  .option("--fail-on <severity>", "critical|high|medium|low", "high")
  .action(async (path: string, opts) => {
    const categories = parseCategories(opts.only);
    const harness = selectHarness("none");
    const results = await identify({ target: path, categories, scanners: ALL_SCANNERS });
    const findings = mergeFindings(results);
    const top = topSeverity(findings);
    const threshold = opts.failOn as Severity;
    const manifest = newManifest(path, categories, harness);
    console.error(toMarkdown(findings, manifest));
    if (top && severityRank(top) <= severityRank(threshold)) {
      console.error(`FAIL: highest severity ${top} >= threshold ${threshold}`);
      process.exit(1);
    }
    console.error(`PASS: nothing at or above ${threshold}`);
  });

program
  .command("login")
  .description("store harness credentials (placeholder)")
  .action(() => {
    console.error("Configure your harness: set SEC_SCAN_HARNESS and the relevant CLI (claude / codex) on PATH.");
  });

void SEVERITY_ORDER; // keep import for typing reference
program.parseAsync(process.argv);
