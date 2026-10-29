#!/usr/bin/env node
// sec-scan CLI: identify -> validate -> remediate.

import { Command } from "commander";
import { readFileSync, writeFileSync } from "node:fs";
import type { ScanCategory, Severity } from "../../core/src/types.js";
import { SEVERITY_ORDER } from "../../core/src/types.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFileSync as writeFileSyncTmp, rmSync } from "node:fs";
import { collectToolVersions, identify, mergeFindings, newManifest, severityRank, topSeverity } from "../../core/src/engine.js";
import { loadScope, ScopeError } from "../../core/src/scope.js";
import { audit } from "../../core/src/audit.js";
import type { Finding } from "../../core/src/types.js";

const pExecFile = promisify(execFile);
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
    manifest.toolVersions = await collectToolVersions(ALL_SCANNERS, categories);
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
    manifest.toolVersions = await collectToolVersions(ALL_SCANNERS, categories);
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
  .command("fix")
  .description("show proposed remediation diffs; apply only with explicit confirmation")
  .argument("<findings.json>", "a findings JSON file produced by scan/audit")
  .option("--apply", "apply the diffs to the working tree (requires --yes)")
  .option("--yes", "non-interactive confirmation for --apply")
  .action(async (file: string, opts) => {
    const data = JSON.parse(readFileSync(file, "utf8")) as { manifest?: { target?: string }; findings: Finding[] };
    const withDiff = (data.findings ?? []).filter((f) => f.remediation?.diff && !f.falsePositive);
    if (withDiff.length === 0) {
      console.error("No remediation diffs to apply. Run `sec-scan audit --harness <h>` first.");
      return;
    }
    for (const f of withDiff) {
      console.log(`\n# ${f.severity.toUpperCase()} ${f.ruleId} (${f.tool}) — ${f.title}`);
      console.log(f.remediation!.summary);
      console.log(f.remediation!.diff);
    }
    if (!opts.apply) {
      console.error(`\n${withDiff.length} diff(s) shown. Re-run with --apply --yes to apply them.`);
      return;
    }
    if (!opts.yes) {
      console.error("Refusing to apply without explicit confirmation. Pass --yes.");
      process.exit(2);
    }
    let applied = 0;
    for (const f of withDiff) {
      const patch = join(tmpdir(), `sec-scan-fix-${f.id}.patch`);
      writeFileSyncTmp(patch, f.remediation!.diff!.endsWith("\n") ? f.remediation!.diff! : f.remediation!.diff! + "\n");
      try {
        await pExecFile("git", ["apply", "--whitespace=nowarn", patch]);
        applied++;
        audit({ action: "fix-apply", target: data.manifest?.target ?? ".", detail: `${f.tool}:${f.ruleId}` });
        console.error(`applied: ${f.ruleId}`);
      } catch (e) {
        console.error(`FAILED to apply ${f.ruleId}: ${(e as Error).message.split("\n")[0]}`);
      } finally {
        try {
          rmSync(patch, { force: true });
        } catch {
          /* ignore */
        }
      }
    }
    console.error(`\n${applied}/${withDiff.length} diff(s) applied. Review with 'git diff' before committing.`);
  });

program
  .command("login")
  .description("store harness credentials (placeholder)")
  .action(() => {
    console.error("Configure your harness: set SEC_SCAN_HARNESS and the relevant CLI (claude / codex) on PATH.");
  });

void SEVERITY_ORDER; // keep import for typing reference
program.parseAsync(process.argv);
