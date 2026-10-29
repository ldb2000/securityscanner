import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { loadConfig, applyRuleFilters, profileFailOn, ConfigError } from "../dist/core/src/config.js";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli", "src", "index.js");
const MOCKBIN = join(here, "fixtures", "mockbin");

function tmpWithConfig(cfg) {
  const dir = mkdtempSync(join(tmpdir(), "sec-scan-cfg-"));
  writeFileSync(join(dir, ".sec-scan.json"), JSON.stringify(cfg));
  return dir;
}
function runCli(args, mock = true) {
  const env = { ...process.env };
  if (mock) env.PATH = `${MOCKBIN}:${env.PATH}`;
  const r = spawnSync("node", [CLI, ...args], { encoding: "utf8", env });
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

test("profileFailOn maps profiles to thresholds", () => {
  assert.equal(profileFailOn("strict"), "medium");
  assert.equal(profileFailOn("standard"), "high");
  assert.equal(profileFailOn("permissive"), "critical");
});

test("loadConfig rejects an invalid profile with a clear message", () => {
  const dir = tmpWithConfig({ profile: "ultra" });
  assert.throws(() => loadConfig(undefined, dir), (e) => e instanceof ConfigError && /profile/.test(e.message));
  rmSync(dir, { recursive: true, force: true });
});

test("loadConfig rejects an unknown category", () => {
  const dir = tmpWithConfig({ categories: ["sast", "bogus"] });
  assert.throws(() => loadConfig(undefined, dir), ConfigError);
  rmSync(dir, { recursive: true, force: true });
});

test("loadConfig auto-discovers .sec-scan.json in the target dir", () => {
  const dir = tmpWithConfig({ categories: ["sast"], profile: "strict" });
  const cfg = loadConfig(undefined, dir);
  assert.deepEqual(cfg.categories, ["sast"]);
  assert.equal(cfg.profile, "strict");
  rmSync(dir, { recursive: true, force: true });
});

test("applyRuleFilters disables and enables by tool", () => {
  const f = (tool, ruleId) => ({ id: ruleId, ruleId, tool, category: "sast", severity: "high", title: ruleId, message: "", location: {} });
  const findings = [f("semgrep", "r1"), f("semgrep", "r2"), f("trivy", "CVE-1")];
  const disabled = applyRuleFilters(findings, { semgrep: { disable: ["r1"] } });
  assert.deepEqual(disabled.map((x) => x.ruleId).sort(), ["CVE-1", "r2"]);
  const onlyEnabled = applyRuleFilters(findings, { semgrep: { enable: ["r2"] } });
  assert.deepEqual(onlyEnabled.map((x) => x.ruleId).sort(), ["CVE-1", "r2"]);
});

test("a run is reproducible from config alone (no flags)", () => {
  // strict profile -> threshold medium; mock semgrep yields a high finding -> fail
  const dir = tmpWithConfig({ categories: ["sast"], profile: "strict" });
  const r = runCli(["ci", dir]);
  assert.equal(r.code, 1, "config-driven strict run fails on the high finding");
  rmSync(dir, { recursive: true, force: true });
});

test("CLI flag overrides config", () => {
  const dir = tmpWithConfig({ categories: ["sast"], profile: "strict" });
  const r = runCli(["ci", dir, "--fail-on", "critical"]);
  assert.equal(r.code, 0, "--fail-on critical overrides strict profile");
  rmSync(dir, { recursive: true, force: true });
});

test("an invalid config is rejected with exit 2", () => {
  const dir = tmpWithConfig({ categories: "not-an-array" });
  const r = runCli(["scan", dir, "--only", "sast"]);
  assert.equal(r.code, 2);
  assert.match(r.stderr, /categories/);
  rmSync(dir, { recursive: true, force: true });
});
