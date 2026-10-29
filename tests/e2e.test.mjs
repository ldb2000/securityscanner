import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const CLI = join(root, "dist", "cli", "src", "index.js");
const MOCKBIN = join(here, "fixtures", "mockbin");
const VULN = join(here, "fixtures", "vuln-app");

function runCli(args, { mock = false } = {}) {
  const env = { ...process.env };
  if (mock) env.PATH = `${MOCKBIN}:${env.PATH}`;
  const r = spawnSync("node", [CLI, ...args], { encoding: "utf8", env });
  return { code: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

test("scan --only sast finds the eval via the mock semgrep", () => {
  const r = runCli(["scan", VULN, "--only", "sast", "--format", "json"], { mock: true });
  assert.equal(r.code, 0);
  const report = JSON.parse(r.stdout);
  const ids = report.findings.map((f) => f.ruleId);
  assert.ok(ids.includes("javascript.lang.security.detect-eval"), "eval finding present");
});

test("scan --only secrets finds the hardcoded key via the mock gitleaks", () => {
  const r = runCli(["scan", VULN, "--only", "secrets", "--format", "json"], { mock: true });
  assert.equal(r.code, 0);
  const report = JSON.parse(r.stdout);
  assert.ok(report.findings.some((f) => f.tool === "gitleaks"), "gitleaks finding present");
});

test("ci exits non-zero when findings reach the threshold", () => {
  const r = runCli(["ci", VULN, "--only", "sast", "--fail-on", "high"], { mock: true });
  assert.equal(r.code, 1, "ERROR-level eval -> high -> fail");
});

test("ci passes when nothing reaches the threshold", () => {
  const r = runCli(["ci", VULN, "--only", "sast", "--fail-on", "critical"], { mock: true });
  assert.equal(r.code, 0, "high < critical -> pass");
});

test("scan without mocks degrades gracefully (no scanners installed)", () => {
  const r = runCli(["scan", VULN, "--only", "sast", "--format", "md"]);
  assert.equal(r.code, 0);
  assert.match(r.stderr, /skip semgrep\/sast/);
});

test("DAST is refused without an authorization scope", () => {
  const r = runCli(["scan", "https://staging.example.com", "--only", "dast", "--format", "md"]);
  assert.match(r.stderr, /authorization scope/);
});

test("DAST is refused for an out-of-scope target", () => {
  const scope = join(here, "fixtures", "scope-ok.json");
  const r = runCli(["scan", "https://evil.example.org", "--only", "dast", "--scope", scope]);
  assert.match(r.stderr, /not in the authorized scope/);
});

test("scope command validates and prints the attestation", () => {
  const scope = join(here, "fixtures", "scope-ok.json");
  const r = runCli(["scope", scope]);
  assert.equal(r.code, 0);
  assert.match(r.stdout, /Authorized by:/);
});
