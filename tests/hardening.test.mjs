import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync, rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { hostMatchesEntry, assertInScope, ScopeError } from "../dist/core/src/scope.js";
import { audit } from "../dist/core/src/audit.js";

const CLI = join(dirname(fileURLToPath(import.meta.url)), "..", "dist", "cli", "src", "index.js");

test("CIDR matching: in-range vs out-of-range", () => {
  assert.ok(hostMatchesEntry("10.0.0.5", "10.0.0.0/24"));
  assert.ok(!hostMatchesEntry("10.0.1.5", "10.0.0.0/24"));
  assert.ok(hostMatchesEntry("192.168.1.200", "192.168.0.0/16"));
});

test("wildcard matching: single label only", () => {
  assert.ok(hostMatchesEntry("api.example.com", "*.example.com"));
  assert.ok(!hostMatchesEntry("example.com", "*.example.com"));
  assert.ok(!hostMatchesEntry("a.b.example.com", "*.example.com"));
});

test("assertInScope accepts a CIDR-covered target, rejects outside", () => {
  const scope = { authorizedBy: "x", authorizedAt: "now", targets: ["10.0.0.0/24", "*.staging.example.com"] };
  assert.doesNotThrow(() => assertInScope(scope, "http://10.0.0.42:8080/health"));
  assert.doesNotThrow(() => assertInScope(scope, "https://api.staging.example.com"));
  assert.throws(() => assertInScope(scope, "https://10.0.9.9"), ScopeError);
  assert.throws(() => assertInScope(scope, "https://example.com"), ScopeError);
});

test("audit entry records who / when / perimeter", () => {
  const log = join(mkdtempSync(join(tmpdir(), "sec-scan-audit-")), "audit.log");
  audit({ action: "active-scan", target: "https://api.staging.example.com", detail: "nuclei/dast", authorizedBy: "secteam", authorizedAt: "2026-10-29T00:00:00Z", targets: ["*.staging.example.com"] }, log);
  const entry = JSON.parse(readFileSync(log, "utf8").trim());
  assert.equal(entry.authorizedBy, "secteam");
  assert.equal(entry.authorizedAt, "2026-10-29T00:00:00Z");
  assert.deepEqual(entry.targets, ["*.staging.example.com"]);
  assert.ok(entry.at, "timestamp present");
  rmSync(dirname(log), { recursive: true, force: true });
});

test("fix --apply writes nothing without --yes", () => {
  const dir = mkdtempSync(join(tmpdir(), "sec-scan-fix-"));
  const findings = join(dir, "f.json");
  writeFileSync(findings, JSON.stringify({
    manifest: { target: "." },
    findings: [{ id: "x", ruleId: "r", tool: "semgrep", category: "sast", severity: "high", title: "t", message: "", location: { file: "a" }, remediation: { summary: "s", diff: "--- a/a\n+++ b/a\n@@ -1 +1 @@\n-x\n+y\n" } }],
  }));
  const r = spawnSync("node", [CLI, "fix", findings, "--apply"], { encoding: "utf8" });
  assert.equal(r.status, 2, "refused without --yes");
  assert.match(r.stderr, /without explicit confirmation/i);
  rmSync(dir, { recursive: true, force: true });
});
