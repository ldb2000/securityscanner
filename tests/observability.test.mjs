import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { toMarkdown } from "../dist/report/src/index.js";
import { identify } from "../dist/core/src/engine.js";

const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, "..", "dist", "cli", "src", "index.js");
const MOCKBIN = join(here, "fixtures", "mockbin");
const VULN = join(here, "fixtures", "vuln-app");

const manifest = {
  startedAt: "t",
  target: ".",
  categories: ["sast", "sca"],
  harness: "none",
  toolVersions: { semgrep: "1.90.0" },
  durations: { semgrep: 42 },
  delta: { added: ["a", "b"], resolved: ["c"] },
};
const findings = [
  { id: "a", ruleId: "r1", tool: "semgrep", category: "sast", severity: "high", title: "H", message: "", location: {} },
  { id: "b", ruleId: "r2", tool: "trivy", category: "sca", severity: "medium", title: "M", message: "", location: {} },
];

test("markdown shows summary by severity and by category", () => {
  const md = toMarkdown(findings, manifest);
  assert.match(md, /## Summary by severity/);
  assert.match(md, /\| high \| 1 \|/);
  assert.match(md, /## Summary by category/);
  assert.match(md, /\| sast \| 1 \|/);
  assert.match(md, /\| sca \| 1 \|/);
});

test("markdown shows per-scanner durations", () => {
  const md = toMarkdown(findings, manifest);
  assert.match(md, /## Scanner durations/);
  assert.match(md, /\| semgrep \| 42 \|/);
});

test("markdown shows delta vs baseline", () => {
  const md = toMarkdown(findings, manifest);
  assert.match(md, /New since baseline:\*\* 2/);
  assert.match(md, /Resolved since baseline:\*\* 1/);
});

test("identify records a numeric duration per scanner", async () => {
  const fake = {
    tool: "fake",
    category: "sast",
    version: async () => "1",
    scan: async () => ({ tool: "fake", category: "sast", ok: true, findings: [] }),
  };
  const res = await identify({ target: ".", categories: ["sast"], scanners: [fake] });
  assert.equal(typeof res[0].durationMs, "number");
  assert.ok(res[0].durationMs >= 0);
});

test("e2e: scan with a baseline reports new/resolved counts", () => {
  const dir = mkdtempSync(join(tmpdir(), "sec-scan-delta-"));
  // Baseline accepts a fingerprint that the mock will NOT produce -> it is "resolved".
  const bl = join(dir, "baseline.json");
  writeFileSync(bl, JSON.stringify({ suppressions: [{ fingerprint: "deadbeefdeadbeef", reason: "old" }] }));
  const env = { ...process.env, PATH: `${MOCKBIN}:${process.env.PATH}` };
  const r = spawnSync("node", [CLI, "scan", VULN, "--only", "sast", "--baseline", bl, "--format", "md"], { encoding: "utf8", env });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /New since baseline:\*\* 1/); // the mock eval finding
  assert.match(r.stdout, /Resolved since baseline:\*\* 1/); // the stale baseline fingerprint
  rmSync(dir, { recursive: true, force: true });
});
