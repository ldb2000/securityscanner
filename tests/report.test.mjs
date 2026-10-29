import { test } from "node:test";
import assert from "node:assert/strict";
import { toSarif, toJson, toMarkdown } from "../dist/report/src/index.js";

const manifest = { startedAt: "t", target: ".", categories: ["sast"], harness: "none", toolVersions: { semgrep: "1.0" } };
const findings = [
  { id: "a", ruleId: "r.high", tool: "semgrep", category: "sast", severity: "high", title: "High issue", message: "bad", location: { file: "app.js", startLine: 3 } },
  { id: "b", ruleId: "r.fp", tool: "semgrep", category: "sast", severity: "critical", title: "FP", message: "", location: { file: "x.js" }, falsePositive: true },
];

test("toSarif emits a valid 2.1.0 envelope and excludes false positives", () => {
  const sarif = JSON.parse(toSarif(findings, manifest));
  assert.equal(sarif.version, "2.1.0");
  const results = sarif.runs.flatMap((r) => r.results);
  assert.equal(results.length, 1, "false positive excluded");
  assert.equal(results[0].ruleId, "r.high");
  assert.equal(results[0].level, "error"); // high -> error
});

test("toJson round-trips findings and manifest", () => {
  const obj = JSON.parse(toJson(findings, manifest));
  assert.equal(obj.findings.length, 2);
  assert.equal(obj.manifest.target, ".");
});

test("toMarkdown lists live findings and a summary line", () => {
  const md = toMarkdown(findings, manifest);
  assert.match(md, /Findings:\*\* 1/);
  assert.match(md, /r\.high/);
  assert.ok(!md.includes("r.fp"), "false positive not listed");
});

test("toMarkdown reports a clean tree when empty", () => {
  const md = toMarkdown([], manifest);
  assert.match(md, /No findings/);
});
