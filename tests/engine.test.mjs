import { test } from "node:test";
import assert from "node:assert/strict";
import { mergeFindings, topSeverity, severityRank, identify } from "../dist/core/src/engine.js";

function f(id, severity, category = "sast", falsePositive = false) {
  return { id, ruleId: id, tool: "t", category, severity, title: id, message: "", location: {}, falsePositive };
}

test("mergeFindings dedupes by id keeping highest severity", () => {
  const merged = mergeFindings([
    { tool: "a", category: "sast", ok: true, findings: [f("x", "low"), f("y", "medium")] },
    { tool: "b", category: "sast", ok: true, findings: [f("x", "critical")] },
  ]);
  assert.equal(merged.length, 2);
  assert.equal(merged.find((m) => m.id === "x").severity, "critical");
});

test("mergeFindings sorts by severity (critical first)", () => {
  const merged = mergeFindings([
    { tool: "a", category: "sast", ok: true, findings: [f("lo", "low"), f("cr", "critical"), f("me", "medium")] },
  ]);
  assert.deepEqual(merged.map((m) => m.id), ["cr", "me", "lo"]);
});

test("topSeverity ignores false positives", () => {
  assert.equal(topSeverity([f("a", "critical", "sast", true), f("b", "medium")]), "medium");
  assert.equal(topSeverity([f("a", "critical", "sast", true)]), null);
});

test("severityRank orders critical < info", () => {
  assert.ok(severityRank("critical") < severityRank("info"));
});

test("identify gates DAST without scope", async () => {
  const fakeDast = {
    tool: "fake",
    category: "dast",
    version: async () => "1",
    scan: async () => ({ tool: "fake", category: "dast", ok: true, findings: [f("net", "high", "dast")] }),
  };
  const res = await identify({ target: "https://example.com", categories: ["dast"], scanners: [fakeDast] });
  assert.equal(res[0].skipped, true);
  assert.match(res[0].reason, /authorization scope/);
});

test("identify runs DAST when target is in scope", async () => {
  const fakeDast = {
    tool: "fake",
    category: "dast",
    version: async () => "1",
    scan: async () => ({ tool: "fake", category: "dast", ok: true, findings: [f("net", "high", "dast")] }),
  };
  const scope = { authorizedBy: "me", authorizedAt: "now", targets: ["example.com"] };
  const res = await identify({ target: "https://example.com", categories: ["dast"], scanners: [fakeDast], scope });
  assert.equal(res[0].ok, true);
  assert.equal(res[0].findings.length, 1);
});

test("identify refuses DAST for out-of-scope target", async () => {
  const fakeDast = {
    tool: "fake",
    category: "dast",
    version: async () => "1",
    scan: async () => ({ tool: "fake", category: "dast", ok: true, findings: [] }),
  };
  const scope = { authorizedBy: "me", authorizedAt: "now", targets: ["example.com"] };
  const res = await identify({ target: "https://evil.org", categories: ["dast"], scanners: [fakeDast], scope });
  assert.equal(res[0].skipped, true);
  assert.match(res[0].reason, /not in the authorized scope/);
});
