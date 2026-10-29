import { test } from "node:test";
import assert from "node:assert/strict";
import { applyBaseline, activeSuppressions, baselineFromFindings } from "../dist/core/src/baseline.js";
import { fingerprint } from "../dist/core/src/engine.js";

function f(id, severity = "high") {
  return { id, ruleId: id, tool: "t", category: "sast", severity, title: id, message: "", location: {} };
}

test("a baselined finding is removed from the kept set", () => {
  const findings = [f("a"), f("b")];
  const baseline = { suppressions: [{ fingerprint: "a", reason: "accepted" }] };
  const { kept, suppressed } = applyBaseline(findings, baseline);
  assert.deepEqual(kept.map((x) => x.id), ["b"]);
  assert.deepEqual(suppressed.map((x) => x.id), ["a"]);
});

test("an expired suppression lets the finding reappear", () => {
  const findings = [f("a")];
  const past = { suppressions: [{ fingerprint: "a", expires: "2000-01-01" }] };
  const future = { suppressions: [{ fingerprint: "a", expires: "2999-01-01" }] };
  assert.equal(applyBaseline(findings, past).kept.length, 1, "expired -> reappears");
  assert.equal(applyBaseline(findings, future).kept.length, 0, "future -> suppressed");
});

test("activeSuppressions honors the provided clock", () => {
  const b = { suppressions: [{ fingerprint: "x", expires: "2026-06-01" }] };
  assert.ok(activeSuppressions(b, new Date("2026-01-01")).has("x"));
  assert.ok(!activeSuppressions(b, new Date("2026-12-01")).has("x"));
});

test("baselineFromFindings suppresses every given finding", () => {
  const b = baselineFromFindings([f("a"), f("b")], "known");
  assert.deepEqual(b.suppressions.map((s) => s.fingerprint).sort(), ["a", "b"]);
  assert.equal(b.suppressions[0].reason, "known");
});

test("fingerprint is stable across identical inputs and differs otherwise", () => {
  assert.equal(fingerprint(["semgrep", "rule", "a.js", 3]), fingerprint(["semgrep", "rule", "a.js", 3]));
  assert.notEqual(fingerprint(["semgrep", "rule", "a.js", 3]), fingerprint(["semgrep", "rule", "a.js", 4]));
});
