import { test } from "node:test";
import assert from "node:assert/strict";
import { ingestSarif } from "../dist/core/src/sarif-ingest.js";

const sample = {
  runs: [
    {
      tool: { driver: { name: "semgrep", rules: [{ id: "rule.x", helpUri: "https://ex/rule" }] } },
      results: [
        {
          ruleId: "rule.x",
          level: "error",
          message: { text: "bad thing" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "app.js" }, region: { startLine: 10, endLine: 12 } } }],
        },
        {
          ruleId: "rule.y",
          level: "warning",
          message: { text: "meh" },
          locations: [{ physicalLocation: { artifactLocation: { uri: "b.js" }, region: { startLine: 1 } } }],
        },
      ],
    },
  ],
};

test("ingestSarif maps levels, locations and help URIs", () => {
  const findings = ingestSarif(sample, { tool: "semgrep", category: "sast" });
  assert.equal(findings.length, 2);
  const x = findings.find((f) => f.ruleId === "rule.x");
  assert.equal(x.severity, "high"); // error -> high
  assert.equal(x.location.file, "app.js");
  assert.equal(x.location.startLine, 10);
  assert.deepEqual(x.references, ["https://ex/rule"]);
  assert.equal(findings.find((f) => f.ruleId === "rule.y").severity, "medium"); // warning -> medium
});

test("ingestSarif ids are stable and category is applied", () => {
  const a = ingestSarif(sample, { tool: "semgrep", category: "sast" });
  const b = ingestSarif(JSON.stringify(sample), { tool: "semgrep", category: "sast" });
  assert.deepEqual(a.map((f) => f.id), b.map((f) => f.id));
  assert.ok(a.every((f) => f.category === "sast"));
});

test("ingestSarif returns [] on malformed input", () => {
  assert.deepEqual(ingestSarif("not json", { tool: "t", category: "sast" }), []);
});
