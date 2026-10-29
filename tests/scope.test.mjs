import { test } from "node:test";
import assert from "node:assert/strict";
import { writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { loadScope, assertInScope, ScopeError } from "../dist/core/src/scope.js";

function tmpScope(obj) {
  const p = join(tmpdir(), `scope-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(p, JSON.stringify(obj));
  return p;
}

test("loadScope rejects missing fields", () => {
  const p = tmpScope({ authorizedBy: "x" });
  assert.throws(() => loadScope(p), ScopeError);
  rmSync(p, { force: true });
});

test("loadScope accepts a complete scope", () => {
  const p = tmpScope({ authorizedBy: "x", authorizedAt: "now", targets: ["a.com"] });
  const s = loadScope(p);
  assert.deepEqual(s.targets, ["a.com"]);
  rmSync(p, { force: true });
});

test("assertInScope matches by host, ignores scheme", () => {
  const s = { authorizedBy: "x", authorizedAt: "now", targets: ["staging.example.com"] };
  assert.doesNotThrow(() => assertInScope(s, "https://staging.example.com/path"));
  assert.throws(() => assertInScope(s, "https://evil.example.org"), ScopeError);
});
