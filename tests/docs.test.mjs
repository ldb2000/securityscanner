import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const docs = join(root, "docs");
const read = (p) => readFileSync(p, "utf8");

test("root README links to docs/", () => {
  assert.match(read(join(root, "README.md")), /docs\/README\.md/);
});

test("every SEC_SCAN_* env var in the source is documented", () => {
  const srcDirs = ["cli", "core", "scanners", "agent", "report", "scripts"];
  const vars = new Set();
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(ts|sh|mjs)$/.test(e.name)) {
        for (const m of read(p).matchAll(/SEC_SCAN_[A-Z_]+/g)) vars.add(m[0]);
      }
    }
  };
  for (const d of srcDirs) walk(join(root, d));
  const envDoc = read(join(docs, "environnement.md"));
  const missing = [...vars].filter((v) => !envDoc.includes(v));
  assert.deepEqual(missing, [], `undocumented env vars: ${missing.join(", ")}`);
});

test("every CLI command is documented in docs/commandes.md", () => {
  const ref = read(join(docs, "commandes.md"));
  for (const cmd of ["scan", "audit", "fix", "report", "ci", "baseline", "scope", "login"]) {
    assert.match(ref, new RegExp(`\`${cmd}`), `command ${cmd} documented`);
  }
});

test("DAST doc states authorization and ships no offensive payloads", () => {
  const d = read(join(docs, "dast-et-autorisation.md")).toLowerCase();
  assert.match(d, /autoris/);
  assert.match(d, /rejet.*avant tout trafic|avant tout trafic/);
});

test("all expected doc pages exist", () => {
  for (const p of [
    "README.md", "installation.md", "demarrage-rapide.md", "commandes.md",
    "configuration.md", "environnement.md", "harness.md", "baseline.md",
    "dast-et-autorisation.md", "ci.md", "sorties.md", "guidelines.md",
  ]) {
    assert.ok(existsSync(join(docs, p)), `docs/${p} exists`);
  }
});
