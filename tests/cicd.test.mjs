import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, existsSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const CLI = join(root, "dist", "cli", "src", "index.js");
const MOCKBIN = join(here, "fixtures", "mockbin");
const VULN = join(here, "fixtures", "vuln-app");

test("composite action exposes the severity gate and SARIF upload", () => {
  const a = readFileSync(join(root, "action.yml"), "utf8");
  assert.match(a, /using: "composite"/);
  assert.match(a, /fail-on/);
  assert.match(a, /upload-sarif/);
  assert.match(a, /sec-scan ci/);
});

test("pipeline examples exist for GitHub and GitLab", () => {
  assert.ok(existsSync(join(root, "examples", "github-actions.yml")));
  assert.ok(existsSync(join(root, "examples", "gitlab-ci.yml")));
});

test("pre-commit hook is executable and gates on secrets+sast", () => {
  const p = join(root, "scripts", "pre-commit");
  assert.ok(existsSync(p));
  assert.ok(statSync(p).mode & 0o111, "hook is executable");
  assert.match(readFileSync(p, "utf8"), /ci .*--only secrets,sast .*--fail-on high/);
});

test("the gate blocks a secret introduced locally (exit 1)", () => {
  const env = { ...process.env, PATH: `${MOCKBIN}:${process.env.PATH}` };
  const r = spawnSync("node", [CLI, "ci", VULN, "--only", "secrets", "--fail-on", "high"], { encoding: "utf8", env });
  assert.equal(r.status, 1, "mock gitleaks secret -> high -> gate fails");
});
