import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

test("package.json is publishable: scoped name, bin, files, public access", () => {
  assert.match(pkg.name, /^@[a-z0-9-]+\/sec-scan$/);
  assert.match(pkg.version, /^\d+\.\d+\.\d+$/);
  assert.ok(pkg.bin && pkg.bin["sec-scan"], "bin.sec-scan present");
  assert.ok(Array.isArray(pkg.files) && pkg.files.includes("dist"), "files includes dist");
  assert.equal(pkg.publishConfig?.access, "public");
  assert.ok(pkg.scripts?.prepublishOnly, "prepublishOnly builds before publish");
});

test("LICENSE and CHANGELOG ship with the package", () => {
  assert.ok(existsSync(join(root, "LICENSE")), "LICENSE present");
  assert.ok(existsSync(join(root, "CHANGELOG.md")), "CHANGELOG present");
  assert.match(readFileSync(join(root, "LICENSE"), "utf8"), /Apache License/);
});

test("pinned scanner versions agree between Dockerfile and verify-tools.sh", () => {
  const dockerfile = readFileSync(join(root, "Dockerfile"), "utf8");
  const verify = readFileSync(join(root, "scripts", "verify-tools.sh"), "utf8");
  for (const tool of ["TRIVY", "GRYPE", "SYFT", "GITLEAKS"]) {
    const dv = new RegExp(`${tool}_VERSION=([0-9.]+)`).exec(dockerfile)?.[1];
    const lower = tool.toLowerCase();
    const vv = new RegExp(`\\[${lower}\\]="([0-9.]+)"`).exec(verify)?.[1];
    assert.ok(dv, `${tool} pinned in Dockerfile`);
    assert.equal(dv, vv, `${tool} version matches in verify-tools.sh`);
  }
});
