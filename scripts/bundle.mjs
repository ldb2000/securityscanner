// Build a self-contained single-file CLI (dist/sec-scan.mjs) with esbuild.
// Run: npm run bundle  ->  node dist/sec-scan.mjs --help
import { build } from "esbuild";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";

const outfile = "dist/sec-scan.cjs";
const SHEBANG = "#!/usr/bin/env node";

await build({
  entryPoints: ["cli/src/index.ts"],
  outfile,
  bundle: true,
  platform: "node",
  target: "node20",
  // CJS so bundled CommonJS deps (commander) can require Node built-ins.
  format: "cjs",
  external: ["node:*"],
  logLevel: "info",
});

// Ensure the shebang is the very first byte of the file (required for direct exec).
let code = readFileSync(outfile, "utf8").replace(/^\s*#![^\n]*\n/, "").replace(/^\s+/, "");
writeFileSync(outfile, `${SHEBANG}\n${code}`);
chmodSync(outfile, 0o755);
console.log(`bundled -> ${outfile}`);
