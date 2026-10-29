// Invoke an external agent CLI (Claude Code / Codex) non-interactively and
// read-only, returning its raw stdout. The prompt is passed on stdin so that
// untrusted finding data never lands on the shell command line.
//
// Command resolution precedence:
//   1. env override  (SEC_SCAN_CLAUDE_CMD / SEC_SCAN_CODEX_CMD) — useful for
//      tests and custom wrappers; space-separated argv.
//   2. built-in read-only invocation of `claude` / `codex`.

import { spawn } from "node:child_process";
import { detect } from "../../scanners/src/exec.js";

export type HarnessKind = "claude-code" | "codex";

interface CliSpec {
  bin: string;
  versionArgs: string[];
  args: string[]; // the prompt is piped on stdin
  envVar: string;
}

function spec(kind: HarnessKind): CliSpec {
  if (kind === "claude-code") {
    return {
      bin: "claude",
      versionArgs: ["--version"],
      // print mode, JSON envelope, no tools -> pure read-only reasoning over data
      args: ["-p", "--output-format", "json", "--allowedTools", ""],
      envVar: "SEC_SCAN_CLAUDE_CMD",
    };
  }
  return {
    bin: "codex",
    versionArgs: ["--version"],
    // exec = non-interactive; read-only sandbox, never asks for approval
    args: ["exec", "--sandbox", "read-only", "--ask-for-approval", "never", "-"],
    envVar: "SEC_SCAN_CODEX_CMD",
  };
}

/** Returns the resolved command argv, honoring the env override. */
function resolveArgv(s: CliSpec): string[] {
  const override = process.env[s.envVar];
  if (override && override.trim()) return override.trim().split(/\s+/);
  return [s.bin, ...s.args];
}

/** Whether the harness CLI is available (or overridden for tests). */
export async function harnessAvailable(kind: HarnessKind): Promise<boolean> {
  const s = spec(kind);
  if (process.env[s.envVar]?.trim()) return true;
  return (await detect(s.bin, s.versionArgs)) !== null;
}

/** Run the harness with `prompt` on stdin. Resolves to raw stdout (possibly ""). */
export function invokeHarness(kind: HarnessKind, prompt: string): Promise<string> {
  const s = spec(kind);
  const [cmd, ...args] = resolveArgv(s);
  return new Promise((resolve) => {
    let out = "";
    let err = "";
    let settled = false;
    const child = spawn(cmd, args, { stdio: ["pipe", "pipe", "pipe"] });
    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill("SIGKILL");
        resolve(out);
      }
    }, 300_000);
    child.stdout.on("data", (d) => (out += d.toString()));
    child.stderr.on("data", (d) => (err += d.toString()));
    child.on("error", () => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(""); // treated as "no response" -> caller falls back
      }
    });
    child.on("close", () => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        void err;
        resolve(out);
      }
    });
    child.stdin.write(prompt);
    child.stdin.end();
  });
}

/**
 * Claude Code's `--output-format json` wraps the reply in an envelope with a
 * `result` string. Unwrap it; otherwise return the text unchanged.
 */
export function unwrapEnvelope(raw: string, kind: HarnessKind): string {
  if (kind !== "claude-code") return raw;
  try {
    const env = JSON.parse(raw) as { result?: unknown };
    if (env && typeof env.result === "string") return env.result;
  } catch {
    /* not an envelope; use as-is */
  }
  return raw;
}
