// Helpers to detect and run external scanner binaries safely.

import { execFile } from "node:child_process";
import { promisify } from "node:util";

const pExecFile = promisify(execFile);

export interface ExecResult {
  code: number;
  stdout: string;
  stderr: string;
}

/** Returns a version string if the binary exists, else null. */
export async function detect(bin: string, versionArgs = ["--version"]): Promise<string | null> {
  try {
    const { stdout, stderr } = await pExecFile(bin, versionArgs, { timeout: 10_000 });
    return (stdout || stderr).trim().split("\n")[0] || "present";
  } catch {
    return null;
  }
}

export interface RunOptions {
  cwd?: string;
  /** Hard time-box in ms (kills the process on expiry). Default 600s. */
  timeoutMs?: number;
}

/** Run a scanner. Never throws on non-zero exit (scanners use exit codes for findings). */
export async function run(bin: string, args: string[], opts: RunOptions | string = {}): Promise<ExecResult> {
  const o: RunOptions = typeof opts === "string" ? { cwd: opts } : opts;
  try {
    const { stdout, stderr } = await pExecFile(bin, args, {
      cwd: o.cwd,
      timeout: o.timeoutMs ?? 600_000,
      maxBuffer: 64 * 1024 * 1024,
    });
    return { code: 0, stdout, stderr };
  } catch (e) {
    const err = e as { code?: number; stdout?: string; stderr?: string; message?: string };
    return {
      code: typeof err.code === "number" ? err.code : 1,
      stdout: err.stdout ?? "",
      stderr: err.stderr ?? err.message ?? "",
    };
  }
}
