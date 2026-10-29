// Authorization scope gate for active (DAST) scanning.
// Hard requirement: active checks refuse to run outside a recorded, attested scope.

import { readFileSync } from "node:fs";
import type { AuthorizationScope } from "./types.js";

export class ScopeError extends Error {}

export function loadScope(path: string): AuthorizationScope {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    throw new ScopeError(`Cannot read scope file: ${path}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new ScopeError(`Scope file is not valid JSON: ${path}`);
  }
  const s = parsed as Partial<AuthorizationScope>;
  if (!s.authorizedBy || !s.authorizedAt || !Array.isArray(s.targets) || s.targets.length === 0) {
    throw new ScopeError(
      "Scope must include authorizedBy, authorizedAt, and a non-empty targets allow-list.",
    );
  }
  return s as AuthorizationScope;
}

/** Normalize a target to a comparable host token. */
function hostOf(target: string): string {
  try {
    return new URL(target.includes("://") ? target : `https://${target}`).host.toLowerCase();
  } catch {
    return target.toLowerCase();
  }
}

/** Throws unless `target` is covered by the authorization allow-list. */
export function assertInScope(scope: AuthorizationScope, target: string): void {
  const want = hostOf(target);
  const allowed = scope.targets.some((t) => hostOf(t) === want);
  if (!allowed) {
    throw new ScopeError(
      `Target "${target}" is not in the authorized scope. Active scanning refused.`,
    );
  }
}
