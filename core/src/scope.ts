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

/** Normalize a target to a comparable host token (no scheme, no port). */
function hostOf(target: string): string {
  try {
    return new URL(target.includes("://") ? target : `https://${target}`).hostname.toLowerCase();
  } catch {
    return target.toLowerCase().replace(/:\d+$/, "");
  }
}

function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function inCidr(ip: string, cidr: string): boolean {
  const [net, bitsRaw] = cidr.split("/");
  const bits = Number(bitsRaw);
  const ipInt = ipv4ToInt(ip);
  const netInt = ipv4ToInt(net);
  if (ipInt === null || netInt === null || !(bits >= 0 && bits <= 32)) return false;
  if (bits === 0) return true;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

function wildcardToRegExp(pattern: string): RegExp {
  const esc = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^.]+");
  return new RegExp(`^${esc}$`, "i");
}

/** Does the target host match a single allow-list entry? */
export function hostMatchesEntry(host: string, entry: string): boolean {
  const e = entry.includes("://") ? hostOf(entry) : entry.trim().toLowerCase();
  if (e.includes("/") && ipv4ToInt(e.split("/")[0] ?? "") !== null) return inCidr(host, e); // CIDR
  if (e.startsWith("*.")) {
    const suffix = e.slice(1); // ".example.com"
    if (!host.endsWith(suffix)) return false;
    const label = host.slice(0, -suffix.length); // single label only
    return label.length > 0 && !label.includes(".");
  }
  if (e.includes("*")) return wildcardToRegExp(e).test(host); // generic wildcard
  return host === e; // exact
}

/** Throws unless `target` is covered by the authorization allow-list. */
export function assertInScope(scope: AuthorizationScope, target: string): void {
  const want = hostOf(target);
  const allowed = scope.targets.some((t) => hostMatchesEntry(want, t));
  if (!allowed) {
    throw new ScopeError(
      `Target "${target}" is not in the authorized scope. Active scanning refused.`,
    );
  }
}
