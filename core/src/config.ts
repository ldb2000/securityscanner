// Configuration file (.sec-scan.json) for reproducible runs.
//
// Precedence everywhere: CLI flag > config file > built-in default.
// A config lets a run be reproduced with no flags at all.

import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import type { Finding, ScanCategory, Severity } from "./types.js";

export class ConfigError extends Error {}

export type Profile = "strict" | "standard" | "permissive";

export interface RuleFilter {
  disable?: string[]; // ruleIds to drop
  enable?: string[]; // if set, keep ONLY these ruleIds (after disable)
}

export interface SecScanConfig {
  categories?: ScanCategory[];
  profile?: Profile;
  failOn?: Severity;
  harness?: "claude-code" | "codex" | "none";
  baseline?: string;
  rules?: Record<string, RuleFilter>; // keyed by tool name
}

const CONFIG_NAME = ".sec-scan.json";
const CATEGORIES: ScanCategory[] = ["sast", "sca", "secrets", "iac", "container", "sbom", "dast"];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const PROFILES: Profile[] = ["strict", "standard", "permissive"];

/** Profile -> ci severity threshold. */
export function profileFailOn(profile: Profile): Severity {
  switch (profile) {
    case "strict":
      return "medium";
    case "permissive":
      return "critical";
    default:
      return "high";
  }
}

function validate(raw: unknown): SecScanConfig {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ConfigError("Config must be a JSON object.");
  }
  const c = raw as Record<string, unknown>;
  const out: SecScanConfig = {};

  if (c.categories !== undefined) {
    if (!Array.isArray(c.categories) || c.categories.some((x) => !CATEGORIES.includes(x as ScanCategory))) {
      throw new ConfigError(`\`categories\` must be a subset of: ${CATEGORIES.join(", ")}`);
    }
    out.categories = c.categories as ScanCategory[];
  }
  if (c.profile !== undefined) {
    if (!PROFILES.includes(c.profile as Profile)) {
      throw new ConfigError(`\`profile\` must be one of: ${PROFILES.join(", ")}`);
    }
    out.profile = c.profile as Profile;
  }
  if (c.failOn !== undefined) {
    if (!SEVERITIES.includes(c.failOn as Severity)) {
      throw new ConfigError(`\`failOn\` must be one of: ${SEVERITIES.join(", ")}`);
    }
    out.failOn = c.failOn as Severity;
  }
  if (c.harness !== undefined) {
    if (!["claude-code", "codex", "none"].includes(c.harness as string)) {
      throw new ConfigError("`harness` must be claude-code, codex or none.");
    }
    out.harness = c.harness as SecScanConfig["harness"];
  }
  if (c.baseline !== undefined) {
    if (typeof c.baseline !== "string") throw new ConfigError("`baseline` must be a path string.");
    out.baseline = c.baseline;
  }
  if (c.rules !== undefined) {
    if (typeof c.rules !== "object" || c.rules === null || Array.isArray(c.rules)) {
      throw new ConfigError("`rules` must be an object keyed by tool name.");
    }
    out.rules = c.rules as Record<string, RuleFilter>;
  }
  return out;
}

/**
 * Resolve the config file. With `explicitPath`, it must exist and be valid.
 * Otherwise auto-discover `.sec-scan.json` in `targetDir` then cwd; returns an
 * empty config when none is found.
 */
export function loadConfig(explicitPath: string | undefined, targetDir = "."): SecScanConfig {
  let path: string | undefined;
  if (explicitPath) {
    if (!existsSync(explicitPath)) throw new ConfigError(`Config file not found: ${explicitPath}`);
    path = explicitPath;
  } else {
    const candidates: string[] = [];
    try {
      if (statSync(targetDir).isDirectory()) candidates.push(join(targetDir, CONFIG_NAME));
    } catch {
      /* targetDir may be a URL or missing */
    }
    candidates.push(CONFIG_NAME);
    path = candidates.find((p) => existsSync(p));
  }
  if (!path) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new ConfigError(`Config file is not valid JSON: ${path}`);
  }
  return validate(parsed);
}

/** Drop findings disabled by per-tool rule filters; keep only enabled when set. */
export function applyRuleFilters(findings: Finding[], rules: Record<string, RuleFilter> | undefined): Finding[] {
  if (!rules) return findings;
  return findings.filter((f) => {
    const r = rules[f.tool];
    if (!r) return true;
    if (r.disable?.includes(f.ruleId)) return false;
    if (r.enable && r.enable.length > 0) return r.enable.includes(f.ruleId);
    return true;
  });
}
