// Agent harness: validates findings and proposes remediations.
//
// Findings are passed to the model as DATA, never as instructions (see
// harness-io.ts for the safety preamble). Triage runs read-only; remediations
// are returned as unified diffs and are NEVER auto-applied here — application is
// gated behind explicit human confirmation in the CLI layer.

import type { Harness } from "../../core/src/engine.js";
import type { Finding } from "../../core/src/types.js";
import {
  buildRemediationPrompt,
  buildTriagePrompt,
  parseRemediation,
  parseTriage,
} from "./harness-io.js";
import { harnessAvailable, invokeHarness, unwrapEnvelope, type HarnessKind } from "./invoke.js";

/** Default harness: no model available. Passthrough, nothing auto-applied. */
export const noneHarness: Harness = {
  name: "none",
  async validate(findings: Finding[]): Promise<Finding[]> {
    return findings.map((f) => ({ ...f, validated: false, reachability: f.reachability ?? "unknown" }));
  },
  async remediate(findings: Finding[]): Promise<Finding[]> {
    return findings;
  },
};

/**
 * Harness that drives an external agent CLI (Claude Code or Codex) read-only.
 * Falls back to the no-op harness when the binary is absent or gives no usable
 * response, so a run never fails because the harness is unavailable.
 */
export function externalHarness(kind: HarnessKind): Harness {
  return {
    name: kind,
    async validate(findings: Finding[]): Promise<Finding[]> {
      if (findings.length === 0) return findings;
      if (!(await harnessAvailable(kind))) return noneHarness.validate(findings);

      const raw = unwrapEnvelope(await invokeHarness(kind, buildTriagePrompt(findings)), kind);
      const parsed = parseTriage(raw);
      if (!parsed) return noneHarness.validate(findings);

      return findings.map((f) => {
        const v = parsed.verdicts[f.id];
        return {
          ...f,
          validated: true,
          falsePositive: v?.falsePositive ?? f.falsePositive ?? false,
          reachability: v?.reachability ?? f.reachability ?? "unknown",
        };
      });
    },

    async remediate(findings: Finding[]): Promise<Finding[]> {
      const targets = findings.filter((f) => !f.falsePositive);
      if (targets.length === 0) return findings;
      if (!(await harnessAvailable(kind))) return noneHarness.remediate(findings);

      const raw = unwrapEnvelope(await invokeHarness(kind, buildRemediationPrompt(targets)), kind);
      const parsed = parseRemediation(raw);
      if (!parsed) return findings;

      return findings.map((f) => {
        const r = parsed.remediations[f.id];
        if (!r || !r.diff) return f;
        return {
          ...f,
          remediation: { summary: r.summary || "Proposed fix", diff: r.diff, applied: false },
        };
      });
    },
  };
}

export function selectHarness(name: string | undefined): Harness {
  switch (name) {
    case "claude-code":
      return externalHarness("claude-code");
    case "codex":
      return externalHarness("codex");
    default:
      return noneHarness;
  }
}

export { buildTriagePrompt, buildRemediationPrompt } from "./harness-io.js";
