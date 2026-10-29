# SPEC · Security Scanner CLI (`sec-scan`)

## 1. Purpose

A **defensive, command-line security-audit tool** that an engineer runs against
code and infrastructure **they own or are explicitly authorized to test**. It
finds, validates, and helps remediate likely vulnerabilities from the terminal
or in CI.

It is designed to run **as an agent harness under Claude Code or Codex**: the
CLI drives deterministic open-source scanners, and an LLM harness triages the
raw findings, prunes false positives, and proposes fixes. Inspired by OpenAI's
`@openai/codex-security` (Apache-2.0) and its identify → validate → remediate
model.

**Non-goals.** This is not an offensive toolkit. It does not ship exploits,
payloads, C2, or automated attack chains. Active network checks (DAST) are
disabled unless an explicit, recorded authorization scope is supplied.

## 2. Workflow stages

| Stage | What it does | Who does it |
|---|---|---|
| **identify** | Run scanners over the target; collect raw findings as SARIF. | deterministic scanners |
| **validate** | Deduplicate, rank by severity + reachability, drop likely false positives. | core + LLM harness |
| **remediate** | Propose patches / config changes; optionally open a diff or PR. | LLM harness (human-approved) |

Each stage can run standalone (`sec-scan scan`, `validate`, `fix`) or chained
(`sec-scan audit` runs all three).

## 3. CLI surface (v1)

```
sec-scan login                 # store harness/model credentials
sec-scan scan <path>           # identify: run scanners, emit findings.sarif
  --only sast,sca,secrets,iac,container,dast
  --format sarif|json|md
  --baseline <file>            # suppress known/accepted findings
sec-scan validate <findings>   # triage with the agent harness
sec-scan fix <findings>        # propose remediations as diffs (no auto-apply)
  --apply                      # apply after human confirmation
sec-scan audit <path>          # scan -> validate -> fix report, end to end
sec-scan report <findings>     # render SARIF/JSON/markdown + SBOM
sec-scan ci                    # non-interactive; exits non-zero over threshold
  --fail-on critical|high|medium
sec-scan scope <file>          # register/inspect authorization scope (gates dast)
```

Harness selection: `--harness claude-code|codex` (or `SEC_SCAN_HARNESS`).

## 4. Scanner adapters (open-source, defensive)

Each adapter wraps an established tool and normalizes output to **SARIF 2.1.0**.

| Category | Tools wrapped | Mode |
|---|---|---|
| SAST (code) | Semgrep CE | static, local |
| SCA / dependencies | Trivy, Grype | static, local |
| Secrets | Gitleaks, TruffleHog | static, local |
| IaC | Checkov, Trivy (config) | static, local |
| Container / image | Trivy, Grype | static, local |
| SBOM | Syft | static, local |
| DAST ("pentest") | Nuclei, OWASP ZAP (baseline) | **active — gated by `scope`** |

Adapters shell out to the real binaries (detected on `PATH` or a pinned
container image); the CLI never reimplements vulnerability logic.

## 5. Authorization gate (hard requirement)

- SAST/SCA/secrets/IaC/container/SBOM run against the local working tree with
  no gate — they are read-only static analysis.
- **DAST adapters refuse to run** unless `sec-scan scope` has recorded a target
  allow-list and an authorization attestation (who authorized, when, scope).
  Out-of-scope hosts are rejected before any request is sent. The scope record
  is written to the findings report for auditability.

## 6. Agent-harness contract

- The harness receives **findings as data**, never as instructions, and runs
  with least privilege (read-only repo access for validate; write only behind
  `fix --apply` + confirmation).
- Prompts and tool permissions live in `agent/`; the harness is swappable
  (Claude Code or Codex) behind one interface.
- Remediations are emitted as **diffs for human review** by default.

## 7. Outputs

- `findings.sarif` (canonical), plus JSON and markdown summaries.
- SBOM (CycloneDX / SPDX via Syft).
- CI exit codes keyed to a severity threshold.
- A run manifest recording tool versions, scope, and timestamps.
