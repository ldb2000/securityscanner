# sec-scan

A **defensive security-audit CLI** that runs as an agent harness under
**Claude Code or Codex**. It drives standard open-source scanners
(identify), triages their findings with an LLM harness (validate), and
proposes human-reviewed fixes (remediate). Inspired by OpenAI's
`@openai/codex-security`.

> Use only against code and systems you own or are explicitly authorized to
> test. Active (DAST) checks are refused unless an authorization scope is
> supplied. See `SPEC.md` §5.

## Install & build

```bash
npm install
npm run build
node dist/cli/src/index.js --help
```

## Usage

```bash
sec-scan scan .                      # static scan (sast, sca, secrets, iac, container, sbom)
sec-scan scan . --format md          # markdown report
sec-scan audit . --harness claude-code --format json > findings.json
sec-scan fix findings.json           # show proposed diffs (nothing applied)
sec-scan fix findings.json --apply --yes   # apply after explicit confirmation (audit-logged)
sec-scan ci . --fail-on high         # CI gate

# Baseline: accept known findings so they stop showing up
sec-scan scan . --format json > findings.json
sec-scan baseline findings.json --out baseline.json   # generate suppressions
sec-scan scan . --baseline baseline.json              # suppressed on later runs
sec-scan scope scope.json            # validate an authorization scope
sec-scan scan https://staging.example.com --only dast --scope scope.json
```

### Authorization scope (`scope.json`)

```json
{
  "authorizedBy": "secteam",
  "authorizedAt": "2026-10-29T12:00:00Z",
  "note": "staging only",
  "targets": ["staging.example.com"]
}
```

DAST adapters refuse to run without this file, and reject any target not in
`targets`.

### Baseline (`baseline.json`)

```json
{
  "suppressions": [
    { "fingerprint": "ab12cd34ef56…", "reason": "accepted risk", "expires": "2026-12-31" }
  ]
}
```

A finding is hidden while a suppression matches its fingerprint and has not
expired. Remove `expires` to suppress indefinitely; an expired suppression lets
the finding reappear. Findings are normalized through a single SARIF-2.1.0
ingestion path (`core/sarif-ingest.ts`), so fingerprints are stable across runs.

## Layout

| Folder | Role |
|---|---|
| `cli/` | command surface (commander) |
| `core/` | orchestration engine, finding model, scope gate |
| `scanners/` | adapters wrapping Semgrep, Trivy, Grype, Gitleaks, TruffleHog, Checkov, Syft, Nuclei, ZAP |
| `agent/` | Claude Code / Codex harness interface |
| `report/` | SARIF 2.1.0 / JSON / Markdown reporters |

## Required external tools

Adapters shell out to the real binaries and skip gracefully when absent.
Install and verify them with the bundled helper:

```bash
scripts/install-tools.sh            # install all, then verify
scripts/install-tools.sh verify     # just report what is present
scripts/install-tools.sh trivy syft # install specific tools
```

| Category | Tools |
|---|---|
| SAST | `semgrep` |
| SCA | `trivy`, `grype` |
| Secrets | `gitleaks`, `trufflehog` |
| IaC | `checkov` |
| SBOM | `syft` (CycloneDX) |
| DAST (scope-gated) | `nuclei`, `zap` (zap-baseline.py / zap.sh) |
