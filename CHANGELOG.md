# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Packaging & distribution: scoped npm package `@ldb2000/sec-scan` with `bin`,
  `files`, and `publishConfig`; `npm run bundle` produces a self-contained CLI.
- Container image with pinned, checksum-verified scanners.
- `scripts/verify-tools.sh` to assert pinned scanner versions.
- Release workflow publishing to npm on a version tag.
- Composite GitHub Action, GitLab example, and documented CI exit codes.

## [0.1.0] - 2026-10-29

### Added
- Core engine (identify → validate → remediate) with SARIF 2.1.0 model.
- Scanner adapters: semgrep, trivy, grype, gitleaks, trufflehog, checkov, syft,
  nuclei, zap (DAST adapters gated by an authorization scope).
- Agent harness (Claude Code / Codex) for triage and human-reviewed fixes.
- Baseline/suppressions, `.sec-scan.json` config with severity profiles and
  per-tool rule filters.
- Authorization scope with CIDR/wildcard matching; active-scan audit log and
  rate-limit/time-box.
- Test suite with vulnerable fixtures, mock binaries, and a coverage gate.

[Unreleased]: https://github.com/ldb2000/securityscanner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ldb2000/securityscanner/releases/tag/v0.1.0
