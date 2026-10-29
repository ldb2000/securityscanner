# Security policy & acceptable use

`sec-scan` is a **defensive** security-audit tool. It is intended to help teams
find, validate, and fix vulnerabilities in code and infrastructure **they own or
are explicitly authorized to test**.

## Acceptable use

- Static analysis (SAST, SCA, secrets, IaC, SBOM) runs read-only against a local
  working tree and requires no special authorization.
- **Active scanning (DAST: `nuclei`, `zap`) is refused** unless an authorization
  scope is supplied via `sec-scan scope` / `--scope`. The scope must record who
  authorized the test, when, and an allow-list of targets. Out-of-scope hosts are
  rejected before any network request is sent, and every active run is written to
  an append-only audit log (`.sec-scan-audit.log`, override with
  `SEC_SCAN_AUDIT_LOG`).
- Remediations are produced as **unified diffs for human review**. Nothing is
  applied without `fix --apply --yes`, and each applied patch is audit-logged.

## Not supported

This project does not ship exploits, payloads, credential harvesting, C2, or any
offensive automation, and must not be used to test systems without authorization.

## Least privilege & active-scan limits

- Scanners are invoked with `execFile` (no shell), so finding/target data is
  never interpreted by a shell.
- The container image runs as a non-root user (`scan`, uid 10001).
- Active (DAST) adapters are **rate-limited and time-boxed** (defaults: 50 req/s,
  300s wall-clock), overridable for authorized engagements via
  `SEC_SCAN_DAST_RATE_LIMIT` and `SEC_SCAN_DAST_TIMEOUT_MS`.
- The scope allow-list supports exact hosts, `*.wildcard` hostnames, and IPv4
  CIDR ranges; any target outside it is rejected before a request is sent.

## Agent-harness safety

The LLM harness (Claude Code / Codex) receives findings as **data, not
instructions**: they are placed inside a fenced, clearly-labeled data block and
the model is instructed never to act on their contents. The harness runs with no
tools during triage and never executes finding content.

## Reporting a vulnerability in sec-scan

Please report suspected vulnerabilities privately to the maintainers rather than
opening a public issue. Include affected version, reproduction steps, and impact.
We aim to acknowledge within a few business days.
