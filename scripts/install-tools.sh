#!/usr/bin/env bash
# install-tools.sh — install and verify the external scanners sec-scan wraps.
#
# Usage:
#   scripts/install-tools.sh            # install all, then verify
#   scripts/install-tools.sh verify     # only check what is present
#   scripts/install-tools.sh <tool>...  # install specific tools
#
# Tools: semgrep trivy grype gitleaks trufflehog checkov syft nuclei zap
#
# Honors SEC_SCAN_BIN_DIR (default: $HOME/.local/bin) for Go/binary installs.
# Safe to re-run; skips tools already on PATH.

set -euo pipefail

BIN_DIR="${SEC_SCAN_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"
export PATH="$BIN_DIR:$PATH"

ALL=(semgrep trivy grype gitleaks trufflehog checkov syft nuclei zap)

have() { command -v "$1" >/dev/null 2>&1; }
log()  { printf '\033[1;34m[install-tools]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[install-tools]\033[0m %s\n' "$*" >&2; }

# Pinned versions (keep in sync with the Dockerfile ARGs and verify-tools.sh).
TRIVY_VERSION="${TRIVY_VERSION:-0.55.0}"
GRYPE_VERSION="${GRYPE_VERSION:-0.79.6}"
SYFT_VERSION="${SYFT_VERSION:-1.11.1}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.18.4}"
SEMGREP_VERSION="${SEMGREP_VERSION:-1.90.0}"
CHECKOV_VERSION="${CHECKOV_VERSION:-3.2.257}"

install_script() { # url [version] -> runs vendor installer into BIN_DIR (installers verify checksums)
  curl -sSfL "$1" | sh -s -- -b "$BIN_DIR" ${2:+"$2"}
}

install_one() {
  local tool="$1"
  if have "$tool" || { [ "$tool" = zap ] && have zap-baseline.py; }; then
    log "$tool already present — skipping"
    return 0
  fi
  log "installing $tool (pinned) ..."
  case "$tool" in
    semgrep)    pipx install "semgrep==$SEMGREP_VERSION" 2>/dev/null || pip install --user "semgrep==$SEMGREP_VERSION" ;;
    checkov)    pipx install "checkov==$CHECKOV_VERSION" 2>/dev/null || pip install --user "checkov==$CHECKOV_VERSION" ;;
    trivy)      install_script https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh "v$TRIVY_VERSION" ;;
    grype)      install_script https://raw.githubusercontent.com/anchore/grype/main/install.sh "v$GRYPE_VERSION" ;;
    syft)       install_script https://raw.githubusercontent.com/anchore/syft/main/install.sh "v$SYFT_VERSION" ;;
    gitleaks)   if have go; then go install "github.com/gitleaks/gitleaks/v8@v$GITLEAKS_VERSION" && cp "$(go env GOPATH)/bin/gitleaks" "$BIN_DIR" 2>/dev/null || true; else warn "need Go for gitleaks"; fi ;;
    trufflehog) install_script https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh ;;
    nuclei)     if have go; then go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && cp "$(go env GOPATH)/bin/nuclei" "$BIN_DIR" 2>/dev/null || true; else warn "need Go for nuclei"; fi ;;
    zap)        warn "ZAP: install Docker image 'ghcr.io/zaproxy/zaproxy:stable' or the desktop package; expose zap-baseline.py on PATH." ;;
    *)          warn "unknown tool: $tool"; return 1 ;;
  esac
}

verify() {
  log "verifying tools on PATH ($BIN_DIR + system):"
  local missing=0
  for t in "${ALL[@]}"; do
    if have "$t"; then
      printf '  \033[1;32m✓\033[0m %-12s %s\n' "$t" "$(command -v "$t")"
    elif [ "$t" = zap ] && have zap-baseline.py; then
      printf '  \033[1;32m✓\033[0m %-12s %s\n' "zap" "$(command -v zap-baseline.py)"
    else
      printf '  \033[1;31m✗\033[0m %-12s (absent — sec-scan will skip this category)\n' "$t"
      missing=$((missing + 1))
    fi
  done
  log "$(( ${#ALL[@]} - missing ))/${#ALL[@]} tools available"
  [ "$missing" -eq 0 ]
}

main() {
  if [ "${1:-}" = verify ]; then verify; exit $?; fi
  local targets=("$@")
  [ ${#targets[@]} -eq 0 ] && targets=("${ALL[@]}")
  for t in "${targets[@]}"; do install_one "$t" || warn "failed: $t"; done
  echo
  verify || warn "some tools are still missing (see messages above)"
}

main "$@"
