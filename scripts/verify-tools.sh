#!/usr/bin/env bash
# verify-tools.sh — assert that installed scanners match the PINNED versions.
# Integrity for container builds is enforced at download time (official
# installers verify checksums; the gitleaks tarball is checked against its
# release checksums.txt in the Dockerfile). This script confirms the resulting
# binaries report the expected versions.
set -euo pipefail

# Pinned versions (keep in sync with the Dockerfile ARGs).
declare -A PINNED=(
  [trivy]="0.55.0"
  [grype]="0.79.6"
  [syft]="1.11.1"
  [gitleaks]="8.18.4"
)

fail=0
for tool in "${!PINNED[@]}"; do
  want="${PINNED[$tool]}"
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '  ? %-10s not installed (expected %s)\n' "$tool" "$want"
    continue
  fi
  got="$("$tool" --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
  if [ "$got" = "$want" ]; then
    printf '  \033[1;32m✓\033[0m %-10s %s\n' "$tool" "$got"
  else
    printf '  \033[1;31m✗\033[0m %-10s got %s, expected %s\n' "$tool" "${got:-?}" "$want"
    fail=1
  fi
done
exit "$fail"
