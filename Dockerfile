# sec-scan runtime image with the common scanners preinstalled and pinned.
# Build:  docker build -t sec-scan .
# Run:    docker run --rm -v "$PWD:/src" sec-scan scan /src --only sast,sca,secrets

FROM node:20-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci
COPY cli ./cli
COPY core ./core
COPY scanners ./scanners
COPY agent ./agent
COPY report ./report
RUN npm run build && npm prune --omit=dev

FROM node:20-bookworm-slim
LABEL org.opencontainers.image.title="sec-scan" \
      org.opencontainers.image.description="Defensive security-audit CLI (identify -> validate -> remediate)"

# Pinned scanner versions for reproducible scans.
ARG TRIVY_VERSION=0.55.0
ARG GRYPE_VERSION=0.79.6
ARG SYFT_VERSION=1.11.1
ARG GITLEAKS_VERSION=8.18.4
ARG SEMGREP_VERSION=1.90.0
ARG CHECKOV_VERSION=3.2.257

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git python3 python3-pip tar \
    && rm -rf /var/lib/apt/lists/*

# Semgrep + Checkov (Python), pinned
RUN pip3 install --no-cache-dir --break-system-packages \
      "semgrep==${SEMGREP_VERSION}" "checkov==${CHECKOV_VERSION}"

# Trivy, Grype, Syft (official installers verify their own checksums, pinned)
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${TRIVY_VERSION} \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin v${GRYPE_VERSION} \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b /usr/local/bin v${SYFT_VERSION}

# Gitleaks (pinned release tarball), integrity verified against the release checksums.txt
RUN cd /tmp \
    && curl -sSfL -O "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    && curl -sSfL -O "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_checksums.txt" \
    && grep "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" | sha256sum -c - \
    && tar -xz -C /usr/local/bin -f "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" gitleaks \
    && rm -f gitleaks_${GITLEAKS_VERSION}_*

# Confirm the installed binaries match the pinned versions.
COPY scripts/verify-tools.sh /usr/local/bin/verify-tools.sh
RUN chmod +x /usr/local/bin/verify-tools.sh && /usr/local/bin/verify-tools.sh

WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY scripts ./scripts

# Run as an unprivileged user (no capabilities needed for scanning).
RUN useradd --system --uid 10001 --create-home --home-dir /home/scan scan \
    && chown -R scan:scan /app
USER scan

ENTRYPOINT ["node", "dist/cli/src/index.js"]
CMD ["--help"]
