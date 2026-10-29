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

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git python3 python3-pip tar \
    && rm -rf /var/lib/apt/lists/*

# Semgrep + Checkov (Python)
RUN pip3 install --no-cache-dir --break-system-packages semgrep checkov

# Trivy, Grype, Syft (official installers, pinned)
RUN curl -sSfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v${TRIVY_VERSION} \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin v${GRYPE_VERSION} \
    && curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b /usr/local/bin v${SYFT_VERSION}

# Gitleaks (pinned release tarball)
RUN curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks

WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY scripts ./scripts

ENTRYPOINT ["node", "dist/cli/src/index.js"]
CMD ["--help"]
