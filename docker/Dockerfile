# syntax=docker/dockerfile:1.7
ARG NODE_IMAGE=node:24-bookworm-slim
ARG RUST_IMAGE=rust:1-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

FROM ${NODE_IMAGE} AS node

FROM ${RUST_IMAGE} AS builder
COPY --from=node /usr/local /usr/local

ARG DEBIAN_FRONTEND=noninteractive
ARG DOONA_REPOSITORY=https://github.com/Zakkaus/doona.git
ARG DOONA_REVISION
ARG LEMONVPN_VERSION=dev
ARG NPM_REGISTRY=https://registry.npmjs.org
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pins.env ./
COPY patches ./patches
COPY app/scripts ./app/scripts
COPY app/branding ./app/branding
COPY sidecar-stub ./sidecar-stub

# The desktop frontend is pinned by revision; CI and local builds pass the same
# value from pins.env. Patch order matches the release workflow.
RUN test -n "$DOONA_REVISION" || { echo "DOONA_REVISION build arg is required" >&2; exit 1; } \
    && git init -q doona \
    && git -C doona remote add origin "$DOONA_REPOSITORY" \
    && git -C doona fetch --depth 1 origin "$DOONA_REVISION" \
    && git -C doona checkout -q FETCH_HEAD \
    && for p in doona-lemonvpn-desktop doona-lemonvpn-proxy-health doona-lemonvpn-lan-sharing doona-lemonvpn-rules-dns; do \
         git -C doona apply --binary --whitespace=nowarn "../patches/$p.patch"; \
       done

RUN npm install -g "pnpm@11.15.1" --registry="$NPM_REGISTRY" \
    && pnpm --dir doona install --frozen-lockfile --registry="$NPM_REGISTRY"

# The About box reads the doona package version; show the LemonVPN release instead.
RUN node -e 'const fs=require("fs");const p="doona/package.json";const v=process.env.LEMONVPN_VERSION;if(v&&v!=="dev"){const j=JSON.parse(fs.readFileSync(p,"utf8"));j.version=v;fs.writeFileSync(p,JSON.stringify(j,null,2)+"\n");console.log("doona version",v)}'

# Builds doona, the engine sidecar, lemonvpn-service, mihomo and the Geo assets.
RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) export TAURI_ENV_TARGET_TRIPLE=x86_64-unknown-linux-gnu ;; \
      arm64) export TAURI_ENV_TARGET_TRIPLE=aarch64-unknown-linux-gnu ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    node app/scripts/prepare.mjs

RUN set -eux; \
    case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu ;; \
      arm64) triple=aarch64-unknown-linux-gnu ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    mkdir -p /out; \
    cp -a app/dist /out/dist; \
    cp "app/src-tauri/binaries/lemonvpn-engine-stub-$triple" /out/lemonvpn-engine; \
    cp app/src-tauri/binaries/lemonvpn-service \
       app/src-tauri/binaries/lemonvpn-kernel \
       app/src-tauri/binaries/geoip.dat \
       app/src-tauri/binaries/geosite.dat \
       /out/; \
    cp app/src-tauri/binaries/*.LICENSE.txt \
       app/src-tauri/binaries/*.manifest.json \
       /out/; \
    chmod 755 /out/lemonvpn-engine /out/lemonvpn-service /out/lemonvpn-kernel

FROM ${RUNTIME_IMAGE}
ARG LEMONVPN_VERSION=dev
ARG TARGETARCH

LABEL org.opencontainers.image.title="LemonVPN" \
      org.opencontainers.image.description="LemonVPN proxy engine with the doona web UI" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.version="${LEMONVPN_VERSION}" \
      org.opencontainers.image.source="https://github.com/lemon-casino/lemonvpn"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      nginx iproute2 procps ca-certificates curl openssl util-linux tini libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --user-group --create-home --home-dir /home/lemonvpn \
         --shell /usr/sbin/nologin lemonvpn

COPY --from=builder /out/ /out/
RUN set -eux; \
    mkdir -p /usr/local/lib/lemonvpn /usr/share/nginx/html; \
    mv /out/lemonvpn-engine /usr/local/bin/lemonvpn-engine; \
    mv /out/lemonvpn-service /out/lemonvpn-kernel /out/geoip.dat /out/geosite.dat \
       /out/*.LICENSE.txt /out/*.manifest.json /usr/local/lib/lemonvpn/; \
    cp -a /out/dist/. /usr/share/nginx/html/; \
    rm -rf /out; \
    chmod 755 /usr/local/bin/lemonvpn-engine \
              /usr/local/lib/lemonvpn/lemonvpn-service \
              /usr/local/lib/lemonvpn/lemonvpn-kernel

COPY docker/nginx.conf /etc/nginx/nginx.conf
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
# A Windows checkout may carry CRLF; the container files are used verbatim.
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh /etc/nginx/nginx.conf \
    && chmod 755 /usr/local/bin/entrypoint.sh

ENV LEMONVPN_DATA_DIR=/data \
    LEMONVPN_ENGINE_PORT=18080 \
    LEMONVPN_RESOURCE_DIR=/usr/local/lib/lemonvpn

VOLUME ["/data"]
EXPOSE 8080 18081
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsS http://127.0.0.1:18080/health >/dev/null || exit 1

# The entrypoint starts as root so it can launch the standalone TUN broker; the
# engine, nginx and all data files run as uid 1000.
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/usr/local/bin/entrypoint.sh"]
