#!/usr/bin/env bash
# Builds the image with the pinned doona revision and the desktop version.
# Extra arguments are passed to `docker build`, e.g.:
#   ./docker/build.sh --platform linux/arm64 -t lemonvpn:arm64
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
revision="$(sed -n 's/^DOONA_DESKTOP_REVISION=//p' pins.env | tr -d '\r')"
version="$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' app/src-tauri/tauri.conf.json | head -n1)"
registry="${NPM_REGISTRY:-https://registry.npmjs.org}"
[[ -n "$revision" ]] || { echo "missing DOONA_DESKTOP_REVISION in pins.env" >&2; exit 1; }
[[ -n "$version" ]] || { echo "missing version in tauri.conf.json" >&2; exit 1; }
exec docker build \
  -f docker/Dockerfile \
  --build-arg "DOONA_REVISION=$revision" \
  --build-arg "LEMONVPN_VERSION=$version" \
  --build-arg "NPM_REGISTRY=$registry" \
  "$@" .
