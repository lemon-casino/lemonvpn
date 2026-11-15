#!/usr/bin/env bash
# No external connectivity probe: verify this supervisor's local engine only.
set -euo pipefail
pid="$(cat /run/lemonvpn/engine.pid 2>/dev/null)" || exit 1
[[ "$pid" =~ ^[0-9]+$ ]] || exit 1
kill -0 "$pid" 2>/dev/null || exit 1
body="$(curl -fsS --noproxy '*' --connect-timeout 1 --max-time 2 \
  "http://127.0.0.1:${LEMONVPN_ENGINE_PORT:-18080}/health" 2>/dev/null)" || exit 1
[[ "$body" == *\"instance\":\"lemonvpn-$pid\"* ]]
