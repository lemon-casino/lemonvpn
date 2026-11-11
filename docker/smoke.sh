#!/usr/bin/env bash
# Proxy-mode smoke test: auth, UI/API, LAN proxy (HTTP + SOCKS5), persistence,
# and a clean stop. Requires Docker and curl on the host.
set -euo pipefail
image="${1:?usage: smoke.sh <image>}"
name="lemonvpn-smoke-$$"
data="$(mktemp -d)"
url="${SMOKE_URL:-https://www.baidu.com}"

cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$data"
}
trap cleanup EXIT

pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

echo "[1/7] start $image"
docker run -d --name "$name" \
  -p 127.0.0.1::8080 -p 127.0.0.1::18081 \
  -v "$data:/data" \
  -e LEMONVPN_UI_PASSWORD=testpass \
  -e LEMONVPN_LAN_USERNAME=u -e LEMONVPN_LAN_PASSWORD=p \
  "$image" >/dev/null

host_ui="$(docker port "$name" 8080/tcp | head -n1 | awk -F: '{print $NF}')"
host_proxy="$(docker port "$name" 18081/tcp | head -n1 | awk -F: '{print $NF}')"
[[ -n "$host_ui" && -n "$host_proxy" ]] || fail "published ports missing"

echo "[2/7] wait for health"
ok=0
for _ in $(seq 1 90); do
  if curl -fsS -u admin:testpass "http://127.0.0.1:$host_ui/api" >/dev/null 2>&1; then ok=1; break; fi
  sleep 1
done
[[ "$ok" == 1 ]] || { docker logs "$name" >&2 || true; fail "UI/API did not become healthy"; }
pass "UI/API reachable"

echo "[3/7] authentication"
code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$host_ui/api")"
[[ "$code" == 401 ]] || fail "unauthenticated API returned $code (expected 401)"
pass "unauthenticated requests are rejected"
curl -fsS -u admin:testpass "http://127.0.0.1:$host_ui/api" | grep -q '"api_major":1' \
  || fail "discovery document missing"
pass "authenticated discovery document"

echo "[4/7] proxy: HTTP CONNECT"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
  -x "http://u:p@127.0.0.1:$host_proxy" "$url")"
[[ "$code" == 200 ]] || fail "HTTP proxy returned $code"
pass "HTTP proxy works"

echo "[5/7] proxy: SOCKS5"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
  --socks5-hostname "u:p@127.0.0.1:$host_proxy" "$url")"
[[ "$code" == 200 ]] || fail "SOCKS5 proxy returned $code"
pass "SOCKS5 proxy works"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
  --socks5-hostname "u:wrong@127.0.0.1:$host_proxy" "$url" || true)"
[[ "$code" != 200 ]] || fail "SOCKS5 accepted a wrong password"
pass "wrong proxy credentials are rejected"

echo "[6/7] persistence"
docker restart "$name" >/dev/null
# An ephemeral host port is reassigned by the restart.
host_ui="$(docker port "$name" 8080/tcp | head -n1 | awk -F: '{print $NF}')"
for _ in $(seq 1 90); do
  curl -fsS -u admin:testpass "http://127.0.0.1:$host_ui/api" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS -u admin:testpass "http://127.0.0.1:$host_ui/api" >/dev/null || fail "API did not return after restart"
[[ -s "$data/lan-settings.json" ]] || fail "LAN settings were not persisted"
pass "container restart keeps settings"

echo "[7/7] stop"
timeout 30 docker stop "$name" >/dev/null || fail "stop timed out"
pass "clean stop"
echo "smoke: OK"
