#!/usr/bin/env bash
# Host-network TUN smoke test. WARNING: it changes host routes while running.
# Run it only on a disposable host or with console access. A watchdog stops the
# container after LEMONVPN_TUN_WATCHDOG seconds (default 180).
set -euo pipefail
image="${1:?usage: tun-smoke.sh <image>}"
name="lemonvpn-tun-smoke-$$"
data="$(mktemp -d)"
watchdog="${LEMONVPN_TUN_WATCHDOG:-180}"
watchdog_pid=""

cleanup() {
  [[ -n "$watchdog_pid" ]] && kill "$watchdog_pid" >/dev/null 2>&1 || true
  docker rm -f "$name" >/dev/null 2>&1 || true
  for _ in $(seq 1 32); do ip rule del pref 8890 >/dev/null 2>&1 || break; done
  ip link del LemonVPN >/dev/null 2>&1 || true
  rm -rf "$data"
}
trap cleanup EXIT

pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*" >&2; exit 1; }

[[ -c /dev/net/tun ]] || fail "/dev/net/tun is missing"
command -v capsh >/dev/null || fail "capsh is missing"
capsh --has-p=cap_net_admin >/dev/null || fail "CAP_NET_ADMIN is missing"

echo "[1/6] start host-network TUN container (watchdog ${watchdog}s)"
( sleep "$watchdog"; docker stop "$name" >/dev/null 2>&1 || true ) &
watchdog_pid=$!
docker run -d --name "$name" \
  --network host --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$data:/data" \
  -e LEMONVPN_UI_PASSWORD=testpass \
  -e LEMONVPN_LAN_USERNAME=u -e LEMONVPN_LAN_PASSWORD=p \
  -e LEMONVPN_TUN=1 -e LEMONVPN_TUN_STRICT=1 -e LEMONVPN_TUN_EXCLUDE_LAN=1 \
  "$image" >/dev/null

echo "[2/6] wait for TUN"
ok=0
for _ in $(seq 1 90); do
  if curl -fsS -u admin:testpass http://127.0.0.1:8080/api/v1/tun 2>/dev/null | grep -q '"enabled":true'; then ok=1; break; fi
  sleep 1
done
[[ "$ok" == 1 ]] || { docker logs "$name" >&2 || true; fail "TUN did not become active"; }
pass "engine reports TUN enabled"

echo "[3/6] device and rules"
ip link show LemonVPN >/dev/null 2>&1 || fail "TUN device is missing"
ip rule | grep -q '^9000:' || fail "mihomo rule 9000 is missing"
ip rule | grep -q '^8890:' || fail "LAN exclusion rule 8890 is missing"
pass "TUN device and policy rules exist"

echo "[4/6] host egress through TUN"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 "${SMOKE_URL:-https://www.baidu.com}")"
[[ "$code" == 200 ]] || fail "host egress returned $code"
pass "host traffic still reaches the internet"

echo "[5/6] UI/proxy remain reachable from the LAN path"
curl -fsS -u admin:testpass http://127.0.0.1:8080/api >/dev/null || fail "UI API unreachable"
code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 30 \
  -x "http://u:p@127.0.0.1:18081" "${SMOKE_URL:-https://www.baidu.com}")"
[[ "$code" == 200 ]] || fail "LAN proxy returned $code"
pass "UI and LAN proxy still work with TUN enabled"

echo "[6/6] stop and verify cleanup"
timeout 30 docker stop "$name" >/dev/null || fail "stop timed out"
for _ in $(seq 1 40); do
  ip link show LemonVPN >/dev/null 2>&1 || break
  sleep 0.25
done
ip link show LemonVPN >/dev/null 2>&1 && fail "TUN device survived the stop"
ip rule | grep -Eq '^(9000|8890):' && fail "policy rules survived the stop"
pass "TUN routes and rules are cleaned up"
echo "tun-smoke: OK"
