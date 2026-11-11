#!/usr/bin/env bash
# Clear policy rules left by a LemonVPN TUN session that was killed before it
# could clean up. Run on the Docker host as root.
#
# The entrypoint performs the same cleanup on startup, so this is only needed
# when you want to hand the network back to another TUN (for example the
# desktop app) without starting a new container first.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "tun-cleanup: run as root" >&2
  exit 1
fi

if ip link show LemonVPN >/dev/null 2>&1; then
  echo "tun-cleanup: LemonVPN is still up; stop its owner first" >&2
  exit 1
fi

# 8750-8799: broker egress rules; 8890: LAN exclusions; 9000-9010: mihomo.
for pref in $(seq 8750 8799) 8890 9000 9001 9002 9010; do
  for _ in $(seq 1 64); do ip rule del pref "$pref" >/dev/null 2>&1 || break; done
  for _ in $(seq 1 64); do ip -6 rule del pref "$pref" >/dev/null 2>&1 || break; done
done
# Rules that reference mihomo's table or device at any other priority.
for _ in $(seq 1 64); do ip rule del lookup 2022 >/dev/null 2>&1 || break; done
for _ in $(seq 1 64); do ip -6 rule del lookup 2022 >/dev/null 2>&1 || break; done
for _ in $(seq 1 64); do ip rule del iif LemonVPN >/dev/null 2>&1 || break; done
ip link del LemonVPN >/dev/null 2>&1 || true

echo "tun-cleanup: done"
