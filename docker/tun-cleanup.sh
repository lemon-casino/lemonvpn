#!/usr/bin/env bash
# Safely clear tagged LemonVPN egress/LAN rules after its TUN has stopped.
# Untagged capture rules cannot be attributed by priority alone: list them for
# administrator inspection rather than deleting another VPN's policy rules.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "tun-cleanup: run as root" >&2
  exit 1
fi
if ip link show LemonVPN >/dev/null 2>&1; then
  echo "tun-cleanup: LemonVPN is still up; stop its owner first" >&2
  exit 1
fi
for family in -4 -6; do
  for pref in $(seq 8750 8799); do
    for _ in $(seq 1 64); do
      ip "$family" rule del pref "$pref" lookup main protocol 242 >/dev/null 2>&1 || break
    done
  done
  for _ in $(seq 1 64); do
    ip "$family" rule del pref 8890 lookup main protocol 243 >/dev/null 2>&1 || break
  done
done
echo "tun-cleanup: tagged LemonVPN rules cleaned; untagged rules were preserved."
echo "Inspect remaining capture rules with: ip -4 rule show; ip -6 rule show"
