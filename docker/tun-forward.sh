#!/usr/bin/env bash
# Owned forwarding exceptions for Docker hosts with a DROP forwarding policy.
# Do not alter the host policy, enable forwarding or add NAT masquerading.
set -euo pipefail

action="${1:-}"
[[ "$action" == start || "$action" == stop ]] || exit 2
tag=lemonvpn-tun-gateway

rule() {
  local tool="$1"; shift
  local -a spec=("$@" -m comment --comment "$tag" -j ACCEPT)
  if [[ "$action" == start ]]; then
    "$tool" -w 5 -C FORWARD "${spec[@]}" 2>/dev/null || "$tool" -w 5 -I FORWARD 1 "${spec[@]}"
  else
    for _ in $(seq 1 16); do
      "$tool" -w 5 -D FORWARD "${spec[@]}" 2>/dev/null || break
    done
  fi
}

for family in 4 6; do
  tool=iptables; [[ "$family" == 4 ]] || tool=ip6tables
  if [[ "$action" == start ]]; then
    if [[ "$family" == 4 ]]; then
      [[ "$(cat /proc/sys/net/ipv4/ip_forward)" == 1 ]] || {
        echo 'TUN gateway needs host net.ipv4.ip_forward=1' >&2; exit 1;
      }
    elif [[ ! -r /proc/sys/net/ipv6/conf/all/forwarding ]] || [[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding)" != 1 ]]; then
      # IPv6 stays disabled until the host administrator enables forwarding.
      continue
    fi
  fi
  command -v "$tool" >/dev/null || { [[ "$action" == stop ]] && continue; exit 1; }
  # Only private LAN/container clients may use this gateway exception.
  # Keep public inbound traffic subject to the host's existing policy.
  if [[ "$family" == 4 ]]; then
    ranges=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16)
  else
    ranges=(fc00::/7)
  fi
  for cidr in "${ranges[@]}"; do
    rule "$tool" -s "$cidr" -o LemonVPN
    rule "$tool" -d "$cidr" -i LemonVPN -m conntrack --ctstate ESTABLISHED,RELATED
  done
done
