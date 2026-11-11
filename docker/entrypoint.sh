#!/usr/bin/env bash
# LemonVPN container entrypoint: prepares credentials, the LAN listener and the
# optional TUN broker, then runs nginx + the engine sidecar under one supervisor.
set -Eeuo pipefail

DATA_DIR="${LEMONVPN_DATA_DIR:-/data}"
ENGINE_PORT="${LEMONVPN_ENGINE_PORT:-18080}"
RESOURCE_DIR="${LEMONVPN_RESOURCE_DIR:-/usr/local/lib/lemonvpn}"
RUN_UID=1000
RUN_GID=1000
SERVICE_BIN="$RESOURCE_DIR/lemonvpn-service"
SERVICE_DIR=/var/lib/lemonvpn/Service
TUN_SOCKET=/run/lemonvpn-tun.sock
LAN_RULE_PREF=8890

BROKER_PID=""
ENGINE_PID=""
NGINX_PID=""
NGINX_LOG_PID=""
FIRST_RUN=0

log() { printf '[lemonvpn] %s\n' "$*" >&2; }

json_escape() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '%s' "$value"
}

random_secret() { openssl rand -hex 16; }

cleanup_lan_rules() {
  local i
  for i in $(seq 1 32); do
    ip rule del pref "$LAN_RULE_PREF" >/dev/null 2>&1 || break
  done
}

add_lan_exclusions() {
  # Keep the LAN (management UI, proxy clients, SSH) on the physical path while
  # TUN owns the default route. 8890 sorts before mihomo's 9000 rules.
  local iface cidr
  while read -r iface cidr; do
    case "$iface" in
      lo|docker*|br-*|veth*|virbr*|tun*|LemonVPN) continue ;;
    esac
    if ip rule add to "$cidr" lookup main pref "$LAN_RULE_PREF" 2>/dev/null; then
      log "TUN: keeping $cidr on the physical route ($iface)"
    fi
  done < <(ip -o -4 addr show scope global 2>/dev/null | awk '{print $2, $4}')
}

maybe_read_secret() {
  # $1 = value, $2 = variable holding a file path
  local value="$1" file_var="$2" file_value=""
  if [[ -n "${!file_var:-}" ]]; then
    [[ -r "${!file_var}" ]] || { log "ERROR: cannot read ${!file_var}"; return 1; }
    file_value="$(<"${!file_var}")"
    printf '%s' "$file_value"
  else
    printf '%s' "$value"
  fi
}

shutdown() {
  local code="${1:-0}"
  trap - TERM INT
  if [[ -n "$NGINX_PID" ]] && kill -0 "$NGINX_PID" 2>/dev/null; then
    kill -TERM "$NGINX_PID" 2>/dev/null || true
    wait "$NGINX_PID" 2>/dev/null || true
  fi
  if [[ -n "$ENGINE_PID" ]] && kill -0 "$ENGINE_PID" 2>/dev/null; then
    # Ask the engine to drop TUN first; ignore failures while stopping.
    curl -sS --max-time 4 -X POST -H 'Content-Type: application/json' \
      -d '{"enabled":false}' "http://127.0.0.1:$ENGINE_PORT/api/v1/tun/set" >/dev/null 2>&1 || true
    kill -TERM "$ENGINE_PID" 2>/dev/null || true
    wait "$ENGINE_PID" 2>/dev/null || true
  fi
  if [[ -n "$NGINX_LOG_PID" ]] && kill -0 "$NGINX_LOG_PID" 2>/dev/null; then
    kill -TERM "$NGINX_LOG_PID" 2>/dev/null || true
    wait "$NGINX_LOG_PID" 2>/dev/null || true
  fi
  if [[ -n "$BROKER_PID" ]] && kill -0 "$BROKER_PID" 2>/dev/null; then
    kill -TERM "$BROKER_PID" 2>/dev/null || true
    wait "$BROKER_PID" 2>/dev/null || true
  fi
  cleanup_lan_rules
  log "Stopped (exit $code)."
  exit "$code"
}

fatal() { log "ERROR: $*"; shutdown 1; }

prepare_credentials() {
  mkdir -p "$DATA_DIR" /run/nginx-auth
  chown "$RUN_UID:$RUN_GID" "$DATA_DIR" 2>/dev/null || true

  local user="${LEMONVPN_UI_USERNAME:-admin}"
  local password
  [[ "$user" != *:* ]] || fatal "LEMONVPN_UI_USERNAME must not contain ':'"
  password="$(maybe_read_secret "${LEMONVPN_UI_PASSWORD:-}" LEMONVPN_UI_PASSWORD_FILE)"
  if [[ -z "$password" ]]; then
    if [[ -s "$DATA_DIR/ui-password" ]]; then
      password="$(<"$DATA_DIR/ui-password")"
    else
      password="$(random_secret)"
      umask 077
      printf '%s' "$password" > "$DATA_DIR/ui-password"
      chown "$RUN_UID:$RUN_GID" "$DATA_DIR/ui-password" 2>/dev/null || true
      FIRST_RUN=1
      log "Generated Web UI password for user '$user'."
    fi
  fi
  [[ -n "$password" && "$password" != *$'\n'* && "$password" != *$'\r'* ]] \
    || fatal "Web UI password must be one line"
  printf '%s:%s\n' "$user" "$(openssl passwd -apr1 "$password")" > /run/nginx-auth/htpasswd
  chmod 755 /run/nginx-auth
  chmod 644 /run/nginx-auth/htpasswd
  if [[ "$FIRST_RUN" == 1 ]]; then
    printf '\n  Web UI: http://<host>:8080/   user=%s  password=%s\n\n' "$user" "$password" >&2
  fi
}

prepare_lan() {
  local file="$DATA_DIR/lan-settings.json"
  local enabled="${LEMONVPN_LAN_ENABLED:-1}"
  local bind="${LEMONVPN_LAN_BIND:-0.0.0.0}"
  local port="${LEMONVPN_LAN_PORT:-18081}"
  local username="${LEMONVPN_LAN_USERNAME:-}"
  local password auth tmp

  [[ "$enabled" == 1 ]] || return 0
  if [[ "${LEMONVPN_LAN_RESEED:-0}" != 1 && -s "$file" ]]; then
    return 0
  fi

  [[ "$bind" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || fatal "Invalid LEMONVPN_LAN_BIND: $bind"
  [[ "$port" =~ ^[0-9]{1,5}$ ]] || fatal "Invalid LEMONVPN_LAN_PORT: $port"

  [[ -n "$username" ]] || username="lemonvpn"
  password="$(maybe_read_secret "${LEMONVPN_LAN_PASSWORD:-}" LEMONVPN_LAN_PASSWORD_FILE)"
  if [[ -z "$password" ]]; then
    if [[ "${LEMONVPN_LAN_ALLOW_ANONYMOUS:-0}" == 1 ]]; then
      :
    else
      password="$(random_secret)"
      FIRST_RUN=1
      log "Generated LAN proxy credentials for user '$username'."
    fi
  fi
  [[ "$password" != *$'\n'* && "$password" != *$'\r'* ]] || fatal "LAN password must be one line"

  auth="null"
  if [[ -n "$username" && -n "$password" ]]; then
    auth="{\"username\":\"$(json_escape "$username")\",\"password\":\"$(json_escape "$password")\"}"
  elif [[ "${LEMONVPN_LAN_ALLOW_ANONYMOUS:-0}" != 1 ]]; then
    die_lan_credentials
  fi

  umask 077
  tmp="$file.tmp"
  printf '{"enabled":true,"bind_address":"%s","port":%s,"authentication":%s}\n' \
    "$(json_escape "$bind")" "$port" "$auth" > "$tmp"
  mv "$tmp" "$file"
  chown "$RUN_UID:$RUN_GID" "$file" 2>/dev/null || true
  if [[ "$FIRST_RUN" == 1 ]]; then
    printf '  Proxy : http://<host>:%s   user=%s  password=%s\n\n' "$port" "$username" "$password" >&2
  fi
}

# Remove policy rules left behind when a previous container was killed before
# its broker could clean up. A TUN device disappears with its process, so a
# present device means another live broker owns this network namespace and we
# must not touch its rules.
cleanup_stale_tun() {
  if ip link show LemonVPN >/dev/null 2>&1; then
    return 1
  fi
  local pref i
  # 8750-8799: broker egress rules; 8890: LAN exclusions; 9000-9010: mihomo.
  for pref in $(seq 8750 8799) 8890 9000 9001 9002 9010; do
    for i in $(seq 1 64); do
      ip rule del pref "$pref" >/dev/null 2>&1 || break
    done
    for i in $(seq 1 64); do
      ip -6 rule del pref "$pref" >/dev/null 2>&1 || break
    done
  done
  # Catch rules that reference mihomo's table or device at other priorities.
  for i in $(seq 1 64); do
    ip rule del lookup 2022 >/dev/null 2>&1 || break
  done
  for i in $(seq 1 64); do
    ip -6 rule del lookup 2022 >/dev/null 2>&1 || break
  done
  for i in $(seq 1 64); do
    ip rule del iif LemonVPN >/dev/null 2>&1 || break
  done
  ip link del LemonVPN >/dev/null 2>&1 || true
  return 0
}

install_tun_service() {
  local parent
  parent="$(dirname "$SERVICE_DIR")"
  mkdir -p "$SERVICE_DIR"
  # The engine runs as uid 1000 and must traverse /var/lib/lemonvpn to see the
  # service registration. prepare_lan sets umask 077 for its credential file,
  # which would otherwise leave this parent directory unreadable to the engine.
  chmod 755 "$parent" "$SERVICE_DIR"
  cp "$SERVICE_BIN" "$RESOURCE_DIR/lemonvpn-kernel" "$SERVICE_DIR/"
  chmod 755 "$SERVICE_DIR/lemonvpn-service" "$SERVICE_DIR/lemonvpn-kernel"
  printf '{"manager":"Standalone","owner":%s}' "$RUN_UID" > "$SERVICE_DIR/service.json"
  chmod 600 "$SERVICE_DIR/service.json"
}

start_engine() {
  setpriv --reuid="$RUN_UID" --regid="$RUN_GID" --init-groups \
    env LEMONVPN_DATA_DIR="$DATA_DIR" \
        LEMONVPN_ENGINE_PORT="$ENGINE_PORT" \
        LEMONVPN_RESOURCE_DIR="$RESOURCE_DIR" \
    /usr/local/bin/lemonvpn-engine \
    2> >(tee -a /tmp/lemonvpn-engine.log >&2) &
  ENGINE_PID=$!

  local i
  for i in $(seq 1 300); do
    if ! kill -0 "$ENGINE_PID" 2>/dev/null; then
      log "Engine exited during startup; last log lines:"
      tail -n 40 /tmp/lemonvpn-engine.log >&2 || true
      fatal "engine exited before becoming healthy"
    fi
    if curl -fsS "http://127.0.0.1:$ENGINE_PORT/health" >/dev/null 2>&1; then
      log "Engine is healthy on 127.0.0.1:$ENGINE_PORT"
      return 0
    fi
    sleep 0.1
  done
  fatal "engine did not become healthy within 30s"
}

enable_tun() {
  local response
  response="$(curl -sS --max-time 20 -X POST -H 'Content-Type: application/json' \
    -d '{"enabled":true}' "http://127.0.0.1:$ENGINE_PORT/api/v1/tun/set")" || response=""
  if [[ "$response" == *'"enabled":true'* ]]; then
    log "TUN enabled: $response"
    return 0
  fi
  log "TUN enable failed: ${response:-no response}"
  if [[ "${LEMONVPN_TUN_STRICT:-1}" == 1 ]]; then
    fatal "TUN was requested but could not be enabled"
  fi
}

start_nginx() {
  touch /tmp/nginx-access.log
  chown "$RUN_UID:$RUN_GID" /tmp/nginx-access.log 2>/dev/null || true
  tail -n 0 -F /tmp/nginx-access.log >&2 &
  NGINX_LOG_PID=$!
  setpriv --reuid="$RUN_UID" --regid="$RUN_GID" --init-groups \
    nginx -g 'daemon off;' &
  NGINX_PID=$!
}

die_lan_credentials() {
  fatal "LAN proxy needs LEMONVPN_LAN_USERNAME/PASSWORD (or LEMONVPN_LAN_ALLOW_ANONYMOUS=1)"
}

trap 'shutdown 0' TERM INT

prepare_credentials
prepare_lan

if [[ "${LEMONVPN_TUN:-0}" == 1 || -c /dev/net/tun ]]; then
  if [[ -c /dev/net/tun ]] && capsh --has-p=cap_net_admin >/dev/null 2>&1; then
    if ! cleanup_stale_tun; then
      if [[ "${LEMONVPN_TUN:-0}" == 1 ]]; then
        fatal "another LemonVPN TUN is active in this network namespace; stop it before starting TUN mode"
      fi
      log "Another LemonVPN TUN is active; skipping broker setup (proxy mode only)."
    else
      log "TUN capabilities found; installing standalone broker."
      install_tun_service
      "$SERVICE_DIR/lemonvpn-service" --run --owner-uid "$RUN_UID" &
      BROKER_PID=$!
      for _ in $(seq 1 100); do
        [[ -S "$TUN_SOCKET" ]] && break
        kill -0 "$BROKER_PID" 2>/dev/null || fatal "TUN broker exited during startup"
        sleep 0.1
      done
      [[ -S "$TUN_SOCKET" ]] || fatal "TUN broker socket did not appear"
    fi
  elif [[ "${LEMONVPN_TUN:-0}" == 1 ]]; then
    fatal "TUN needs /dev/net/tun and CAP_NET_ADMIN; use docker-compose.tun.yml"
  else
    log "TUN unavailable (/dev/net/tun or CAP_NET_ADMIN missing); proxy mode only."
  fi
fi

start_engine

if [[ "${LEMONVPN_TUN:-0}" == 1 ]]; then
  cleanup_lan_rules
  if [[ "${LEMONVPN_TUN_EXCLUDE_LAN:-1}" == 1 ]]; then
    add_lan_exclusions
  fi
  enable_tun
fi

start_nginx

log "Ready: Web UI on 0.0.0.0:8080, LAN proxy on 0.0.0.0:${LEMONVPN_LAN_PORT:-18081}"
printf '  Web UI: http://<host>:8080/   (credentials in /data/ui-password)\n' >&2
printf '  Proxy : http://<host>:%s   (credentials in /data/lan-settings.json)\n' "${LEMONVPN_LAN_PORT:-18081}" >&2

if wait -n "$NGINX_PID" "$ENGINE_PID" ${BROKER_PID:+"$BROKER_PID"}; then
  :
fi
log "A child process exited; shutting down."
shutdown 1
