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
LAN_RULE_PROTOCOL=243
RUN_DIR=/run/lemonvpn
declare -a LAN_RULE_FAMILIES=()
declare -a LAN_RULE_CIDRS=()

BROKER_PID=""
ENGINE_PID=""
NGINX_PID=""
NGINX_LOG_PID=""
WATCHDOG_PID=""
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
  # Delete the exact rules this supervisor added, not every rule at a shared
  # priority. In particular proxy-only shutdown must never touch host routes.
  local i
  for i in "${!LAN_RULE_CIDRS[@]}"; do
    ip "${LAN_RULE_FAMILIES[$i]}" rule del to "${LAN_RULE_CIDRS[$i]}" \
      lookup main pref "$LAN_RULE_PREF" protocol "$LAN_RULE_PROTOCOL" >/dev/null 2>&1 || true
  done
  LAN_RULE_FAMILIES=()
  LAN_RULE_CIDRS=()
}

add_lan_exclusions() {
  # Keep both address families reachable on the LAN before capture at 9000.
  local family iface cidr
  for family in -4 -6; do
    while read -r iface cidr; do
      case "$iface" in
        lo|docker*|br-*|veth*|virbr*|tun*|LemonVPN) continue ;;
      esac
      if ip "$family" rule add to "$cidr" lookup main pref "$LAN_RULE_PREF" \
          protocol "$LAN_RULE_PROTOCOL" 2>/dev/null; then
        LAN_RULE_FAMILIES+=("$family")
        LAN_RULE_CIDRS+=("$cidr")
        log "TUN: keeping $cidr on the physical route ($iface)"
      else
        fatal "cannot preserve LAN route $cidr ($iface)"
      fi
    done < <(ip -o "$family" addr show scope global 2>/dev/null | awk '{print $2, $4}')
  done
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

stop_child() {
  local pid="$1" grace="$2" deadline=$((SECONDS + $2))
  [[ -n "$pid" ]] || return 0
  kill -TERM "$pid" 2>/dev/null || true
  while kill -0 "$pid" 2>/dev/null; do
    if (( SECONDS >= deadline )); then
      log "Process $pid did not stop in ${grace}s; terminating it."
      kill -KILL "$pid" 2>/dev/null || true
      break
    fi
    sleep 0.1
  done
  wait "$pid" 2>/dev/null || true
}

shutdown() {
  local code="${1:-0}"
  trap - EXIT TERM INT
  stop_child "$WATCHDOG_PID" 1
  stop_child "$NGINX_PID" 3
  if [[ -n "$ENGINE_PID" ]] && kill -0 "$ENGINE_PID" 2>/dev/null; then
    # Only talk to our own listener. A foreign process on this port is never
    # authorized by a successful generic /health response.
    if /usr/local/bin/lemonvpn-healthcheck; then
      curl -sS --noproxy '*' --max-time 4 -X POST -H 'Content-Type: application/json' \
        -d '{"enabled":false}' "http://127.0.0.1:$ENGINE_PORT/api/v1/tun/set" >/dev/null 2>&1 || true
    fi
  fi
  stop_child "$ENGINE_PID" 3
  stop_child "$NGINX_LOG_PID" 1
  stop_child "$BROKER_PID" 18
  if [[ "${LEMONVPN_TUN_GATEWAY:-0}" == 1 ]]; then
    /usr/local/bin/lemonvpn-tun-forward stop || true
  fi
  cleanup_lan_rules
  rm -f "$RUN_DIR/engine.pid"
  log "Stopped (exit $code)."
  exit "$code"
}

fatal() { log "ERROR: $*"; shutdown 1; }

prepare_credentials() {
  mkdir -p "$DATA_DIR" /run/nginx-auth
  chown "$RUN_UID:$RUN_GID" "$DATA_DIR" 2>/dev/null || true

  local user="${LEMONVPN_UI_USERNAME:-admin}"
  local password
  [[ -n "$user" && "$user" != *:* && "$user" != *$'\n'* && "$user" != *$'\r'* ]] \
    || fatal "LEMONVPN_UI_USERNAME must be one line, nonempty and without ':'"
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
  local username="${LEMONVPN_LAN_USERNAME:-lemonvpn}"
  local advertised="${LEMONVPN_LAN_ADVERTISED_ADDRESS:-}"
  local password auth tmp octet first second
  local -a octets

  if [[ "${LEMONVPN_LAN_RESEED:-0}" != 1 && -s "$file" ]]; then
    log "Keeping saved LAN settings; environment changes need LEMONVPN_LAN_RESEED=1."
    return 0
  fi
  [[ "$enabled" == 0 || "$enabled" == 1 ]] || fatal "LEMONVPN_LAN_ENABLED must be 0 or 1"
  [[ "$enabled" == 1 || -s "$file" ]] || return 0
  [[ "$bind" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || fatal "Invalid LEMONVPN_LAN_BIND"
  IFS=. read -ra octets <<< "$bind"
  for octet in "${octets[@]}"; do
    (( 10#$octet <= 255 )) || fatal "Invalid LEMONVPN_LAN_BIND"
  done
  printf -v bind '%d.%d.%d.%d' "$((10#${octets[0]}))" "$((10#${octets[1]}))" \
    "$((10#${octets[2]}))" "$((10#${octets[3]}))"
  first=$((10#${octets[0]})); second=$((10#${octets[1]}))
  [[ "$bind" == 0.0.0.0 ]] || (( first == 10 || (first == 172 && second >= 16 && second <= 31) || (first == 192 && second == 168) )) \
    || fatal "LEMONVPN_LAN_BIND must be 0.0.0.0 or a private IPv4 address"
  [[ "$port" =~ ^[0-9]{1,5}$ ]] || fatal "Invalid LEMONVPN_LAN_PORT"
  port=$((10#$port))
  (( port >= 1024 && port <= 65535 && port != ENGINE_PORT && port != 8080 )) \
    || fatal "LEMONVPN_LAN_PORT must be 1024..65535 and cannot match the engine or UI port"

  local advertised_json=null
  if [[ -n "$advertised" ]]; then
    [[ "$advertised" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || fatal "Invalid LEMONVPN_LAN_ADVERTISED_ADDRESS"
    IFS=. read -ra octets <<< "$advertised"
    for octet in "${octets[@]}"; do (( 10#$octet <= 255 )) || fatal "Invalid LEMONVPN_LAN_ADVERTISED_ADDRESS"; done
    first=$((10#${octets[0]})); second=$((10#${octets[1]}))
    (( first == 10 || (first == 172 && second >= 16 && second <= 31) || (first == 192 && second == 168) )) \
      || fatal "LEMONVPN_LAN_ADVERTISED_ADDRESS must be a private IPv4 address"
    printf -v advertised '%d.%d.%d.%d' "$first" "$second" "$((10#${octets[2]}))" "$((10#${octets[3]}))"
    advertised_json="\"$advertised\""
  fi

  [[ -n "$username" ]] || username="lemonvpn"
  password="$(maybe_read_secret "${LEMONVPN_LAN_PASSWORD:-}" LEMONVPN_LAN_PASSWORD_FILE)"
  if [[ "$enabled" == 1 && -z "$password" && "${LEMONVPN_LAN_ALLOW_ANONYMOUS:-0}" != 1 ]]; then
    password="$(random_secret)"
    FIRST_RUN=1
    log "Generated LAN proxy credentials for user '$username'."
  fi
  # Same limits as engine-core::lan::Settings: reject bad credentials before
  # generating JSON, so a tab/control character never silently disables LAN.
  local LC_ALL=C
  [[ "$username" =~ ^[!-~]+$ && ${#username} -le 128 && "$username" != *:* ]] \
    || fatal "LAN username must be 1..128 visible ASCII characters, without ':'"
  [[ -z "$password" || ( "$password" =~ ^[!-~]+$ && ${#password} -le 128 ) ]] \
    || fatal "LAN password must be 1..128 visible ASCII characters"

  auth="null"
  if [[ -n "$password" ]]; then
    auth="{\"username\":\"$(json_escape "$username")\",\"password\":\"$(json_escape "$password")\"}"
  elif [[ "$enabled" == 1 && "${LEMONVPN_LAN_ALLOW_ANONYMOUS:-0}" != 1 ]]; then
    die_lan_credentials
  fi

  umask 077
  tmp="$file.tmp"
  local enabled_json=false
  [[ "$enabled" == 1 ]] && enabled_json=true
  printf '{"enabled":%s,"bind_address":"%s","port":%s,"authentication":%s,"advertised_address":%s}\n' \
    "$enabled_json" "$(json_escape "$bind")" "$port" "$auth" "$advertised_json" > "$tmp"
  mv "$tmp" "$file"
  chown "$RUN_UID:$RUN_GID" "$file" 2>/dev/null || true
  if [[ "$enabled" == 1 && "$FIRST_RUN" == 1 ]]; then
    printf '  Proxy : http://<host>:%s   user=%s  password=%s\n\n' "$port" "$username" "$password" >&2
  fi
}

# The root broker cleans its own protocol-242 egress journal. Capture rules
# without ownership markers may belong to another VPN, even without a LemonVPN
# interface, so never delete them by priority/table here. The broker rejects
# occupied capture slots before starting its kernel.
prepare_tun_namespace() {
  ! ip link show LemonVPN >/dev/null 2>&1
}

install_tun_service() {
  local parent
  parent="$(dirname "$SERVICE_DIR")"
  mkdir -p "$SERVICE_DIR"
  # The engine runs as uid 1000 and must traverse /var/lib/lemonvpn to see the
  # service registration. prepare_lan sets umask 077 for its credential file,
  # which would otherwise leave this parent directory unreadable to the engine.
  chmod 755 "$parent" "$SERVICE_DIR"
  # A dedicated volume survives container recreation without exposing root
  # runtime configuration and its controller secret to the unprivileged UI.
  install -d -m 700 -o 0 -g 0 "$SERVICE_DIR/runtime"
  cp "$SERVICE_BIN" "$RESOURCE_DIR/lemonvpn-kernel" "$SERVICE_DIR/"
  chmod 755 "$SERVICE_DIR/lemonvpn-service" "$SERVICE_DIR/lemonvpn-kernel"
  printf '{"manager":"Standalone","owner":%s}' "$RUN_UID" > "$SERVICE_DIR/service.json"
  chmod 600 "$SERVICE_DIR/service.json"
}

start_engine() {
  # Send logs straight to Docker's configured rotating driver. A second append-
  # only /tmp log would grow forever despite json-file max-size/max-file.
  setpriv --reuid="$RUN_UID" --regid="$RUN_GID" --init-groups \
    env LEMONVPN_DATA_DIR="$DATA_DIR" \
        LEMONVPN_ENGINE_PORT="$ENGINE_PORT" \
        LEMONVPN_RESOURCE_DIR="$RESOURCE_DIR" \
    /usr/local/bin/lemonvpn-engine &
  ENGINE_PID=$!
  printf '%s\n' "$ENGINE_PID" > "$RUN_DIR/engine.pid"
  chmod 644 "$RUN_DIR/engine.pid"

  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    kill -0 "$ENGINE_PID" 2>/dev/null || fatal "engine exited before becoming healthy (see container logs)"
    if /usr/local/bin/lemonvpn-healthcheck; then
      log "Engine $ENGINE_PID is healthy on 127.0.0.1:$ENGINE_PORT"
      return 0
    fi
    sleep 0.1
  done
  fatal "engine did not become healthy within 30s"
}

enable_tun() {
  local response
  response="$(curl -sS --noproxy '*' --max-time 20 -X POST -H 'Content-Type: application/json' \
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
  # FIFO keeps access logs in the rotating Docker log stream. The parent is
  # root-owned; the unprivileged nginx worker can write only the FIFO itself.
  rm -f "$RUN_DIR/nginx-access.fifo"
  mkfifo -m 600 "$RUN_DIR/nginx-access.fifo"
  chown "$RUN_UID:$RUN_GID" "$RUN_DIR/nginx-access.fifo"
  cat "$RUN_DIR/nginx-access.fifo" >&2 &
  NGINX_LOG_PID=$!
  sed "s/__LEMONVPN_ENGINE_PORT__/$ENGINE_PORT/g" /etc/nginx/nginx.conf > "$RUN_DIR/nginx.conf"
  chmod 644 "$RUN_DIR/nginx.conf"
  setpriv --reuid="$RUN_UID" --regid="$RUN_GID" --init-groups \
    nginx -c "$RUN_DIR/nginx.conf" -g 'daemon off;' &
  NGINX_PID=$!
}

watch_engine() {
  # A live PID can still be hung. Returning from this child wakes wait -n,
  # which runs normal owned-process cleanup before the restart policy applies.
  # This background subshell must not inherit the supervisor's EXIT trap.
  trap - EXIT TERM INT
  local failures=0
  while kill -0 "$ENGINE_PID" 2>/dev/null; do
    sleep 10
    if /usr/local/bin/lemonvpn-healthcheck; then
      failures=0
    else
      failures=$((failures + 1))
      log "Local engine health check failed $failures/3."
      if (( failures >= 3 )); then
        log "Engine stopped responding; requesting container recovery."
        return 1
      fi
    fi
  done
  return 1
}

die_lan_credentials() {
  fatal "LAN proxy needs LEMONVPN_LAN_USERNAME/PASSWORD (or LEMONVPN_LAN_ALLOW_ANONYMOUS=1)"
}

trap 'shutdown 0' TERM INT
trap 'shutdown $?' EXIT

[[ "$ENGINE_PORT" =~ ^[0-9]{1,5}$ ]] || fatal "Invalid LEMONVPN_ENGINE_PORT"
ENGINE_PORT=$((10#$ENGINE_PORT))
(( ENGINE_PORT >= 1024 && ENGINE_PORT <= 65535 && ENGINE_PORT != 8080 )) \
  || fatal "LEMONVPN_ENGINE_PORT must be 1024..65535 and cannot be 8080"
export LEMONVPN_ENGINE_PORT="$ENGINE_PORT"
mkdir -p "$RUN_DIR"
chmod 755 "$RUN_DIR"

prepare_credentials
prepare_lan

if [[ "${LEMONVPN_TUN:-0}" == 1 || -c /dev/net/tun ]]; then
  if [[ -c /dev/net/tun ]] && capsh --has-p=cap_net_admin >/dev/null 2>&1; then
    if ! prepare_tun_namespace; then
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
  if [[ "${LEMONVPN_TUN_GATEWAY:-0}" == 1 ]]; then
    /usr/local/bin/lemonvpn-tun-forward start || fatal "cannot prepare TUN gateway forwarding"
  fi
  enable_tun
fi

start_nginx
watch_engine &
WATCHDOG_PID=$!

log "Ready: Web UI on 0.0.0.0:8080; saved LAN settings remain authoritative."
log "Generated UI password (if any): $DATA_DIR/ui-password; LAN settings: $DATA_DIR/lan-settings.json"

if wait -n "$NGINX_PID" "$ENGINE_PID" "$NGINX_LOG_PID" "$WATCHDOG_PID" ${BROKER_PID:+"$BROKER_PID"}; then
  :
fi
log "A child process exited; shutting down."
shutdown 1
