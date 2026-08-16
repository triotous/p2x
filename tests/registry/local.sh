#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
case_name="all"
while (($#)); do
  case "$1" in
    --case) case_name="${2:?missing case}"; shift 2 ;;
    *) echo "usage: $0 --case <all|valid-tcp|valid-quic|exchange-restart>" >&2; exit 2 ;;
  esac
done
case "$case_name" in
  all|valid-tcp|valid-quic|exchange-restart) ;;
  *) echo "unknown registry case: $case_name" >&2; exit 2 ;;
esac

cd "$root"
cargo build -q --workspace --bins
cargo build -q -p p2x-config --example identity-id

run_id="${P2X_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
artifact_root="${P2X_ARTIFACT_DIR:-$root/target/p2x-registry}/$run_id"
mkdir -p "$artifact_root"
chmod 700 "$artifact_root"

pids=()
secret_dirs=()
cleanup() {
  trap - TERM INT EXIT
  for pid in "${pids[@]:-}"; do kill -INT "$pid" 2>/dev/null || true; done
  for _ in $(seq 1 100); do
    alive=false
    for pid in "${pids[@]:-}"; do kill -0 "$pid" 2>/dev/null && alive=true; done
    [[ "$alive" == false ]] && break
    sleep .05
  done
  for pid in "${pids[@]:-}"; do kill -TERM "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for dir in "${secret_dirs[@]:-}"; do rm -rf "$dir"; done
}
trap cleanup TERM INT EXIT

untrack_pid() {
  local target=$1 kept=() pid
  for pid in "${pids[@]:-}"; do
    [[ "$pid" == "$target" ]] || kept+=("$pid")
  done
  pids=("${kept[@]}")
}

wait_for_json() {
  local file=$1 expression=$2 attempts=${3:-400}
  for _ in $(seq 1 "$attempts"); do
    if [[ -f "$file" ]] && python3 - "$file" "$expression" <<'PY'
import json, sys
path, expression = sys.argv[1:]
try:
    rows = [json.loads(line) for line in open(path) if line.strip().startswith('{')]
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)
raise SystemExit(0 if any(eval(expression, {'__builtins__': {}}, {'row': row}) for row in rows) else 1)
PY
    then return 0; fi
    sleep .05
  done
  return 1
}

free_ports() {
  python3 - <<'PY'
import socket
ports=[]
for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
    sock=socket.socket(socket.AF_INET, kind)
    sock.bind(('127.0.0.1', 0))
    ports.append(sock.getsockname()[1])
    sock.close()
print(*ports)
PY
}

run_case() {
  local current=$1 transport=$2 restart=$3
  local out="$artifact_root/$current"
  local secrets
  secrets=$(mktemp -d "${TMPDIR:-/tmp}/p2x-registry.XXXXXX")
  secret_dirs+=("$secrets")
  chmod 700 "$secrets"
  mkdir -p "$out"

  local exchange_key="$secrets/exchange.key"
  local server_key="$secrets/server.key"
  local client_key="$secrets/client.key"
  local ticket_key="$secrets/ticket.key"
  printf '\001' >"$ticket_key"
  head -c 32 /dev/urandom >>"$ticket_key"
  chmod 600 "$ticket_key"
  local identity_bin="$root/target/debug/examples/identity-id"
  local exchange_peer server_peer client_peer
  exchange_peer=$($identity_bin "$exchange_key" --generate)
  server_peer=$($identity_bin "$server_key" --generate)
  client_peer=$($identity_bin "$client_key" --generate)

  local token_data server_token server_digest client_token client_digest
  token_data=$(python3 - <<'PY'
import base64, hashlib
prefix=b'p2x-fixed-token-v1\0'
def make(name, raw):
    token=base64.urlsafe_b64encode(raw).decode().rstrip('=')
    digest=base64.urlsafe_b64encode(hashlib.sha256(prefix+raw).digest()).decode().rstrip('=')
    return 'p2x1.' + name + '.' + token, digest
print(*make('server', bytes([11])+bytes(range(1,32))), *make('client', bytes([12])+bytes(range(1,32))))
PY
)
  read -r server_token server_digest client_token client_digest <<<"$token_data"
  local now
  now=$(date +%s)
  local credentials="$secrets/credentials.yaml"
  local services="$secrets/services.yaml"
  printf '%s\n' \
    'schema_version: 1' \
    'registration:' \
    '  requested_lease_seconds: 30' \
    '  refresh_seconds: 10' \
    'services:' \
    '  - upstream_id: orders' \
    '    selector:' \
    '      protocol: http' \
    '      metadata: {service: orders}' \
    '    enabled: true' >"$services"
  printf '%s\n' \
    'schema_version: 1' \
    'authorization_revision: 1' \
    'credentials:' \
    '  - credential_id: server' \
    "    token_sha256: \"$server_digest\"" \
    "    peer_id: \"$server_peer\"" \
    '    tenant: registry-test' \
    '    role: server' \
    '    scopes: [register_services, reserve_relay]' \
    '    quota_profile: standard' \
    "    not_before: $((now-60))" \
    "    expires_at: $((now+3600))" \
    '    revoked: false' \
    '  - credential_id: client' \
    "    token_sha256: \"$client_digest\"" \
    "    peer_id: \"$client_peer\"" \
    '    tenant: registry-test' \
    '    role: client' \
    '    scopes: [open_proxy_stream]' \
    '    quota_profile: standard' \
    "    not_before: $((now-60))" \
    "    expires_at: $((now+3600))" \
    '    revoked: false' >"$credentials"

  local tcp_port quic_port exchange_addr
  read -r tcp_port quic_port < <(free_ports)
  if [[ "$transport" == tcp ]]; then
    exchange_addr="/ip4/127.0.0.1/tcp/$tcp_port/p2p/$exchange_peer"
  else
    exchange_addr="/ip4/127.0.0.1/udp/$quic_port/quic-v1/p2p/$exchange_peer"
  fi

  start_exchange() {
    local log=$1
    P2X_RUN_ID="$run_id-$current" "$root/target/debug/p2x-exchange" \
      --identity-file "$exchange_key" --credential-file "$credentials" \
      --ticket-key-file "$ticket_key" \
      --tcp-listen "/ip4/127.0.0.1/tcp/$tcp_port" \
      --quic-listen "/ip4/127.0.0.1/udp/$quic_port/quic-v1" \
      --advertise "$exchange_addr" --case-id "$current" >"$log" 2>&1 &
    exchange_pid=$!
    pids+=("$exchange_pid")
    wait_for_json "$log" "row.get('event') == 'listener_ready'" 400 || {
      echo "$current: exchange did not become ready" >&2; return 1;
    }
  }

  local exchange_log="$out/exchange.ndjson"
  start_exchange "$exchange_log"
  local server_log="$out/server.ndjson"
  P2X_TOKEN="$server_token" P2X_RUN_ID="$run_id-$current" "$root/target/debug/p2x-server" \
    --identity-file "$server_key" --exchange "$exchange_addr" \
    --exchange-peer-id "$exchange_peer" --credential-env P2X_TOKEN \
    --services-file "$services" --case-id "$current" >"$server_log" 2>&1 &
  local server_pid=$!
  pids+=("$server_pid")
  wait_for_json "$server_log" "row.get('event') == 'server_readiness' and row.get('ready') is True" 600 || {
    echo "$current: server never reached registry readiness" >&2; return 1;
  }

  local client_log="$out/client.ndjson"
  local server_circuit="$exchange_addr/p2p-circuit/p2p/$server_peer"
  P2X_TOKEN="$client_token" P2X_RUN_ID="$run_id-$current" "$root/target/debug/p2x-client" \
    --identity-file "$client_key" --exchange "$exchange_addr" \
    --exchange-peer-id "$exchange_peer" --credential-env P2X_TOKEN \
    --server "$server_circuit" --finite-relay-ping --case-id "$current" >"$client_log" 2>&1 &
  local client_pid=$!
  pids+=("$client_pid")
  wait_for_json "$client_log" "row.get('event') == 'terminal' and row.get('code') == 'relay.ping'" 600 || {
    echo "$current: authenticated client relay Ping failed" >&2; return 1;
  }
  wait "$client_pid"
  untrack_pid "$client_pid"

  for _ in $(seq 1 400); do
    ready_count=$(python3 - "$server_log" <<'PY'
import json, sys
count=0
for line in open(sys.argv[1]):
    try: row=json.loads(line)
    except json.JSONDecodeError: continue
    count += row.get('event') == 'server_readiness' and row.get('ready') is True
print(count)
PY
)
    [[ "$ready_count" -ge 2 ]] && break
    sleep .05
  done
  [[ "${ready_count:-0}" -ge 2 ]] || { echo "$current: registration refresh was not observed" >&2; return 1; }

  local recovered=false
  if [[ "$restart" == true ]]; then
    kill -INT "$exchange_pid"
    wait "$exchange_pid"
    untrack_pid "$exchange_pid"
    wait_for_json "$server_log" "row.get('event') == 'server_readiness' and row.get('ready') is False" 400 || {
      echo "$current: readiness loss was not observed" >&2; return 1;
    }
    exchange_log="$out/exchange-restart.ndjson"
    start_exchange "$exchange_log"
    wait_for_json "$server_log" "row.get('event') == 'server_readiness' and row.get('ready') is True and row.get('generation', 0) >= 2" 1200 || {
      echo "$current: same-process recovery was not observed" >&2; return 1;
    }
    recovered=true
  fi

  kill -INT "$server_pid"
  wait "$server_pid"
  untrack_pid "$server_pid"
  wait_for_json "$server_log" "row.get('event') == 'terminal' and row.get('code') == 'shutdown'" 100 || {
    echo "$current: graceful server terminal was not observed" >&2; return 1;
  }
  kill -INT "$exchange_pid" 2>/dev/null || true
  wait "$exchange_pid" 2>/dev/null || true
  untrack_pid "$exchange_pid"

  if grep -R -E "$server_token|$client_token|$server_digest|$client_digest|session_id|orders|service: orders" "$out" >/dev/null 2>&1; then
    echo "$current: private registry material appeared in lifecycle artifacts" >&2
    return 1
  fi

  python3 - "$out" "$current" "$transport" "$server_peer" "$server_pid" "$recovered" <<'PY'
import json, pathlib, sys
out, case, transport, peer, pid, recovered = sys.argv[1:]
rows=[]
for name in ('server.ndjson', 'client.ndjson'):
    for line in open(pathlib.Path(out) / name):
        try: rows.append(json.loads(line))
        except json.JSONDecodeError: pass
ready=[r for r in rows if r.get('event') == 'server_readiness' and r.get('ready') is True]
summary={
    'case': case,
    'passed': True,
    'transport': transport,
    'server_peer_id': peer,
    'server_pid': int(pid),
    'observed_assertions': {
        'authenticated_reserve_register_ready': bool(ready),
        'registration_refresh': len(ready) >= 2,
        'authenticated_client_relay_ping': any(r.get('event') == 'terminal' and r.get('code') == 'relay.ping' for r in rows),
        'graceful_server_shutdown': any(r.get('event') == 'terminal' and r.get('code') == 'shutdown' for r in rows),
        'same_process_exchange_restart_recovery': recovered == 'true',
        'privacy_scan_clean': True,
    },
}
(pathlib.Path(out) / 'summary.json').write_text(json.dumps(summary, sort_keys=True) + '\n')
print(json.dumps(summary, sort_keys=True))
PY
}

case "$case_name" in
  valid-tcp) run_case valid-tcp tcp false ;;
  valid-quic) run_case valid-quic quic false ;;
  exchange-restart) run_case exchange-restart tcp true ;;
  all)
    run_case valid-tcp tcp false
    run_case valid-quic quic false
    run_case exchange-restart tcp true
    ;;
esac
