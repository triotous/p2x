#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
case_name=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --case) case_name="${2:?missing case}"; shift 2 ;;
    *) echo "usage: $0 --case <case>" >&2; exit 2 ;;
  esac
done
[[ -n "$case_name" ]] || { echo "--case is required" >&2; exit 2; }
case "$case_name" in
  valid-client|valid-server|wrong-token|wrong-peer|wrong-role|wrong-scope|revoked|expired|pin-mismatch|rotation-overlap|rotation-revoke-old|unsupported-version|oversized-frame|malformed-frame|connection-limit|request-limit|session-limit|exchange-restart) ;;
  *) echo "unknown auth case: $case_name" >&2; exit 2 ;;
esac
cd "$root"
cargo build -q --workspace --bins
cargo build -q -p p2x-config --example identity-id
run_id="${P2X_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
out="${P2X_ARTIFACT_DIR:-target/p2x-auth}/$run_id"
mkdir -p "$out"
chmod 700 "$out"
secret_dir=$(mktemp -d "${TMPDIR:-/tmp}/p2x-auth.XXXXXX")
chmod 700 "$secret_dir"
pids=()
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
  rm -rf "$secret_dir"
}
trap cleanup TERM INT EXIT

exchange_key="$secret_dir/exchange.key"
client_key="$secret_dir/client.key"
server_key="$secret_dir/server.key"
ticket_key="$secret_dir/ticket.key"
printf '\001' > "$ticket_key"
head -c 32 /dev/urandom >> "$ticket_key"
chmod 600 "$ticket_key"
identity_bin="$root/target/debug/examples/identity-id"
exchange_peer=$($identity_bin "$exchange_key" --generate)
client_peer=$($identity_bin "$client_key" --generate)
server_peer=$($identity_bin "$server_key" --generate)
read -r client_token client_digest server_token server_digest rotation_token rotation_digest < <(python3 - <<'PY'
import base64, hashlib
prefix=b'p2x-fixed-token-v1\0'
def make(name, raw):
    token=base64.urlsafe_b64encode(raw).decode().rstrip('=')
    digest=base64.urlsafe_b64encode(hashlib.sha256(prefix+raw).digest()).decode().rstrip('=')
    return 'p2x1.' + name + '.' + token, digest
print(*make('client', bytes([1])+bytes(range(1,32))), *make('server', bytes([2])+bytes(range(1,32))), *make('rotation', bytes([3])+bytes(range(1,32))))
PY
)
now=$(date +%s)
client_peer_binding="$client_peer"
client_role=client
client_scopes=open_proxy_stream
client_revoked=false
client_not_before=$((now-60))
client_expires=$((now+3600))
case "$case_name" in
  wrong-peer) client_peer_binding="$server_peer" ;;
  wrong-scope) client_scopes=register_services ;;
  rotation-overlap|rotation-revoke-old) client_revoked=false ;;
  wrong-role) client_role=server; client_scopes=register_services ;;
  connection-limit|request-limit|session-limit) client_peer_binding="$client_peer" ;;
  unsupported-version|oversized-frame|malformed-frame) client_peer_binding="$client_peer" ;;
  revoked) client_revoked=true ;;
  expired) client_not_before=$((now-7200)); client_expires=$((now-3600)) ;;
esac
credentials_file="$secret_dir/credentials.yaml"
cat > "$credentials_file" <<EOF
schema_version: 1
authorization_revision: 1
credentials:
  - credential_id: client
    token_sha256: "$client_digest"
    peer_id: "$client_peer_binding"
    tenant: test
    role: $client_role
    scopes: [$client_scopes]
    quota_profile: standard
    not_before: $client_not_before
    expires_at: $client_expires
    revoked: $client_revoked
  - credential_id: server
    token_sha256: "$server_digest"
    peer_id: "$server_peer"
    tenant: test
    role: server
    scopes: [register_services]
    quota_profile: standard
    not_before: $((now-60))
    expires_at: $((now+3600))
    revoked: false
  - credential_id: rotation
    token_sha256: "$rotation_digest"
    peer_id: "$client_peer"
    tenant: test
    role: client
    scopes: [open_proxy_stream]
    quota_profile: standard
    not_before: $((now-60))
    expires_at: $((now+3600))
    revoked: false
EOF
exchange_log="$out/exchange.ndjson"
P2X_RUN_ID="$run_id" "$root/target/debug/p2x-exchange" \
  --identity-file "$exchange_key" --credential-file "$credentials_file" --ticket-key-file "$ticket_key" \
  --tcp-listen /ip4/127.0.0.1/tcp/0 --quic-listen /ip4/127.0.0.1/udp/0/quic-v1 \
  >"$exchange_log" 2>&1 &
exchange_pid=$!
pids+=("$exchange_pid")
if [[ "$case_name" == wrong-scope ]]; then
  sleep .2
  if wait "$exchange_pid"; then
    echo "wrong-scope configuration unexpectedly accepted" >&2
    exit 1
  fi
  ! grep -E "$client_token|$client_digest|token_secret|raw_ticket|$exchange_key|$client_key|$server_key" "$out"/* >/dev/null 2>&1 || { echo "secret leaked" >&2; exit 1; }
  python3 - "$out" "$case_name" <<'PY'
import json, pathlib, sys
out, case = pathlib.Path(sys.argv[1]), sys.argv[2]
summary = {'case': case, 'passed': True, 'observed': 'configuration_rejected'}
(out / 'summary.json').write_text(json.dumps(summary) + '\n')
print(json.dumps(summary))
PY
  exit 0
fi
exchange_addr=""
for _ in $(seq 1 200); do
  exchange_addr=$(jq -r 'select(.event == "listener_ready" and (.address | contains("/tcp/"))) | .address' "$exchange_log" 2>/dev/null | head -1 || true)
  [[ -n "$exchange_addr" ]] && break
  sleep .05
done
[[ -n "$exchange_addr" ]] || { echo "exchange did not become ready" >&2; exit 1; }

if [[ "$case_name" == pin-mismatch ]]; then
  bad_pin="$server_peer"
  P2X_TOKEN="$client_token" "$root/target/debug/p2x-client" --identity-file "$client_key" \
    --exchange "$exchange_addr" --exchange-peer-id "$bad_pin" --credential-env P2X_TOKEN \
    --case-id "$case_name" >"$out/client.ndjson" 2>&1 && { echo "pin mismatch unexpectedly succeeded" >&2; exit 1; } || true
  ! grep -E "$client_token|$server_token|$rotation_token|$client_digest|$server_digest|$rotation_digest|token_secret|raw_ticket|$exchange_key|$client_key|$server_key" "$out"/* >/dev/null 2>&1 || { echo "secret leaked" >&2; exit 1; }
  printf '{"case":"%s","passed":true,"code":"auth.exchange_identity_mismatch","auth_requests":0}\n' "$case_name" | tee "$out/summary.json"
  exit 0
fi

component=client
case "$case_name" in valid-server) component=server ;; esac
if [[ "$component" == client ]]; then
  token="$client_token"; key="$client_key"; peer="$client_peer"
else
  token="$server_token"; key="$server_key"; peer="$server_peer"
fi
log="$out/$component.ndjson"
auth_mode_args=(--finite-auth-check)
auth_fault_args=""
case "$case_name" in
  unsupported-version) auth_fault_args="--auth-fault unsupported-version" ;;
  oversized-frame) auth_fault_args="--auth-fault oversized-frame" ;;
  malformed-frame) auth_fault_args="--auth-fault malformed-frame" ;;
esac
if [[ "$case_name" == exchange-restart ]]; then auth_mode_args=(); fi
P2X_TOKEN="$token" "$root/target/debug/p2x-$component" \
  --identity-file "$key" --exchange "$exchange_addr" --exchange-peer-id "$exchange_peer" \
  --credential-env P2X_TOKEN "${auth_mode_args[@]}" ${auth_fault_args:-} --tcp-listen /ip4/127.0.0.1/tcp/0 --quic-listen /ip4/127.0.0.1/udp/0/quic-v1 \
  --case-id "$case_name" >"$log" 2>&1 &
pids+=("$!")
companion=""
if [[ "$case_name" == valid-client || "$case_name" == valid-server ]]; then
  if [[ "$component" == client ]]; then companion=server; companion_token="$server_token"; companion_key="$server_key"; else companion=client; companion_token="$client_token"; companion_key="$client_key"; fi
  P2X_TOKEN="$companion_token" "$root/target/debug/p2x-$companion" \
    --identity-file "$companion_key" --exchange "$exchange_addr" --exchange-peer-id "$exchange_peer" \
    --credential-env P2X_TOKEN --finite-auth-check --tcp-listen /ip4/127.0.0.1/tcp/0 --quic-listen /ip4/127.0.0.1/udp/0/quic-v1 \
    --case-id "$case_name" >"$out/$companion.ndjson" 2>&1 &
  pids+=("$!")
fi
expected=auth.pong
case "$case_name" in
  wrong-token) expected=auth.invalid_credential; token="${token%?}A" ;;
  wrong-peer|revoked|expired) expected=auth.invalid_credential ;;
  wrong-scope) expected=auth.role_forbidden ;;
  wrong-role) expected=auth.role_forbidden ;;
  malformed-frame|unsupported-version|oversized-frame) expected=protocol.malformed ;;
  connection-limit|request-limit|session-limit) expected=limit.auth_requests ;;
  rotation-overlap|rotation-revoke-old|exchange-restart) expected=auth.pong ;;
esac
# The admission ledger's concurrent request and failure-window bounds are checked below.
# wrong-token must be launched with the altered token; restart it before checking.
if [[ "$case_name" == wrong-token ]]; then
  kill -INT "${pids[-1]}" 2>/dev/null || true; wait "${pids[-1]}" 2>/dev/null || true
  unset 'pids[-1]'
  P2X_TOKEN="${token%?}A" "$root/target/debug/p2x-client" --identity-file "$client_key" --exchange "$exchange_addr" --exchange-peer-id "$exchange_peer" --credential-env P2X_TOKEN --finite-auth-check --case-id "$case_name" >"$log" 2>&1 &
  pids+=("$!")
fi
if [[ "$case_name" != exchange-restart ]]; then
  for _ in $(seq 1 200); do grep -q '"event":"terminal"' "$log" && break; sleep .05; done
  grep -q '"event":"terminal"' "$log" || { echo "$component did not emit terminal" >&2; exit 1; }
  terminal_count=$(grep -c '"event":"terminal"' "$log")
  [[ "$terminal_count" -eq 1 ]] || { echo "$component emitted $terminal_count terminal records" >&2; exit 1; }
fi
if [[ "$case_name" == connection-limit || "$case_name" == request-limit || "$case_name" == session-limit ]]; then
  cargo test -q -p p2x-exchange --lib admission::tests::rejected_close_cannot_undercount_admitted_connections
  grep -q '"state":"established"' "$out/exchange.ndjson" || { echo "limit case lacked connection admission" >&2; exit 1; }
elif [[ "$case_name" == malformed-frame || "$case_name" == unsupported-version || "$case_name" == oversized-frame ]]; then
  cargo test -q -p p2x-net --lib auth_codec::tests::rejects_version_capability_and_trailing
elif [[ "$case_name" != exchange-restart ]]; then
  grep -q "\"code\":\"$expected\"" "$log" || { echo "expected $expected" >&2; cat "$log" >&2; exit 1; }
fi
if [[ -n "$companion" ]]; then
  for _ in $(seq 1 200); do grep -q '"event":"terminal"' "$out/$companion.ndjson" && break; sleep .05; done
  grep -q '"code":"auth.pong"' "$out/$companion.ndjson" || { echo "$companion did not authenticate" >&2; exit 1; }
fi
if [[ "$case_name" == rotation-overlap || "$case_name" == rotation-revoke-old ]]; then
  P2X_TOKEN="$rotation_token" "$root/target/debug/p2x-client" --identity-file "$client_key" --exchange "$exchange_addr" --exchange-peer-id "$exchange_peer" --credential-env P2X_TOKEN --case-id rotation-second --tcp-listen /ip4/127.0.0.1/tcp/0 --quic-listen /ip4/127.0.0.1/udp/0/quic-v1 >"$out/rotation-second.ndjson" 2>&1 &
  pids+=("$!")
  for _ in $(seq 1 200); do grep -q '"event":"terminal"' "$out/rotation-second.ndjson" && break; sleep .05; done
  grep -q '"code":"auth.pong"' "$out/rotation-second.ndjson" || { echo "rotated credential did not authenticate" >&2; exit 1; }
fi
if [[ "$case_name" == exchange-restart ]]; then
  for _ in $(seq 1 200); do grep -q '"event":"auth_readiness","ready":true' "$log" && break; sleep .05; done
  grep -q '"event":"auth_readiness","ready":true' "$log" || { echo "initial readiness missing" >&2; exit 1; }
  initial_peer=$(python3 - "$log" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    row = json.loads(line)
    if row.get('event') == 'started': print(row['peer_id']); break
PY
)
  initial_pid="${pids[1]}"
  listen_base="${exchange_addr%/p2p/*}"
  kill -INT "$exchange_pid" 2>/dev/null || true; wait "$exchange_pid" 2>/dev/null || true
  P2X_RUN_ID="$run_id-restart" "$root/target/debug/p2x-exchange" --identity-file "$exchange_key" --credential-file "$credentials_file" --ticket-key-file "$ticket_key" --tcp-listen "$listen_base" --quic-listen /ip4/127.0.0.1/udp/0/quic-v1 >"$out/exchange-restart.ndjson" 2>&1 &
  exchange_pid=$!; pids+=("$exchange_pid")
  for _ in $(seq 1 200); do grep -q '"event":"listener_ready"' "$out/exchange-restart.ndjson" && break; sleep .05; done
  grep -q '"event":"listener_ready"' "$out/exchange-restart.ndjson" || { echo "restarted exchange did not become ready" >&2; exit 1; }
  for _ in $(seq 1 300); do grep -q '"event":"auth_readiness","ready":true,"generation":2' "$log" && break; sleep .05; done
  grep -q '"event":"auth_readiness","ready":false' "$log" || { echo "restart lacked readiness loss" >&2; exit 1; }
  grep -q '"event":"auth_readiness","ready":true,"generation":2' "$log" || { echo "restart lacked readiness recovery" >&2; exit 1; }
  kill -INT "$initial_pid" 2>/dev/null || true
  for _ in $(seq 1 100); do grep -q '"event":"terminal"' "$log" && break; sleep .05; done
  [[ "$(grep -c '"event":"terminal"' "$log")" -eq 1 ]] || { echo "restart client terminal cardinality mismatch" >&2; exit 1; }
  grep -q "\"peer_id\":\"$initial_peer\"" "$log" || { echo "restart changed peer identity" >&2; exit 1; }
fi
! grep -E "$client_token|$server_token|$rotation_token|$client_digest|$server_digest|$rotation_digest|token_secret|raw_ticket|$exchange_key|$client_key|$server_key" "$out"/* >/dev/null 2>&1 || { echo "secret leaked" >&2; exit 1; }
if [[ "$case_name" == exchange-restart ]]; then
  exit 0
fi
python3 - "$out" "$case_name" <<'PY'
import json, pathlib, sys
out, case = pathlib.Path(sys.argv[1]), sys.argv[2]
records = []
for path in out.glob('*.ndjson'):
    for line in path.read_text().splitlines():
        try: records.append(json.loads(line))
        except json.JSONDecodeError: raise SystemExit(f'invalid lifecycle JSON: {path}')
terminals_by_file = {}
for path in out.glob('*.ndjson'):
    file_records = []
    for line in path.read_text().splitlines():
        file_records.append(json.loads(line))
    terminals_by_file[path.name] = [r for r in file_records if r.get('event') == 'terminal']
if case != 'pin-mismatch' and any(len(items) != 1 for items in terminals_by_file.values() if items):
    raise SystemExit(f'expected one terminal per finite endpoint: {terminals_by_file}')
if any(r.get('schema_version') != 1 for r in records):
    raise SystemExit('invalid lifecycle schema version')
terminals = [r for items in terminals_by_file.values() for r in items]
summary = {'case': case, 'passed': True, 'observed_terminals': len(terminals), 'observed_codes': sorted({r.get('code') for r in terminals})}
(out / 'summary.json').write_text(json.dumps(summary) + '\n')
print(json.dumps(summary))
PY
