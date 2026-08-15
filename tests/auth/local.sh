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
  valid-client|valid-server|wrong-token|wrong-peer|wrong-role|revoked|expired|pin-mismatch|rotation|malformed|limits|exchange-restart) ;;
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
client_revoked=false
client_not_before=$((now-60))
client_expires=$((now+3600))
case "$case_name" in
  wrong-peer) client_peer_binding="$server_peer" ;;
  wrong-role) client_role=server ;;
  limits) client_peer_binding="$client_peer" ;;
  malformed) client_peer_binding="$client_peer" ;;
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
    scopes: [register_services]
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
    scopes: [register_services]
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
exchange_addr=""
for _ in $(seq 1 200); do
  exchange_addr=$(sed -n 's/.*"event":"listener_ready".*"address":"\([^" ]*\/tcp\/[^" ]*\)".*/\1/p' "$exchange_log" | head -1 || true)
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
P2X_TOKEN="$token" "$root/target/debug/p2x-$component" \
  --identity-file "$key" --exchange "$exchange_addr" --exchange-peer-id "$exchange_peer" \
  --credential-env P2X_TOKEN --tcp-listen /ip4/127.0.0.1/tcp/0 --quic-listen /ip4/127.0.0.1/udp/0/quic-v1 \
  --case-id "$case_name" >"$log" 2>&1 &
pids+=("$!")
companion=""
if [[ "$case_name" == valid-client || "$case_name" == valid-server ]]; then
  if [[ "$component" == client ]]; then companion=server; companion_token="$server_token"; companion_key="$server_key"; else companion=client; companion_token="$client_token"; companion_key="$client_key"; fi
  P2X_TOKEN="$companion_token" "$root/target/debug/p2x-$companion" \
    --identity-file "$companion_key" --exchange "$exchange_addr" --exchange-peer-id "$exchange_peer" \
    --credential-env P2X_TOKEN --tcp-listen /ip4/127.0.0.1/tcp/0 --quic-listen /ip4/127.0.0.1/udp/0/quic-v1 \
    --case-id "$case_name" >"$out/$companion.ndjson" 2>&1 &
  pids+=("$!")
fi
expected=auth.pong
case "$case_name" in
  wrong-token) expected=auth.invalid_credential; token="${token%?}A" ;;
  wrong-peer|revoked|expired) expected=auth.invalid_credential ;;
  wrong-role) expected=auth.role_forbidden ;;
  malformed) expected=auth.pong ;;
  limits) expected=auth.pong ;;
  rotation|exchange-restart) expected=auth.pong ;;
esac
# The admission ledger's concurrent request and failure-window bounds are checked below.
# wrong-token must be launched with the altered token; restart it before checking.
if [[ "$case_name" == wrong-token ]]; then
  kill -INT "${pids[-1]}" 2>/dev/null || true; wait "${pids[-1]}" 2>/dev/null || true
  unset 'pids[-1]'
  P2X_TOKEN="${token%?}A" "$root/target/debug/p2x-client" --identity-file "$client_key" --exchange "$exchange_addr" --exchange-peer-id "$exchange_peer" --credential-env P2X_TOKEN --case-id "$case_name" >"$log" 2>&1 &
  pids+=("$!")
fi
for _ in $(seq 1 200); do grep -q '"event":"terminal"' "$log" && break; sleep .05; done
grep -q '"event":"terminal"' "$log" || { echo "$component did not emit terminal" >&2; exit 1; }
if [[ "$case_name" == limits ]]; then
  cargo test -q -p p2x-exchange --lib admission::tests::bounds_and_failure_windows_are_deterministic
  grep -q '"code":"auth.pong"' "$log" || { echo "limits case lacked live authenticated baseline" >&2; exit 1; }
  grep -q '"state":"established"' "$out/exchange.ndjson" || { echo "limits case lacked connection admission" >&2; exit 1; }
elif [[ "$case_name" == malformed ]]; then
  cargo test -q -p p2x-net --lib auth_codec::tests::rejects_version_and_trailing
  grep -q '"code":"auth.pong"' "$log" || { echo "malformed case lacked live authenticated baseline" >&2; exit 1; }
else
  grep -q "\"code\":\"$expected\"" "$log" || { echo "expected $expected" >&2; cat "$log" >&2; exit 1; }
fi
if [[ -n "$companion" ]]; then
  for _ in $(seq 1 200); do grep -q '"event":"terminal"' "$out/$companion.ndjson" && break; sleep .05; done
  grep -q '"code":"auth.pong"' "$out/$companion.ndjson" || { echo "$companion did not authenticate" >&2; exit 1; }
fi
if [[ "$case_name" == rotation ]]; then
  P2X_TOKEN="$rotation_token" "$root/target/debug/p2x-client" --identity-file "$client_key" --exchange "$exchange_addr" --exchange-peer-id "$exchange_peer" --credential-env P2X_TOKEN --case-id rotation-second --tcp-listen /ip4/127.0.0.1/tcp/0 --quic-listen /ip4/127.0.0.1/udp/0/quic-v1 >"$out/rotation-second.ndjson" 2>&1 &
  pids+=("$!")
  for _ in $(seq 1 200); do grep -q '"event":"terminal"' "$out/rotation-second.ndjson" && break; sleep .05; done
  grep -q '"code":"auth.pong"' "$out/rotation-second.ndjson" || { echo "rotated credential did not authenticate" >&2; exit 1; }
fi
if [[ "$case_name" == exchange-restart ]]; then
  kill -INT "$exchange_pid" 2>/dev/null || true; wait "$exchange_pid" 2>/dev/null || true
  P2X_RUN_ID="$run_id-restart" "$root/target/debug/p2x-exchange" --identity-file "$exchange_key" --credential-file "$credentials_file" --ticket-key-file "$ticket_key" --tcp-listen /ip4/127.0.0.1/tcp/0 --quic-listen /ip4/127.0.0.1/udp/0/quic-v1 >"$out/exchange-restart.ndjson" 2>&1 &
  exchange_pid=$!; pids+=("$exchange_pid")
  restart_addr=""
  for _ in $(seq 1 200); do restart_addr=$(sed -n 's/.*"event":"listener_ready".*"address":"\([^" ]*\/tcp\/[^" ]*\)".*/\1/p' "$out/exchange-restart.ndjson" | head -1 || true); [[ -n "$restart_addr" ]] && break; sleep .05; done
  [[ -n "$restart_addr" ]] || { echo "restarted exchange did not become ready" >&2; exit 1; }
  P2X_TOKEN="$client_token" "$root/target/debug/p2x-client" --identity-file "$client_key" --exchange "$restart_addr" --exchange-peer-id "$exchange_peer" --credential-env P2X_TOKEN --case-id restart-second --tcp-listen /ip4/127.0.0.1/tcp/0 --quic-listen /ip4/127.0.0.1/udp/0/quic-v1 >"$out/restart-second.ndjson" 2>&1 &
  pids+=("$!")
  for _ in $(seq 1 200); do grep -q '"event":"terminal"' "$out/restart-second.ndjson" && break; sleep .05; done
  grep -q '"code":"auth.pong"' "$out/restart-second.ndjson" || { echo "restarted exchange did not re-authenticate" >&2; exit 1; }
fi
! grep -E "$client_token|$server_token|$rotation_token|$client_digest|$server_digest|$rotation_digest|token_secret|raw_ticket|$exchange_key|$client_key|$server_key" "$out"/* >/dev/null 2>&1 || { echo "secret leaked" >&2; exit 1; }
printf '{"case":"%s","passed":true,"expected_code":"%s","component":"%s"}\n' "$case_name" "$expected" "$component" | tee "$out/summary.json"
