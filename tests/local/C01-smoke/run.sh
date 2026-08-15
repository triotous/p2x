#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"
command -v jq >/dev/null || { echo 'C01 requires jq' >&2; exit 2; }
run_id=${P2X_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
out=${P2X_ARTIFACT_DIR:-target/p2x-spike/$run_id}/C01-smoke
mkdir -p "$out"
pids=()
cleanup() { trap - TERM INT EXIT; for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup TERM INT EXIT
cargo build --workspace --bins >/dev/null
P2X_RUN_ID="$run_id" target/debug/p2x-exchange --identity-seed 1 --tcp-listen /ip4/127.0.0.1/tcp/0 >"$out/exchange.ndjson" 2>&1 & pids+=("$!")
P2X_RUN_ID="$run_id" target/debug/p2x-server --identity-seed 2 --tcp-listen /ip4/127.0.0.1/tcp/0 >"$out/server.ndjson" 2>&1 & pids+=("$!")
for _ in $(seq 1 100); do
  if grep -q '"event":"listen_addr"' "$out/exchange.ndjson" && grep -q '"event":"listen_addr"' "$out/server.ndjson"; then break; fi
  sleep 0.1
done
if ! grep -q '"event":"listen_addr"' "$out/exchange.ndjson" || ! grep -q '"event":"listen_addr"' "$out/server.ndjson"; then
  echo 'services did not become ready' >&2
  exit 2
fi
P2X_RUN_ID="$run_id" target/debug/p2x-client --identity-seed 3 >"$out/client.ndjson" 2>&1 & client_pid=$!
for _ in $(seq 1 20); do
  if grep -q '"event":"started"' "$out/client.ndjson"; then break; fi
  sleep 0.1
done
kill "$client_pid" 2>/dev/null || true
wait "$client_pid" 2>/dev/null || true
for f in "$out"/*.ndjson; do
  jq -e --arg run "$run_id" 'select(.schema_version == 1 and .run_id == $run)' "$f" >/dev/null || {
    echo "invalid NDJSON: $f" >&2
    exit 1
  }
done
printf '{"schema_version":1,"case":"C01-smoke","run_id":"%s","passed":true,"artifacts":["exchange.ndjson","server.ndjson","client.ndjson"]}\n' "$run_id" >"$out/summary.json"
cat "$out/summary.json"
