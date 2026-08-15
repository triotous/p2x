#!/usr/bin/env bash
set -euo pipefail

start_services() {
  local case_id=$1
  RUN_ID=${P2X_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
  OUT=${P2X_ARTIFACT_DIR:-target/p2x-spike/$RUN_ID}/$case_id
  mkdir -p "$OUT"
  cd "$(git rev-parse --show-toplevel)"
  cargo build --workspace --bins >/dev/null
  pids=()
  cleanup() {
    trap - TERM INT EXIT
    for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
  }
  trap cleanup TERM INT EXIT
  P2X_RUN_ID="$RUN_ID" target/debug/p2x-exchange \
    --identity-seed 1 --tcp-listen /ip4/127.0.0.1/tcp/0 >"$OUT/exchange.ndjson" 2>&1 &
  pids+=("$!")
  for _ in $(seq 1 100); do
    exchange_addr=$(awk -F'"detail":"' '/"event":"listen_addr"/{split($2,a,"\""); print a[1]; exit}' "$OUT/exchange.ndjson" || true)
    [[ -n "${exchange_addr:-}" ]] && break
    sleep 0.1
  done
  [[ -n "${exchange_addr:-}" ]] || { echo 'exchange did not become ready' >&2; return 2; }
  P2X_RUN_ID="$RUN_ID" target/debug/p2x-server \
    --identity-seed 2 --exchange "$exchange_addr" --tcp-listen /ip4/127.0.0.1/tcp/0 >"$OUT/server.ndjson" 2>&1 &
  pids+=("$!")
  for _ in $(seq 1 100); do
    circuit_addr=$(awk -F'"detail":"' '/"event":"circuit_ready"/{split($2,a,"\""); print a[1]; exit}' "$OUT/server.ndjson" || true)
    [[ -n "${circuit_addr:-}" ]] && break
    sleep 0.1
  done
  [[ -n "${circuit_addr:-}" ]] || { echo 'server relay circuit did not become ready' >&2; return 2; }
  P2X_RUN_ID="$RUN_ID" target/debug/p2x-client --identity-seed 3 --server "$circuit_addr" >"$OUT/client.ndjson" 2>&1 &
  pids+=("$!")
}

run_local_case() {
  local case_id=$1
  start_services "$case_id"
  for _ in $(seq 1 200); do
    if grep -q '"event":"probe_succeeded"' "$OUT/client.ndjson" && grep -q '"event":"probe_observed"' "$OUT/server.ndjson"; then
      printf '{"schema_version":1,"case":"%s","run_id":"%s","passed":true,"terminal_code":"probe.ok","artifacts":["exchange.ndjson","server.ndjson","client.ndjson"]}\n' "$case_id" "$RUN_ID" >"$OUT/summary.json"
      cat "$OUT/summary.json"
      return 0
    fi
    sleep 0.1
  done
  printf '{"schema_version":1,"case":"%s","run_id":"%s","passed":false,"terminal_code":"failed","reason":"probe lifecycle did not complete","artifacts":["exchange.ndjson","server.ndjson","client.ndjson"]}\n' "$case_id" "$RUN_ID" >"$OUT/summary.json"
  cat "$OUT/summary.json"
  return 1
}
