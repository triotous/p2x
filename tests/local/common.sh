#!/usr/bin/env bash
set -euo pipefail

start_services() {
  local case_id=$1
  RUN_ID=${P2X_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
  OUT=${P2X_ARTIFACT_DIR:-target/p2x-spike/$RUN_ID}/$case_id
  mkdir -p "$OUT"
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
  P2X_RUN_ID="$RUN_ID" target/debug/p2x-server \
    --identity-seed 2 --tcp-listen /ip4/127.0.0.1/tcp/0 >"$OUT/server.ndjson" 2>&1 &
  pids+=("$!")
  sleep 1
}

run_local_case() {
  local case_id=$1
  start_services "$case_id"
  printf '{"schema_version":1,"case":"%s","run_id":"%s","passed":false,"terminal_code":"not_implemented","reason":"the binary lifecycle required by this case is not implemented","artifacts":["exchange.ndjson","server.ndjson"]}\n' "$case_id" "$RUN_ID" >"$OUT/summary.json"
  cat "$OUT/summary.json"
  echo "$case_id is not implemented; services were started and stopped" >&2
  return 2
}
