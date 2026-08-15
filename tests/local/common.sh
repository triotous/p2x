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
  local client_args=(--identity-seed 3 --server "$circuit_addr")
  case "$case_id" in
    C10-concurrency) client_args+=(--count 8) ;;
    C11-large-transfer) client_args+=(--mode slow_reader --length 1048576) ;;
    C12-renewal|C13-churn) client_args+=(--count 4) ;;
    C05-direct)
      server_peer=$(awk -F'"detail":"' '/"event":"started"/{split($2,a,"\""); split(a[1],b," "); print b[1]; exit}' "$OUT/server.ndjson")
      direct_addr=$(awk -F'"detail":"' '/"event":"listen_addr"/{split($2,a,"\""); print a[1]; exit}' "$OUT/server.ndjson")
      client_args=(--identity-seed 3 --server "$direct_addr/p2p/$server_peer" --path direct)
      ;;
  esac
  P2X_RUN_ID="$RUN_ID" target/debug/p2x-client "${client_args[@]}" >"$OUT/client.ndjson" 2>&1 &
  pids+=("$!")
}

run_local_case() {
  local case_id=$1
  start_services "$case_id"
  local expected=1
  case "$case_id" in
    C10-concurrency) expected=8 ;;
    C11-large-transfer) expected=1 ;;
    C12-renewal|C13-churn) expected=4 ;;
  esac
  local client_path=Relay
  [[ "$case_id" == C05-direct ]] && client_path=Direct
  for _ in $(seq 1 300); do
    local succeeded observed terminals
    succeeded=$(grep -c '"event":"probe_succeeded"' "$OUT/client.ndjson" || true)
    observed=$(grep -c '"event":"probe_observed"' "$OUT/server.ndjson" || true)
    terminals=$(grep -c '"result":"' "$OUT/client.ndjson" || true)
    if [[ "$succeeded" -ge "$expected" && "$observed" -ge "$expected" && "$terminals" -eq 1 ]] && grep -q "path=$client_path" "$OUT/client.ndjson" && grep -q "path=$client_path" "$OUT/server.ndjson"; then
      printf '{"schema_version":1,"case":"%s","run_id":"%s","passed":true,"terminal_code":"probe.ok","expected_probes":%d,"observed_probes":%d,"path":"%s","artifacts":["exchange.ndjson","server.ndjson","client.ndjson"]}\n' "$case_id" "$RUN_ID" "$expected" "$observed" "$client_path" >"$OUT/summary.json"
      cat "$OUT/summary.json"
      return 0
    fi
    sleep 0.1
  done
  printf '{"schema_version":1,"case":"%s","run_id":"%s","passed":false,"terminal_code":"failed","reason":"probe lifecycle did not complete","artifacts":["exchange.ndjson","server.ndjson","client.ndjson"]}\n' "$case_id" "$RUN_ID" >"$OUT/summary.json"
  cat "$OUT/summary.json"
  return 1
}
