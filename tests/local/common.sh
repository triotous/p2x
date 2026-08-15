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
    for pid in "${pids[@]:-}"; do kill -INT "$pid" 2>/dev/null || true; done
    for _ in $(seq 1 50); do
      local alive=false
      for pid in "${pids[@]:-}"; do kill -0 "$pid" 2>/dev/null && alive=true; done
      [[ "$alive" == false ]] && break
      sleep 0.1
    done
    for pid in "${pids[@]:-}"; do kill -TERM "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
  }
  trap cleanup TERM INT EXIT
  P2X_RUN_ID="$RUN_ID" target/debug/p2x-exchange \
    --identity-seed 1 --tcp-listen /ip4/127.0.0.1/tcp/0 >"$OUT/exchange.ndjson" 2>&1 &
  pids+=("$!")
  for _ in $(seq 1 100); do
    exchange_addr=$(sed -n 's/.*"event":"listener_ready".*"address":"\([^" ]*\/tcp\/[^" ]*\)".*/\1/p' "$OUT/exchange.ndjson" | head -1 || true)
    [[ -n "${exchange_addr:-}" ]] && break
    sleep 0.1
  done
  [[ -n "${exchange_addr:-}" ]] || { echo 'exchange did not become ready' >&2; return 2; }
  P2X_RUN_ID="$RUN_ID" target/debug/p2x-server \
    --identity-seed 2 --exchange "$exchange_addr" --tcp-listen /ip4/127.0.0.1/tcp/0 >"$OUT/server.ndjson" 2>&1 &
  pids+=("$!")
  for _ in $(seq 1 100); do
    circuit_addr=$(sed -n 's/.*"event":"listener_ready".*"address":"\([^"]*p2p-circuit[^"]*\)".*/\1/p' "$OUT/server.ndjson" | head -1 || true)
    [[ -n "${circuit_addr:-}" ]] && break
    sleep 0.1
  done
  [[ -n "${circuit_addr:-}" ]] || { echo 'server relay circuit did not become ready' >&2; return 2; }
  local client_args=(--identity-seed 3 --server "$circuit_addr")
  case "$case_id" in
    C01) ;;
    C01-smoke) client_args+=(--path relay) ;;
    C06|C06-relay) client_args+=(--path relay) ;;
    C10|C10-concurrency) client_args+=(--count "${P2X_STREAMS:-8}" --concurrency "${P2X_STREAMS:-8}") ;;
    C11|C11-large-transfer) client_args+=(--mode slow_reader --length "${P2X_BYTES:-268435456}" --path "${P2X_PATH:-relay}") ;;
    C12|C12-renewal) client_args+=(--count 1 --path relay) ;;
    C13|C13-churn) client_args+=(--count "${P2X_ITERATIONS:-100}" --churn --path relay) ;;
    C05-direct)
      server_peer=$(sed -n 's/.*"event":"started","peer_id":"\([^"]*\)".*/\1/p' "$OUT/server.ndjson" | head -1)
      direct_addr=$(sed -n 's/.*"event":"listener_ready".*"address":"\([^" ]*\/tcp\/[^" ]*\)".*/\1/p' "$OUT/server.ndjson" | head -1)
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
    C10|C10-concurrency) expected=${P2X_STREAMS:-8} ;;
    C11|C11-large-transfer) expected=1 ;;
    C12|C12-renewal) expected=1 ;;
    C13|C13-churn) expected=${P2X_ITERATIONS:-100} ;;
  esac
  local client_path=Relay
  [[ "$case_id" == C01 || "$case_id" == C05-direct || "$case_id" == C07 || "$case_id" == C10 || "$case_id" == C10-concurrency ]] && client_path=Direct
  local wait_loops=300
  [[ "$case_id" == C11 || "$case_id" == C11-large-transfer ]] && wait_loops=3600
  [[ "$case_id" == C12 || "$case_id" == C12-renewal ]] && wait_loops=700
  [[ "$case_id" == C13 || "$case_id" == C13-churn ]] && wait_loops=1800
  for _ in $(seq 1 "$wait_loops"); do
    local succeeded observed terminals
    succeeded=$(grep -c '"event":"probe_completed"' "$OUT/client.ndjson" || true)
    observed=$(grep -c '"event":"probe_completed"' "$OUT/server.ndjson" || true)
    terminals=$(grep -c '"event":"terminal"' "$OUT/client.ndjson" || true)
    local lifecycle_ok=true
    [[ "$case_id" == C12 || "$case_id" == C12-renewal ]] && grep -q '"renewal":true' "$OUT/server.ndjson" || true
    if [[ "$case_id" == C12 || "$case_id" == C12-renewal ]] && ! grep -q '"renewal":true' "$OUT/server.ndjson"; then lifecycle_ok=false; fi
    if [[ "$case_id" == C13 || "$case_id" == C13-churn ]] && [[ $(grep -c '"state":"closed"' "$OUT/client.ndjson" || true) -lt 1 ]]; then lifecycle_ok=false; fi
    local json_path
    json_path=$(printf '%s' "$client_path" | tr '[:upper:]' '[:lower:]')
    if [[ "$succeeded" -ge "$expected" && "$observed" -ge "$expected" && "$terminals" -eq 1 && "$lifecycle_ok" == true ]] && grep -q "\"path\":\"$json_path\"" "$OUT/client.ndjson" && grep -q "\"path\":\"$json_path\"" "$OUT/server.ndjson"; then
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
