#!/usr/bin/env bash
set -euo pipefail

start_services() {
  local case_id=$1
  RUN_ID=${P2X_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
  OUT=${P2X_ARTIFACT_DIR:-target/p2x-spike/$RUN_ID}/$case_id
  mkdir -p "$OUT"
  cd "$root"
  if [[ "${P2X_SKIP_BUILD:-0}" != 1 ]]; then
    cargo build --workspace --bins >/dev/null
  fi
  if ! declare -p EXCHANGE_CMD >/dev/null 2>&1; then EXCHANGE_CMD=(target/debug/p2x-exchange); fi
  if ! declare -p SERVER_CMD >/dev/null 2>&1; then SERVER_CMD=(target/debug/p2x-server); fi
  if ! declare -p CLIENT_CMD >/dev/null 2>&1; then CLIENT_CMD=(target/debug/p2x-client); fi
  local exchange_tcp_listen=${P2X_EXCHANGE_TCP_LISTEN:-/ip4/127.0.0.1/tcp/0}
  local exchange_quic_listen=${P2X_EXCHANGE_QUIC_LISTEN:-/ip4/127.0.0.1/udp/0/quic-v1}
  local peer_tcp_listen=${P2X_PEER_TCP_LISTEN:-/ip4/127.0.0.1/tcp/0}
  local peer_quic_listen=${P2X_PEER_QUIC_LISTEN:-/ip4/127.0.0.1/udp/0/quic-v1}
  local server_tcp_listen=${P2X_SERVER_TCP_LISTEN:-$peer_tcp_listen}
  local server_quic_listen=${P2X_SERVER_QUIC_LISTEN:-$peer_quic_listen}
  local client_tcp_listen=${P2X_CLIENT_TCP_LISTEN:-$peer_tcp_listen}
  local client_quic_listen=${P2X_CLIENT_QUIC_LISTEN:-$peer_quic_listen}
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
    if declare -F cleanup_topology >/dev/null 2>&1; then cleanup_topology; fi
  }
  trap cleanup TERM INT EXIT
  local exchange_args=(--unsafe-connectivity-lab --identity-seed 1 --tcp-listen "$exchange_tcp_listen" --quic-listen "$exchange_quic_listen")
  [[ "$exchange_tcp_listen" == *"/127.0.0.1/"* ]] || exchange_args+=(--unsafe-lab-public-relay)
  [[ "$case_id" == C09 ]] && exchange_args+=(--relay-profile limit-test)
  P2X_RUN_ID="$RUN_ID" "${EXCHANGE_CMD[@]}" "${exchange_args[@]}" >"$OUT/exchange.ndjson" 2>&1 &
  pids+=("$!")
  for _ in $(seq 1 100); do
    if [[ "${P2X_EXCHANGE_TRANSPORT:-tcp}" == quic ]]; then
      exchange_addr=$(sed -n 's/.*"event":"listener_ready".*"address":"\([^" ]*\/quic-v1[^" ]*\)".*/\1/p' "$OUT/exchange.ndjson" | head -1 || true)
    else
      exchange_addr=$(sed -n 's/.*"event":"listener_ready".*"address":"\([^" ]*\/tcp\/[^" ]*\)".*/\1/p' "$OUT/exchange.ndjson" | head -1 || true)
    fi
    [[ -n "${exchange_addr:-}" ]] && break
    sleep 0.1
  done
  [[ -n "${exchange_addr:-}" ]] || { echo 'exchange did not become ready' >&2; return 2; }
  local server_args=(--unsafe-connectivity-lab --identity-seed 2 --exchange "$exchange_addr" --tcp-listen "$server_tcp_listen" --quic-listen "$server_quic_listen")
  [[ "$case_id" == C08 ]] && server_args+=(--drop-first-probe)
  P2X_RUN_ID="$RUN_ID" "${SERVER_CMD[@]}" "${server_args[@]}" >"$OUT/server.ndjson" 2>&1 &
  pids+=("$!")
  for _ in $(seq 1 100); do
    circuit_addr=$(sed -n 's/.*"event":"listener_ready".*"address":"\([^"]*p2p-circuit[^"]*\)".*/\1/p' "$OUT/server.ndjson" | head -1 || true)
    [[ -n "${circuit_addr:-}" ]] && break
    sleep 0.1
  done
  [[ -n "${circuit_addr:-}" ]] || { echo 'server relay circuit did not become ready' >&2; return 2; }
  if [[ "$case_id" == C09 ]]; then
    P2X_RUN_ID="$RUN_ID" "${SERVER_CMD[@]}" --unsafe-connectivity-lab --identity-seed 4 --exchange "$exchange_addr" --tcp-listen "$server_tcp_listen" --quic-listen "$server_quic_listen" >"$OUT/server-second.ndjson" 2>&1 &
    pids+=("$!")
    for _ in $(seq 1 100); do
      grep -q '"event":"listener_ready".*p2p-circuit' "$OUT/server-second.ndjson" && break
      sleep 0.1
    done
    grep -q '"event":"listener_ready".*p2p-circuit' "$OUT/server-second.ndjson" || { echo 'C09 second reservation was not admitted' >&2; return 2; }
    P2X_RUN_ID="$RUN_ID" "${SERVER_CMD[@]}" --unsafe-connectivity-lab --identity-seed 5 --exchange "$exchange_addr" --tcp-listen "$server_tcp_listen" --quic-listen "$server_quic_listen" >"$OUT/server-excess.ndjson" 2>&1 &
    pids+=("$!")
    sleep 2
    if grep -q '"event":"listener_ready".*p2p-circuit' "$OUT/server-excess.ndjson"; then echo 'C09 excess reservation was incorrectly admitted' >&2; return 2; fi
  fi
  local client_args=(--unsafe-connectivity-lab --identity-seed 3 --server "$circuit_addr")
  case "$case_id" in
    C01) ;;
    C02|C03) client_args+=(--path direct) ;;
    C04) client_args+=(--path relay) ;;
    C01-smoke) client_args+=(--path relay) ;;
    C05) client_args+=(--path both --count 2 --concurrency 2) ;;
    C06|C06-relay) client_args+=(--suppress-dcutr-result) ;;
    C07) client_args+=(--mode half_close --length "${P2X_BYTES:-268435456}" --path direct) ;;
    C08) client_args+=(--mode half_close --length 1048576 --path relay --recover-after-failure) ;;
    C09) client_args+=(--path relay) ;;
    C10|C10-concurrency)
      first_streams=${P2X_STREAMS:-8}; [[ "$first_streams" -gt 64 ]] && first_streams=64
      client_args+=(--count "$first_streams" --concurrency "$first_streams")
      ;;
    C11|C11-large-transfer) client_args+=(--mode slow_reader --length "${P2X_BYTES:-268435456}" --path "${P2X_PATH:-relay}") ;;
    C12|C12-renewal) client_args+=(--count 1 --path relay) ;;
    C13|C13-churn)
      server_peer=$(sed -n 's/.*"event":"started","peer_id":"\([^"]*\)".*/\1/p' "$OUT/server.ndjson" | head -1)
      direct_addr=$(sed -n 's/.*"event":"listener_ready".*"address":"\([^" ]*\/quic-v1[^" ]*\)".*/\1/p' "$OUT/server.ndjson" | head -1)
      client_args=(--unsafe-connectivity-lab --identity-seed 3 --server "$direct_addr/p2p/$server_peer" --count "${P2X_ITERATIONS:-100}" --churn --path direct)
      ;;
    C05-direct)
      server_peer=$(sed -n 's/.*"event":"started","peer_id":"\([^"]*\)".*/\1/p' "$OUT/server.ndjson" | head -1)
      direct_addr=$(sed -n 's/.*"event":"listener_ready".*"address":"\([^" ]*\/tcp\/[^" ]*\)".*/\1/p' "$OUT/server.ndjson" | head -1)
      client_args=(--unsafe-connectivity-lab --identity-seed 3 --server "$direct_addr/p2p/$server_peer" --path direct)
      ;;
  esac
  client_args+=(--tcp-listen "$client_tcp_listen" --quic-listen "$client_quic_listen")
  P2X_RUN_ID="$RUN_ID" "${CLIENT_CMD[@]}" "${client_args[@]}" >"$OUT/client.ndjson" 2>&1 &
  CLIENT_PID=$!
  pids+=("$CLIENT_PID")
  SECOND_CLIENT_LOG=""
  if [[ "$case_id" == C10 && "${P2X_STREAMS:-8}" -gt 64 ]]; then
    second_streams=$((P2X_STREAMS - 64))
    [[ "$second_streams" -gt 64 ]] && second_streams=64
    SECOND_CLIENT_LOG="$OUT/client-second.ndjson"
    P2X_RUN_ID="$RUN_ID" "${CLIENT_CMD[@]}" --unsafe-connectivity-lab --identity-seed 6 --server "$circuit_addr" --count "$second_streams" --concurrency "$second_streams" --tcp-listen "$client_tcp_listen" --quic-listen "$client_quic_listen" >"$SECOND_CLIENT_LOG" 2>&1 &
    pids+=("$!")
  fi
  if [[ "$case_id" == C07 ]]; then
    for _ in $(seq 1 200); do
      grep -q '"event":"path_selected".*"selected_path":"direct"' "$OUT/client.ndjson" && break
      sleep 0.01
    done
    grep -q '"event":"path_selected".*"selected_path":"direct"' "$OUT/client.ndjson" || { echo 'C07 direct transfer did not start' >&2; return 2; }
    kill -INT "${pids[0]}" 2>/dev/null || true
  fi
  if [[ "$case_id" == C11 ]]; then
    for _ in $(seq 1 300); do
      grep -q '"event":"path_selected"' "$OUT/client.ndjson" && break
      sleep 0.01
    done
    grep -q '"event":"path_selected"' "$OUT/client.ndjson" || { echo 'C11 large transfer did not start' >&2; return 2; }
    P2X_RUN_ID="$RUN_ID" "${CLIENT_CMD[@]}" --unsafe-connectivity-lab --identity-seed 6 --server "$circuit_addr" --path "${P2X_PATH:-relay}" --case-id C11-nonce --tcp-listen "$client_tcp_listen" --quic-listen "$client_quic_listen" >"$OUT/nonce-client.ndjson" 2>&1 &
    pids+=("$!")
    for _ in $(seq 1 500); do
      grep -q '"event":"terminal".*"result":"passed"' "$OUT/nonce-client.ndjson" && break
      sleep 0.01
    done
    grep -q '"event":"terminal".*"result":"passed"' "$OUT/nonce-client.ndjson" || { echo 'C11 concurrent nonce was not responsive' >&2; return 2; }
    if grep -q '"event":"terminal"' "$OUT/client.ndjson"; then
      echo 'C11 large transfer finished before responsiveness probe' >&2
      return 2
    fi
  fi
}

run_local_case() {
  local case_id=$1
  start_services "$case_id"
  local expected=1
  case "$case_id" in
    C05) expected=2 ;;
    C10|C10-concurrency) expected=${P2X_STREAMS:-8} ;;
    C11|C11-large-transfer) expected=1 ;;
    C12|C12-renewal) expected=1 ;;
    C13|C13-churn) expected=${P2X_ITERATIONS:-100} ;;
  esac
  local client_path=Relay
  [[ "$case_id" == C01 || "$case_id" == C02 || "$case_id" == C03 || "$case_id" == C05-direct || "$case_id" == C07 || "$case_id" == C10 || "$case_id" == C10-concurrency || "$case_id" == C13 || "$case_id" == C13-churn ]] && client_path=Direct
  if [[ "$case_id" == C11 && "${P2X_PATH:-relay}" == direct ]]; then client_path=Direct; fi
  local wait_loops=300
  [[ "$case_id" == C11 || "$case_id" == C11-large-transfer ]] && wait_loops=3600
  [[ "$case_id" == C07 ]] && wait_loops=3600
  [[ "$case_id" == C12 || "$case_id" == C12-renewal ]] && wait_loops=1400
  [[ "$case_id" == C13 || "$case_id" == C13-churn ]] && wait_loops=1800
  for _ in $(seq 1 "$wait_loops"); do
    local succeeded observed terminals
    succeeded=$(grep -c '"event":"probe_completed"' "$OUT/client.ndjson" || true)
    [[ -z "$SECOND_CLIENT_LOG" ]] || succeeded=$((succeeded + $(grep -c '"event":"probe_completed"' "$SECOND_CLIENT_LOG" || true)))
    observed=$(grep -c '"event":"probe_completed"' "$OUT/server.ndjson" || true)
    terminals=$(grep -c '"event":"terminal"' "$OUT/client.ndjson" || true)
    expected_terminals=1
    if [[ -n "$SECOND_CLIENT_LOG" ]]; then terminals=$((terminals + $(grep -c '"event":"terminal"' "$SECOND_CLIENT_LOG" || true))); expected_terminals=2; fi
    local lifecycle_ok=true
    if [[ "$case_id" == C11 ]]; then
      rss_kib=$(ps -o rss= -p "$CLIENT_PID" 2>/dev/null | tr -d ' ' || true)
      [[ -z "$rss_kib" ]] || printf '%s\t%s\n' "$(date +%s)" "$rss_kib" >>"$OUT/client-rss.tsv"
      if [[ -n "$rss_kib" && "$rss_kib" -gt 131072 ]]; then lifecycle_ok=false; fi
      grep -q '"event":"terminal".*"result":"passed"' "$OUT/nonce-client.ndjson" || lifecycle_ok=false
    fi
    if [[ "$case_id" == C12 || "$case_id" == C12-renewal ]] && [[ $(grep -c '"renewal":true' "$OUT/server.ndjson" || true) -lt 2 ]]; then lifecycle_ok=false; fi
    if [[ "$case_id" == C13 || "$case_id" == C13-churn ]] && [[ $(grep -c '"state":"closed"' "$OUT/client.ndjson" || true) -lt 1 ]]; then lifecycle_ok=false; fi
    if [[ "$case_id" == C07 ]] && ! grep -q '"event":"reservation_transition".*"state":"degraded"' "$OUT/server.ndjson"; then lifecycle_ok=false; fi
    if [[ "$case_id" == C08 ]] && { ! grep -q '"code":"probe.fault_drop_first"' "$OUT/server.ndjson" || ! grep -q '"code":"probe.recovering"' "$OUT/client.ndjson"; }; then lifecycle_ok=false; fi
    if [[ "$case_id" == C09 ]] && { ! grep -q '"event":"listener_ready".*p2p-circuit' "$OUT/server-second.ndjson" || grep -q '"event":"listener_ready".*p2p-circuit' "$OUT/server-excess.ndjson"; }; then lifecycle_ok=false; fi
    local json_path
    json_path=$(printf '%s' "$client_path" | tr '[:upper:]' '[:lower:]')
    local path_ok=false
    if [[ "$case_id" == C05 ]] && grep -q '"event":"probe_completed".*"path":"direct"' "$OUT/client.ndjson" && grep -q '"event":"probe_completed".*"path":"relay"' "$OUT/client.ndjson" && grep -q '"event":"probe_completed".*"path":"direct"' "$OUT/server.ndjson" && grep -q '"event":"probe_completed".*"path":"relay"' "$OUT/server.ndjson"; then path_ok=true; fi
    if [[ "$case_id" != C05 ]] && grep -q "\"event\":\"probe_completed\".*\"path\":\"$json_path\"" "$OUT/client.ndjson" && grep -q "\"event\":\"probe_completed\".*\"path\":\"$json_path\"" "$OUT/server.ndjson"; then path_ok=true; fi
    if [[ -n "$SECOND_CLIENT_LOG" ]] && ! grep -q "\"event\":\"probe_completed\".*\"path\":\"$json_path\"" "$SECOND_CLIENT_LOG"; then path_ok=false; fi
    if [[ "$case_id" == C06 || "$case_id" == C06-relay ]]; then
      selected_offset=$(sed -n 's/.*"offset_ms":\([0-9][0-9]*\),"event":"path_selected".*"selected_path":"relay".*/\1/p' "$OUT/client.ndjson" | head -1)
      [[ -n "$selected_offset" && "$selected_offset" -ge 1300 && "$selected_offset" -le 2500 ]] || path_ok=false
    fi
    if [[ "$case_id" == C07 ]] && ! grep -q '"event":"probe_completed".*"bytes_read":268435456.*"half_close":true' "$OUT/client.ndjson"; then path_ok=false; fi
    if [[ "$succeeded" -ge "$expected" && "$observed" -ge "$expected" && "$terminals" -eq "$expected_terminals" && "$lifecycle_ok" == true && "$path_ok" == true ]]; then
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
