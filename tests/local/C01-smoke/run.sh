#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$root"
. "$root/tests/local/common.sh"
start_services C01-smoke
for _ in $(seq 1 200); do
  if grep -q '"event":"probe_succeeded"' "$OUT/client.ndjson" && grep -q '"event":"probe_observed"' "$OUT/server.ndjson"; then
    [[ $(grep -c '"result":"' "$OUT/client.ndjson") -eq 1 ]] || break
    [[ $(grep -c '"event":"probe_observed"' "$OUT/server.ndjson") -eq 1 ]] || break
    printf '{"schema_version":1,"case":"C01-smoke","run_id":"%s","passed":true,"terminal_code":"probe.ok","artifacts":["exchange.ndjson","server.ndjson","client.ndjson"]}\n' "$RUN_ID" >"$OUT/summary.json"
    cat "$OUT/summary.json"
    exit 0
  fi
  if grep -q '"result":"failed"' "$OUT/client.ndjson"; then break; fi
  sleep 0.1
done
printf '{"schema_version":1,"case":"C01-smoke","run_id":"%s","passed":false,"terminal_code":"failed","reason":"relay reservation or exact probe did not complete","artifacts":["exchange.ndjson","server.ndjson","client.ndjson"]}\n' "$RUN_ID" >"$OUT/summary.json"
cat "$OUT/summary.json"
exit 2
