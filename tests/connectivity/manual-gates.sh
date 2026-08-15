#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
. "$root/tests/connectivity/common.sh"

case "${1:-}" in
  --linux)
    [[ "$(uname -s)" == Linux ]] || { echo "--linux must run on a Linux host with root/CAP_NET_ADMIN" >&2; exit 2; }
    build_linux_binaries
    for case_id in C02 C03 C04 C05 C06 C07 C08 C09; do
      "$root/tests/connectivity/netns.sh" --case "$case_id"
    done
    "$root/tests/connectivity/netns.sh" --case C10 --streams 64
    "$root/tests/connectivity/netns.sh" --case C10 --streams 128
    "$root/tests/connectivity/netns.sh" --case C11 --bytes 268435456 --path direct
    "$root/tests/connectivity/netns.sh" --case C11 --bytes 268435456 --path relay
    "$root/tests/connectivity/netns.sh" --case C12
    "$root/tests/connectivity/netns.sh" --case C13 --iterations 100
    ;;
  --c14-validate)
    artifact_dir=${2:?usage: $0 --c14-validate <artifact-directory>}
    command -v jq >/dev/null || { echo "C14 validation requires jq" >&2; exit 2; }
    for file in exchange.ndjson server.ndjson client.ndjson environment.txt; do
      [[ -s "$artifact_dir/$file" ]] || { echo "missing C14 artifact: $file" >&2; exit 1; }
    done
    for component in exchange server client; do
      file="$artifact_dir/$component.ndjson"
      jq -e -c . "$file" >/dev/null || { echo "invalid NDJSON in C14 artifact: $component.ndjson" >&2; exit 1; }
      jq -e -s --arg component "$component" '
        all(.[]; .schema_version == 1 and .component == $component)
        and ([.[] | select(.event == "terminal")] | length == 1)
        and (.[-1].event == "terminal")
        and (.[-1].final_connections == 0)
        and (.[-1].final_pending_opens == 0)
        and (.[-1].final_workers == 0)
        and (.[-1].final_tasks == 0)
      ' "$file" >/dev/null || { echo "C14 $component requires one final terminal with zero logical resources" >&2; exit 1; }
    done
    jq -e -s 'any(.[]; .event == "terminal" and .result == "passed" and .observed_path == "relay" and .setup_duration_ms <= 20000)' "$artifact_dir/client.ndjson" >/dev/null || { echo "C14 client did not report a passing relay terminal within 20 seconds" >&2; exit 1; }
    jq -e -s 'any(.[]; .event == "probe_completed" and .ack.path == "relay" and .ack.terminal == "ok")' "$artifact_dir/server.ndjson" >/dev/null || { echo "C14 server did not observe a successful relay probe" >&2; exit 1; }
    [[ $(jq -r '.run_id' "$artifact_dir"/{exchange,server,client}.ndjson | sort -u | wc -l | tr -d ' ') -eq 1 ]] || { echo "C14 artifacts do not share one run_id" >&2; exit 1; }
    expected_run_id=$(jq -r '.run_id' "$artifact_dir/client.ndjson" | head -1)
    [[ $(sed -n 's/^run_id=//p' "$artifact_dir/environment.txt" | sort -u | wc -l | tr -d ' ') -eq 1 ]] || { echo "C14 environment must record one shared run_id for both hosts" >&2; exit 1; }
    [[ $(sed -n 's/^run_id=//p' "$artifact_dir/environment.txt" | head -1) == "$expected_run_id" ]] || { echo "C14 environment run_id does not match NDJSON artifacts" >&2; exit 1; }
    [[ $(grep -Ec '^=== Host [AB]:' "$artifact_dir/environment.txt") -eq 2 ]] || { echo "C14 environment must contain Host A and Host B sections" >&2; exit 1; }
    [[ $(grep -E '^[0-9a-f]{40}$' "$artifact_dir/environment.txt" | sort -u | wc -l | tr -d ' ') -eq 1 ]] || { echo "C14 hosts must record one shared Git commit" >&2; exit 1; }
    printf '{"schema_version":1,"case":"C14","passed":true,"terminal_code":"probe.ok","artifacts":["exchange.ndjson","server.ndjson","client.ndjson","environment.txt"]}\n' >"$artifact_dir/summary.json"
    cat "$artifact_dir/summary.json"
    ;;
  *)
    echo "usage: $0 --linux | --c14-validate <artifact-directory>" >&2
    exit 2
    ;;
esac
