#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)

case "${1:-}" in
  --linux)
    [[ "$(uname -s)" == Linux ]] || { echo "--linux must run on a Linux host with root/CAP_NET_ADMIN" >&2; exit 2; }
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
    [[ $(jq -s '[.[] | select(.event == "terminal")] | length' "$artifact_dir/client.ndjson") -eq 1 ]] || { echo "C14 client requires exactly one terminal" >&2; exit 1; }
    jq -e -s 'any(.[]; .event == "terminal" and .result == "passed" and .observed_path == "relay")' "$artifact_dir/client.ndjson" >/dev/null
    jq -e -s 'any(.[]; .event == "probe_completed" and .ack.path == "relay" and .ack.terminal == "ok")' "$artifact_dir/server.ndjson" >/dev/null
    printf '{"schema_version":1,"case":"C14","passed":true,"terminal_code":"probe.ok","artifacts":["exchange.ndjson","server.ndjson","client.ndjson","environment.txt"]}\n' >"$artifact_dir/summary.json"
    cat "$artifact_dir/summary.json"
    ;;
  *)
    echo "usage: $0 --linux | --c14-validate <artifact-directory>" >&2
    exit 2
    ;;
esac
