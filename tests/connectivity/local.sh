#!/usr/bin/env bash
set -euo pipefail

case_id=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --case) case_id="${2:?missing case id}"; shift 2;;
    --case=*) case_id="${1#*=}"; shift;;
    *) echo "unsupported argument: $1" >&2; exit 2;;
  esac
done
[[ -n "$case_id" ]] || { echo "usage: $0 --case C01..C14" >&2; exit 2; }
run_id="${P2X_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
artifact_dir="${P2X_ARTIFACT_DIR:-target/p2x-spike/$run_id}"
mkdir -p "$artifact_dir"
log="$artifact_dir/$case_id.log"
summary="$artifact_dir/$case_id.json"
{
  echo "case=$case_id"
  echo "run_id=$run_id"
  echo "platform=$(uname -s)"
  echo "status=unsupported"
  echo "reason=live connectivity lifecycle is not yet complete"
} >"$log"
printf '{"case":"%s","run_id":"%s","passed":false,"terminal_code":"unsupported","artifact":"%s"}\n' "$case_id" "$run_id" "$log" >"$summary"
echo "case $case_id is unsupported; artifacts: $artifact_dir" >&2
exit 2
