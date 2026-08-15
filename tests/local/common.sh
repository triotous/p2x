#!/usr/bin/env bash
set -euo pipefail

run_local_case() {
  local case_id=$1
  local run_id=${P2X_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
  local out=${P2X_ARTIFACT_DIR:-target/p2x-spike/$run_id}/$case_id
  mkdir -p "$out"
  printf '{"schema_version":1,"case":"%s","run_id":"%s","passed":false,"terminal_code":"not_implemented","reason":"the binary lifecycle required by this case is not implemented"}\n' "$case_id" "$run_id" >"$out/summary.json"
  cat "$out/summary.json"
  echo "$case_id is not implemented; no connectivity result is claimed" >&2
  return 2
}
