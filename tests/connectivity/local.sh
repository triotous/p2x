#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
case_id=""
streams=""
bytes=""
path=""
iterations=""
exchange_transport=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --case) case_id="${2:?missing case id}"; shift 2 ;;
    --case=*) case_id="${1#*=}"; shift ;;
    --streams) streams="${2:?missing stream count}"; shift 2 ;;
    --bytes) bytes="${2:?missing byte count}"; shift 2 ;;
    --path) path="${2:?missing path}"; shift 2 ;;
    --iterations) iterations="${2:?missing iteration count}"; shift 2 ;;
    --exchange-transport) exchange_transport="${2:?missing exchange transport}"; shift 2 ;;
    *) echo "unsupported argument: $1" >&2; exit 2 ;;
  esac
done

case "$case_id" in
  all|C01|C05|C06|C07|C08|C09|C10|C11|C12|C13) ;;
  *) echo "usage: $0 --case all|C01|C05..C13" >&2; exit 2 ;;
esac

if [[ "$case_id" == all ]]; then
  [[ -z "$streams$bytes$path$iterations$exchange_transport" ]] || {
    echo "--case all does not accept per-case overrides" >&2
    exit 2
  }
  cd "$root"
  cargo build --workspace --bins >/dev/null
  base_run_id=${P2X_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
  artifact_base=${P2X_ARTIFACT_DIR:-target/p2x-spike/$base_run_id}
  run_all_case() {
    local label=$1
    shift
    P2X_SKIP_BUILD=1 P2X_RUN_ID="$base_run_id-$label" \
      P2X_ARTIFACT_DIR="$artifact_base/$label" \
      "$root/tests/connectivity/local.sh" "$@"
  }
  run_all_case C01 --case C01
  run_all_case C05 --case C05
  run_all_case C06 --case C06
  run_all_case C07 --case C07
  run_all_case C08 --case C08
  run_all_case C09 --case C09
  run_all_case C10-64 --case C10 --streams 64
  run_all_case C10-128 --case C10 --streams 128
  run_all_case C11-direct --case C11 --bytes 268435456 --path direct
  run_all_case C11-relay --case C11 --bytes 268435456 --path relay
  run_all_case C12 --case C12
  run_all_case C13 --case C13 --iterations 100
  exit 0
fi

[[ -z "$streams" ]] || export P2X_STREAMS="$streams"
[[ -z "$bytes" ]] || export P2X_BYTES="$bytes"
[[ -z "$path" ]] || export P2X_PATH="$path"
[[ -z "$iterations" ]] || export P2X_ITERATIONS="$iterations"
if [[ -n "$exchange_transport" ]]; then
  [[ "$exchange_transport" == tcp || "$exchange_transport" == quic ]] || { echo "exchange transport must be tcp or quic" >&2; exit 2; }
  export P2X_EXCHANGE_TRANSPORT="$exchange_transport"
fi

cd "$root"
. "$root/tests/connectivity/common.sh"
run_local_case "$case_id"
