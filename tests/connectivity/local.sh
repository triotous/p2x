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
  C01|C05|C06|C07|C08|C09|C10|C11|C12|C13) ;;
  *) echo "usage: $0 --case C01|C05..C13" >&2; exit 2 ;;
esac

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
