#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
case_id=${1:-}
[[ -n "$case_id" ]] || { echo "usage: $0 C01|C05..C13" >&2; exit 2; }
shift || true
exec "$root/tests/connectivity/local.sh" --case "$case_id" "$@"
