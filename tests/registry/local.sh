#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
case_name=all
while (($#)); do
  case "$1" in
    --case) case_name="${2:?missing case}"; shift 2 ;;
    *) echo "usage: $0 --case <name|all>" >&2; exit 2 ;;
  esac
done

cd "$root"
cargo build -q --workspace --bins
cargo build -q -p p2x-config --example identity-id
exec python3 tests/registry/live.py --case "$case_name"
