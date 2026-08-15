#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
case_id=${1:?usage: $0 C02..C13}
shift || true
exec "$root/tests/connectivity/netns.sh" --case "$case_id" "$@"
