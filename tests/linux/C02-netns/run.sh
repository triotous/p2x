#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
exec "$root/tests/connectivity/netns.sh" --case C02 "$@"
