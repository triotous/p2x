#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
case_id=${1:-}
[[ -n "$case_id" ]] || { echo "usage: $0 C02|C03|C04|C05|C06|C07|C08|C09|C10|C11|C12|C13" >&2; exit 2; }
[[ $(uname -s) == Linux ]] || { echo 'Linux test runner requires Linux' >&2; exit 2; }
case "$case_id" in
  C02) exec "$root/tests/linux/C02-netns/run.sh" ;;
  *) echo "Linux case $case_id is not wired yet" >&2; exit 2 ;;
esac
