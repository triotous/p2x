#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
case_id=${1:-}
case_id=${case_id#C}
case_id="C$case_id"
[[ -n "$case_id" ]] || { echo "usage: $0 C01|C05|C06|C07|C08|C09|C10|C11|C12|C13" >&2; exit 2; }
case "$case_id" in
  C01) exec "$root/tests/local/C01-smoke/run.sh" ;;
  C05|C05-direct) exec "$root/tests/local/C05-direct/run.sh" ;;
  C06) exec "$root/tests/local/C06-relay/run.sh" ;;
  C07) exec "$root/tests/local/C07-dcutr/run.sh" ;;
  C08) exec "$root/tests/local/C08-interruption/run.sh" ;;
  C09) exec "$root/tests/local/C09-limits/run.sh" ;;
  C10) exec "$root/tests/local/C10-concurrency/run.sh" ;;
  C11) exec "$root/tests/local/C11-large-transfer/run.sh" ;;
  C12) exec "$root/tests/local/C12-renewal/run.sh" ;;
  C13) exec "$root/tests/local/C13-churn/run.sh" ;;
  *) echo "unknown local case: $case_id" >&2; exit 2 ;;
esac
