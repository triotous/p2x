#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
case_id=${1:-C14}
[[ "$case_id" == C14 ]] || { echo "usage: $0 C14" >&2; exit 2; }
echo "C14 requires this runner on the exchange host and client host; see tests/two-host/C14-relay/README.md" >&2
exit 2
