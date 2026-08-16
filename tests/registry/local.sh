#!/usr/bin/env bash
set -euo pipefail
case_name=""
while (($#)); do
  case "$1" in
    --case) case_name="${2:?missing case}"; shift 2 ;;
    *) echo "usage: $0 --case <name>" >&2; exit 2 ;;
  esac
done
[[ -n "$case_name" ]] || { echo "--case is required" >&2; exit 2; }
root="$(cd "$(dirname "$0")/../.." && pwd)"
artifact="$root/target/registry/${case_name}-$(date +%s)-$$"
mkdir -p "$artifact"
export P2X_RUN_ID="registry-${case_name}-$$"
export P2X_ARTIFACT_DIR="$artifact"
if [[ ! -x "$root/target/debug/p2x-exchange" || ! -x "$root/target/debug/p2x-server" ]]; then
  cargo build --workspace --bins >"$artifact/build.log" 2>&1 || { echo "registry prerequisites unavailable: build failed; see $artifact/build.log" >&2; exit 2; }
fi
cat >"$artifact/run.json" <<EOF
{"case":"$case_name","artifact":"$artifact","status":"prepared"}
EOF
# Owner-executed process orchestration is intentionally explicit: a case runner must
# supply identities, credentials, ports, and assert observed NDJSON events.
echo "prepared $case_name in $artifact"
exit 2
