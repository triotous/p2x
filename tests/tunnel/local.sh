#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
case_name=""
while (($#)); do
  case "$1" in
    --case) case_name="${2:?missing case}"; shift 2 ;;
    *) echo "usage: $0 --case <name|all>" >&2; exit 2 ;;
  esac
done
[[ -n "$case_name" ]] || { echo "--case is required" >&2; exit 2; }

cases=(fixed-tcp-direct fixed-tcp-relay upstream-refused upstream-timeout idle-timeout half-close-direct half-close-relay large-slow-direct large-slow-relay concurrent-streams stream-limits control-loss-direct path-loss-recovery shutdown-cancellation per-ingress-failure-recovery/resolve per-ingress-failure-recovery/path-capacity per-ingress-failure-recovery/upstream per-ingress-failure-recovery/pre-accept-eof stream-limits/client-ingress stream-limits/client-server stream-limits/server-global stream-limits/server-client stream-limits/server-service stream-limits/server-dial deadline-stages shutdown/client-setup shutdown/client-active shutdown/server-setup shutdown/server-active terminal-correlation concurrent-streams/64-sustained concurrent-streams/128-headroom resource-baseline/128)
if [[ "$case_name" != "all" ]] && [[ ! " ${cases[*]} " =~ " $case_name " ]]; then
  echo "unknown tunnel case: $case_name" >&2
  exit 2
fi
cd "$root"
cargo build -q --workspace --bins
cargo build -q -p p2x-config --example identity-id --example ticket-verification
if [[ "$case_name" == "all" ]]; then
  for case in "${cases[@]}"; do
    python3 tests/tunnel/live.py "$root" "$case"
  done
else
  python3 tests/tunnel/live.py "$root" "$case_name"
fi
