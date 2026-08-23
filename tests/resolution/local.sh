#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
case_name=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --case) case_name="${2:?missing case}"; shift 2 ;;
    *) echo "usage: $0 --case <name>" >&2; exit 2 ;;
  esac
done
[[ -n "$case_name" ]] || { echo "--case is required" >&2; exit 2; }
case "$case_name" in
  resolve-ticket-tcp|resolve-ticket-quic|unknown-selector|offline-selector|cross-tenant|idempotent-resolve|forced-relay|direct-preferred|direct-open-fallback|ticket-replay|ticket-bindings|ticket-expiry|registration-revision-change|connection-reuse|concurrent-opens|resolve-limit|proxy-limit|exchange-restart|server-restart|graceful-drain) ;;
  *) echo "unknown resolution case: $case_name" >&2; exit 2 ;;
esac
cat >&2 <<EOF
resolution case '$case_name' is incomplete: Plan 05 stops at the empty Authorized gate;
Phase 4 must provide fixed ingress and upstream Accepted before live route-open cases can pass.
EOF
exit 2
