#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
case_name=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --case) case_name="${2:?missing case}"; shift 2 ;;
    *) echo "usage: $0 --case <case>" >&2; exit 2 ;;
  esac
done
[[ -n "$case_name" ]] || { echo "--case is required" >&2; exit 2; }
case "$case_name" in
  valid-client|valid-server|wrong-token|wrong-peer|wrong-role|revoked|expired|pin-mismatch|rotation|malformed|limits|exchange-restart)
    ;;
  *) echo "unknown auth case: $case_name" >&2; exit 2 ;;
esac
cargo test --workspace --all-targets --all-features
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
printf '{"case":"%s","result":"automated_protocol_checks_passed"}\n' "$case_name"
