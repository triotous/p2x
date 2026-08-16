#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
suite=${1:-all}
fuzz_seconds=${P2X_FUZZ_SECONDS:-10}
artifact_dir=${P2X_ARTIFACT_DIR:-$root/target/container-tests}

cd "$root"
mkdir -p "$artifact_dir"
export P2X_ARTIFACT_DIR="$artifact_dir"

run_static() {
  cargo fmt --all -- --check
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  cargo test --workspace --all-targets --all-features
  cargo deny check
  cargo tree -e features
}

run_live() {
  ./tests/registry/local.sh --case all
  ./tests/auth/local.sh --case all
  ./tests/connectivity/local.sh --case all
  ./tests/auth/manual.sh --platform-security
}

run_fuzz() {
  cargo +nightly fuzz run auth_frame_decode fuzz/corpus/auth_frame -- -max_total_time="$fuzz_seconds"
  cargo +nightly fuzz run token_parse fuzz/corpus/token_parse -- -max_total_time="$fuzz_seconds"
  cargo +nightly fuzz run ticket_claims_decode fuzz/corpus/ticket_claims -- -max_total_time="$fuzz_seconds"
  cargo +nightly fuzz run registry_frame_decode fuzz/corpus/registry_frame_decode -- -max_total_time="$fuzz_seconds"
  cargo +nightly fuzz run ticket_envelope_decode fuzz/corpus/ticket_envelope -- -max_total_time="$fuzz_seconds"
}

run_linux() {
  [[ $(id -u) -eq 0 ]] || {
    echo "the linux namespace suite must run as root with CAP_NET_ADMIN" >&2
    exit 2
  }
  ./tests/connectivity/manual-gates.sh --linux
}

case "$suite" in
  all)
    run_static
    run_live
    run_fuzz
    ;;
  static) run_static ;;
  live) run_live ;;
  fuzz) run_fuzz ;;
  linux) run_linux ;;
  *)
    echo "usage: $0 [all|static|live|fuzz|linux]" >&2
    exit 2
    ;;
esac
