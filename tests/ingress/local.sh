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

cases=(http-direct http-relay http-keepalive http-pipeline-route-lock http-streaming http-websocket http-local-rejections http-error-mapping tls-direct tls-relay tls-fragmentation tls-local-rejections parse-deadlines setup-budget mixed-limits shutdown-parsing shutdown-active mixed-concurrency/64 mixed-concurrency/128)
if [[ "$case_name" != all ]] && [[ ! " ${cases[*]} " =~ " $case_name " ]]; then
  echo "unknown ingress case: $case_name" >&2
  exit 2
fi

cd "$root"
cargo build -q --workspace --bins
cargo build -q -p p2x-config --example identity-id --example ticket-verification
cargo test -q -p p2x-proxy
cargo test -q -p p2x-client --all-targets
cargo check -q --manifest-path fuzz/Cargo.toml --bin domain_authority --bin http_ingress --bin tls_client_hello
python3 -B -m unittest discover -s tests/ingress -p 'test_*.py'
if [[ "$case_name" == all ]]; then
  for ingress_case in "${cases[@]}"; do
    python3 -B tests/ingress/live.py "$root" "$ingress_case"
  done
else
  python3 -B tests/ingress/live.py "$root" "$case_name"
fi
