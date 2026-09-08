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
cargo build -q -p p2x-client --bin p2x-client
cargo test --workspace --all-targets --all-features
printf '%s\n' "deterministic ingress tests passed"
printf '%s\n' "incomplete: live case '$case_name' requires owner-supplied DNS, certificates, exchange fixtures, and direct/relay environment" >&2
exit 2
