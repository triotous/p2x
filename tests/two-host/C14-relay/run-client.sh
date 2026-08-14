#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); cd "$root"
: "${P2X_RUN_ID:?set P2X_RUN_ID}"; : "${P2X_EXCHANGE_ADDR:?set P2X_EXCHANGE_ADDR}"
out=${P2X_ARTIFACT_DIR:-target/p2x-spike/$P2X_RUN_ID}/C14-relay; mkdir -p "$out"
cargo run --locked -p p2x-client -- --identity-seed 3 --exchange "$P2X_EXCHANGE_ADDR" 2>&1 | tee "$out/client.ndjson"
