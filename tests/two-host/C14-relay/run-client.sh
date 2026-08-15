#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); cd "$root"
: "${P2X_RUN_ID:?set P2X_RUN_ID}"; : "${P2X_SERVER_CIRCUIT:?set P2X_SERVER_CIRCUIT}"
out=${P2X_ARTIFACT_DIR:-target/p2x-spike/$P2X_RUN_ID}/C14-relay; mkdir -p "$out"
cargo run --locked -p p2x-client -- --identity-seed 3 --server "$P2X_SERVER_CIRCUIT" --path relay --case-id C14 2>&1 | tee "$out/client.ndjson"
