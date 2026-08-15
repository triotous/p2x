#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); cd "$root"
: "${P2X_RUN_ID:?set P2X_RUN_ID}"
out=${P2X_ARTIFACT_DIR:-target/p2x-spike/$P2X_RUN_ID}/C14-relay; mkdir -p "$out"
cargo run --locked -p p2x-exchange -- --identity-seed 1 --tcp-listen "${P2X_TCP_LISTEN:-/ip4/0.0.0.0/tcp/4001}" --quic-listen "${P2X_QUIC_LISTEN:-/ip4/0.0.0.0/udp/4001/quic-v1}" --unsafe-lab-public-relay --case-id C14 2>&1 | tee "$out/exchange.ndjson"
