#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd); cd "$root"
: "${P2X_RUN_ID:?set P2X_RUN_ID}"
: "${P2X_EXCHANGE_ADDR:?set the public exchange multiaddress including /p2p/<peer>}"
out=${P2X_ARTIFACT_DIR:-target/p2x-spike/$P2X_RUN_ID}/C14-relay; mkdir -p "$out"
cargo build --locked -p p2x-server
exec "$root/target/debug/p2x-server" \
  --unsafe-connectivity-lab \
  --identity-seed 2 \
  --exchange "$P2X_EXCHANGE_ADDR" \
  --tcp-listen "${P2X_TCP_LISTEN:-/ip4/0.0.0.0/tcp/4002}" \
  --quic-listen "${P2X_QUIC_LISTEN:-/ip4/0.0.0.0/udp/4002/quic-v1}" \
  --case-id C14 \
  --artifact "$out/server.ndjson" \
  2>"$out/server.stderr.log"
