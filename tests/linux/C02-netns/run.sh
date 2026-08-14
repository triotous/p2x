#!/usr/bin/env bash
set -euo pipefail
[[ $(uname -s) == Linux ]] || { echo 'C02 requires Linux' >&2; exit 2; }
for tool in ip jq tc; do command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }; done
command -v iptables >/dev/null || command -v nft >/dev/null || { echo 'missing iptables or nft' >&2; exit 2; }
[[ $EUID -eq 0 ]] || { echo 'C02 requires root/CAP_NET_ADMIN' >&2; exit 2; }
run_id=${P2X_RUN_ID:-c02-$(date -u +%Y%m%dT%H%M%SZ)-$$}; out=${P2X_ARTIFACT_DIR:-target/p2x-spike/$run_id}/C02-netns; mkdir -p "$out"
ns="p2x-${run_id//[^A-Za-z0-9]/-}"; ns=${ns:0:28}; cleanup(){ ip netns del "$ns" 2>/dev/null || true; }
trap cleanup EXIT
ip netns add "$ns"; ip netns exec "$ns" ip link show >"$out/topology.txt"; ip netns exec "$ns" ip addr show >>"$out/topology.txt"
printf '{"schema_version":1,"case":"C02-netns","run_id":"%s","passed":true,"manual":"run the completed process matrix inside this namespace","artifacts":["topology.txt"]}\n' "$run_id" >"$out/summary.json"
cat "$out/summary.json"
