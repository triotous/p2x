#!/usr/bin/env bash
set -euo pipefail

[[ $(uname -s) == Linux ]] || { echo 'C02 requires Linux' >&2; exit 2; }
for tool in ip jq tc; do command -v "$tool" >/dev/null || { echo "missing $tool" >&2; exit 2; }; done
command -v iptables >/dev/null || command -v nft >/dev/null || { echo 'missing iptables or nft' >&2; exit 2; }
run_id=${P2X_RUN_ID:-c02-$(date -u +%Y%m%dT%H%M%SZ)-$$}
out=${P2X_ARTIFACT_DIR:-target/p2x-spike/$run_id}/C02-netns
mkdir -p "$out"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo 'C02 requires root or CAP_NET_ADMIN; run with sudo or grant the capability' >&2
  exit 2
fi
ip netns list >/dev/null 2>"$out/permission-error.txt" || {
  echo 'C02 cannot access network namespaces; CAP_NET_ADMIN is missing or restricted' >&2
  exit 2
}

ns="p2x-${run_id//[^A-Za-z0-9]/-}"
ns=${ns:0:28}
cleanup() { ip netns del "$ns" 2>/dev/null || true; }
trap cleanup EXIT

if ! ip netns add "$ns" 2>"$out/namespace-error.txt"; then
  echo 'C02 failed to create network namespace' >&2
  exit 1
fi
ip netns exec "$ns" ip link show >"$out/topology.txt"
ip netns exec "$ns" ip addr show >>"$out/topology.txt"

printf '{"schema_version":1,"case":"C02-netns","run_id":"%s","passed":false,"terminal_code":"not_implemented","reason":"full namespace connectivity matrix is not implemented","artifacts":["topology.txt","namespace-error.txt"]}\n' "$run_id" >"$out/summary.json"
cat "$out/summary.json"
echo 'C02 namespace smoke only; full connectivity result is not claimed' >&2
exit 2
