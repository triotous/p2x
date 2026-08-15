#!/usr/bin/env bash
set -euo pipefail

[[ "$(uname -s)" == Linux ]] || { echo "netns cases require Linux" >&2; exit 2; }
for tool in ip iptables tc ps; do command -v "$tool" >/dev/null || { echo "netns cases require $tool" >&2; exit 2; }; done
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "netns cases require root/CAP_NET_ADMIN" >&2; exit 2; }

root=$(cd "$(dirname "$0")/../.." && pwd)
case_id=""
forward=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --case) case_id="${2:?missing case id}"; shift 2 ;;
    --case=*) case_id="${1#*=}"; shift ;;
    --streams|--bytes|--path|--iterations) forward+=("$1" "${2:?missing value}"); shift 2 ;;
    *) echo "unsupported argument: $1" >&2; exit 2 ;;
  esac
done
case "$case_id" in C02|C03|C04|C05|C06|C07|C08|C09|C10|C11|C12|C13) ;; *) echo "usage: $0 --case C02..C13" >&2; exit 2 ;; esac

run_id=${P2X_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}
[[ "$run_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { echo "unsafe run id" >&2; exit 2; }
suffix=$(printf '%05d' $(( $$ % 100000 )))
bridge="p2xb${suffix}"
exchange_ns="p2x${suffix}e"
server_ns="p2x${suffix}s"
client_ns="p2x${suffix}c"
namespaces=("$exchange_ns" "$server_ns" "$client_ns")
host_links=("p2x${suffix}he" "p2x${suffix}hs" "p2x${suffix}hc")
peer_ips=(10.203.0.2 10.203.0.3 10.203.0.4)

cleanup_topology() {
  trap - EXIT INT TERM
  for ns in "${namespaces[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
  ip link del "$bridge" 2>/dev/null || true
}
trap cleanup_topology EXIT INT TERM

if ! ip link add "$bridge" type bridge; then
  cat >&2 <<'EOF'
unable to create the Linux bridge required by the connectivity matrix.
Run this gate on a native Linux host or VM whose kernel enables CONFIG_BRIDGE
(and exposes bridge plus veth networking to this environment). sudo alone
cannot add kernel features that the host/container runtime does not provide.
EOF
  exit 2
fi
ip addr add 10.203.0.1/24 dev "$bridge"
ip link set "$bridge" up
for index in 0 1 2; do
  ns=${namespaces[$index]}
  host_link=${host_links[$index]}
  ip netns add "$ns"
  ip link add "$host_link" type veth peer name eth0 netns "$ns"
  ip link set "$host_link" master "$bridge"
  ip link set "$host_link" up
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip addr add "${peer_ips[$index]}/24" dev eth0
  ip netns exec "$ns" ip link set eth0 up
done

case "$case_id" in
  C02)
    ip netns exec "$client_ns" iptables -A OUTPUT -d 10.203.0.3 -p tcp -j REJECT
    ip netns exec "$server_ns" iptables -A OUTPUT -d 10.203.0.4 -p tcp -j REJECT
    ;;
  C03)
    ip netns exec "$client_ns" iptables -A OUTPUT -d 10.203.0.3 -p udp -j REJECT
    ip netns exec "$server_ns" iptables -A OUTPUT -d 10.203.0.4 -p udp -j REJECT
    ;;
  C04)
    for protocol in tcp udp; do
      ip netns exec "$client_ns" iptables -A OUTPUT -d 10.203.0.3 -p "$protocol" -j REJECT
      ip netns exec "$server_ns" iptables -A OUTPUT -d 10.203.0.4 -p "$protocol" -j REJECT
    done
    ;;
esac

export P2X_RUN_ID="$run_id"
export P2X_EXCHANGE_TCP_LISTEN=/ip4/10.203.0.2/tcp/4001
export P2X_EXCHANGE_QUIC_LISTEN=/ip4/10.203.0.2/udp/4001/quic-v1
export P2X_SERVER_TCP_LISTEN=/ip4/10.203.0.3/tcp/0
export P2X_SERVER_QUIC_LISTEN=/ip4/10.203.0.3/udp/0/quic-v1
export P2X_CLIENT_TCP_LISTEN=/ip4/10.203.0.4/tcp/0
export P2X_CLIENT_QUIC_LISTEN=/ip4/10.203.0.4/udp/0/quic-v1
EXCHANGE_CMD=(ip netns exec "$exchange_ns" "$root/target/debug/p2x-exchange")
SERVER_CMD=(ip netns exec "$server_ns" "$root/target/debug/p2x-server")
CLIENT_CMD=(ip netns exec "$client_ns" "$root/target/debug/p2x-client")

meta_dir=${P2X_ARTIFACT_DIR:-target/p2x-spike/$run_id}/$case_id
mkdir -p "$meta_dir"
{
  echo "bridge=$bridge"
  for ns in "${namespaces[@]}"; do
    echo "namespace=$ns"
    ip netns exec "$ns" ip -brief address
    ip netns exec "$ns" iptables -S
  done
} >"$meta_dir/topology.txt"

for ((index=0; index<${#forward[@]}; index+=2)); do
  case "${forward[$index]}" in
    --streams) export P2X_STREAMS="${forward[$((index+1))]}" ;;
    --bytes) export P2X_BYTES="${forward[$((index+1))]}" ;;
    --path) export P2X_PATH="${forward[$((index+1))]}" ;;
    --iterations) export P2X_ITERATIONS="${forward[$((index+1))]}" ;;
  esac
done

cd "$root"
. "$root/tests/connectivity/common.sh"
run_local_case "$case_id"
