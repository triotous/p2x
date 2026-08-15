#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
  echo "This installer requires Linux" >&2
  exit 2
fi

command -v pacman >/dev/null || {
  echo "This installer targets Manjaro/Arch and requires pacman" >&2
  echo "Install manually: jq iproute2 iptables nftables" >&2
  exit 2
}

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  pacman -Syu --needed jq iproute2 iptables nftables
else
  command -v sudo >/dev/null || {
    echo "sudo is required when not running as root" >&2
    exit 2
  }
  sudo pacman -Syu --needed jq iproute2 iptables nftables
fi

for command_name in jq ip iproute tc iptables nft; do
  command -v "$command_name" >/dev/null || {
    echo "installation failed: missing $command_name" >&2
    exit 1
  }
done

printf 'installed tools:\n'
printf '  jq: %s\n' "$(jq --version)"
printf '  ip: %s\n' "$(ip -V 2>&1)"
printf '  tc: %s\n' "$(tc -V 2>&1)"
printf '  iptables: %s\n' "$(iptables --version 2>&1)"
printf '  nft: %s\n' "$(nft --version 2>&1)"

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
  ip netns list >/dev/null
else
  sudo ip netns list >/dev/null
fi
printf 'network namespace access: available\n'
