#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
mode=${1:-}

case "$mode" in
  --platform-security)
    cd "$root"
    cargo build -q -p p2x-config --example identity-id
    work=$(mktemp -d "${TMPDIR:-/tmp}/p2x-platform-security.XXXXXX")
    cleanup() { rm -rf "$work"; }
    trap cleanup EXIT
    chmod 700 "$work"
    identity_bin="$root/target/debug/examples/identity-id"
    identity="$work/identity.key"
    original_peer=$($identity_bin "$identity" --generate)

    chmod 0644 "$identity"
    if $identity_bin "$identity" >/dev/null 2>&1; then
      echo "unsafe identity permissions were accepted" >&2
      exit 1
    fi
    chmod 0600 "$identity"

    ln -s "$identity" "$work/identity-link.key"
    if $identity_bin "$work/identity-link.key" >/dev/null 2>&1; then
      echo "identity symlink was accepted" >&2
      exit 1
    fi

    cp "$identity" "$work/identity-backup.key"
    chmod 0600 "$work/identity-backup.key"
    restored_peer=$($identity_bin "$work/identity-backup.key")
    [[ "$restored_peer" == "$original_peer" ]] || { echo "backup/restore changed PeerId" >&2; exit 1; }

    replacement_peer=$($identity_bin "$work/replacement.key" --generate)
    [[ "$replacement_peer" != "$original_peer" ]] || { echo "replacement did not change PeerId" >&2; exit 1; }
    printf '{"platform":"%s","permissions_rejected":true,"symlink_rejected":true,"backup_restore_stable":true,"replacement_changes_peer_id":true}\n' "$(uname -s)"
    ;;
  --linux-connectivity)
    [[ "$(uname -s)" == Linux ]] || { echo "--linux-connectivity must run on Linux" >&2; exit 2; }
    exec "$root/tests/connectivity/manual-gates.sh" --linux
    ;;
  --fuzz-smoke)
    cd "$root"
    cargo fuzz --help >/dev/null 2>&1 || {
      echo "cargo-fuzz is required; install it with: cargo install cargo-fuzz" >&2
      exit 2
    }
    cargo fuzz run auth_frame_decode fuzz/corpus/auth_frame -- -max_total_time=10
    cargo fuzz run token_parse fuzz/corpus/token_parse -- -max_total_time=10
    cargo fuzz run ticket_claims_decode fuzz/corpus/ticket_claims -- -max_total_time=10
    cargo fuzz run ticket_envelope_decode fuzz/corpus/ticket_envelope -- -max_total_time=10
    ;;
  --packet-inspection)
    echo "Start a packet capture on the loopback interface before continuing; press Enter when ready." >&2
    read -r
    "$root/tests/auth/local.sh" --case valid-client
    echo "Stop the capture and verify that it contains no plaintext token, digest, private key, raw ticket, selector, or private upstream value." >&2
    ;;
  *)
    echo "usage: $0 --platform-security | --linux-connectivity | --fuzz-smoke | --packet-inspection" >&2
    exit 2
    ;;
esac
