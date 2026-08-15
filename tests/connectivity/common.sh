#!/usr/bin/env bash
# Shared process ownership, readiness parsing, typed NDJSON checks, and cleanup.
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
. "$root/tests/local/common.sh"

build_linux_binaries() {
  [[ "${P2X_SKIP_BUILD:-0}" == 1 ]] && return 0

  local cargo_bin=${P2X_CARGO:-}
  local build_user=${SUDO_USER:-}
  local build_home=""

  if [[ -n "$build_user" && "$build_user" != root ]]; then
    build_home=$(getent passwd "$build_user" | cut -d: -f6)
    [[ -n "$cargo_bin" ]] || cargo_bin="$build_home/.cargo/bin/cargo"
    [[ -x "$cargo_bin" ]] || {
      echo "cargo for $build_user was not found at $cargo_bin; rerun with P2X_CARGO=/absolute/path/to/cargo" >&2
      exit 2
    }
    sudo -u "$build_user" env HOME="$build_home" "$cargo_bin" build --manifest-path "$root/Cargo.toml" --workspace --bins
  else
    [[ -n "$cargo_bin" ]] || cargo_bin=$(command -v cargo || true)
    [[ -n "$cargo_bin" && -x "$cargo_bin" ]] || {
      echo "cargo was not found; set P2X_CARGO=/absolute/path/to/cargo" >&2
      exit 2
    }
    "$cargo_bin" build --manifest-path "$root/Cargo.toml" --workspace --bins
  fi
  export P2X_SKIP_BUILD=1
}
