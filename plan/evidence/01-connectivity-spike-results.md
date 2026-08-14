# Connectivity spike results

**Status:** incomplete; architecture gate not accepted

## Implemented baseline

- Rust toolchain: 1.96.0
- `libp2p`: exactly 0.56.0, with resolved component versions recorded in the committed `Cargo.lock`
- Workspace binaries: `p2x-exchange`, `p2x-server`, `p2x-client`
- Concrete TCP/QUIC exchange and peer swarm builders with relay, Identify, Ping, DCUtR, and exact-connection `/p2x/spike/1` behaviour
- Deterministic lab-only identity seeds and bounded frame/codec/state-machine unit tests
- Harness entry points now fail clearly and preserve a JSON artifact for unsupported cases

## Reproducible checks

- `cargo fmt --all -- --check` — passed
- `cargo test --workspace --all-targets` — passed
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` — passed
- `cargo deny check` — not run successfully: the `cargo-deny` subcommand is not installed (`no such command: deny`)

## Connectivity cases

C01–C14 are **not passed**. The live relay reservation/renewal lifecycle, probe payload exchange, namespace matrix, and C14 two-host run were not completed in this environment. The scripts record unsupported cases below `target/p2x-spike/<run-id>/` and exit non-zero. No peer private keys, seeds, payloads, credentials, or reusable identities are recorded.

The architecture gate therefore remains deferred. Do not begin identity/authentication, registry, ticket, ingress, or production proxy work.
