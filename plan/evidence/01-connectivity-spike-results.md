# Connectivity spike results

**Status:** incomplete; architecture gate not run

The repository now has a pinned Rust workspace, exact `libp2p = 0.56.0` dependency resolution, three lifecycle binaries, and deterministic connection/path/reservation/header tests. The actual relay, DCUtR, exact-`ConnectionId` stream, process, namespace, slow-reader, interruption, and two-host matrix was not run.

## Reproducible checks

- Toolchain: Rust/Cargo 1.96.0
- Dependency: `libp2p` 0.56.0 (resolved transitive versions are in `Cargo.lock`)
- Commands: `cargo fmt --all`, `cargo test --workspace --all-targets`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Result: passed for the implemented deterministic contracts

## Not run

C01–C14 were not claimed: no libp2p swarm lifecycle/relay implementation exists yet; Linux namespace cases require Linux `CAP_NET_ADMIN`; C14 requires two real machines. No peer IDs, private keys, payloads, or credentials are recorded.
