# Plan 02 connectivity manual test runbook

Plan 02 proves the accepted libp2p connectivity architecture across native processes, controlled Linux namespaces, and two real networks. These environments are complementary: a local pass cannot replace Linux namespace coverage, and neither can replace C14.

Canonical runners write typed per-process NDJSON, summaries, topology, and resource samples below `target/p2x-spike/<run-id>/`. Missing prerequisites and unavailable environments exit non-zero; no unsupported case is reported as passed.

### Case reference

| Case | Condition | Required observation |
|---|---|---|
| C01 | Same host with TCP and QUIC enabled | Relay becomes ready, DCUtR selects direct, and the probe succeeds |
| C02 | Peer-to-peer TCP blocked | Direct QUIC is selected, not relay |
| C03 | Peer-to-peer UDP blocked | Direct TCP is selected, not relay |
| C04 | All peer-to-peer traffic blocked; exchange reachable | Relay succeeds within the setup deadline |
| C05 | Direct and relay coexist | Exact opens on each connection are observed as direct and relay by both endpoints |
| C06 | Terminal DCUtR outcome suppressed | Relay commits after the bounded direct deadline without hanging |
| C07 | Exchange stopped during active direct half-close transfer | Direct transfer completes and relay readiness becomes degraded |
| C08 | Selected connection dropped during payload | Active stream fails, then a later request reconnects and succeeds in the same process |
| C09 | Low relay reservation/circuit limits | Excess work is denied without starving admitted control/events |
| C10 | 64 concurrent probes, then 128 headroom probes | Correct independent results, bounded queues/resources, and no wrong-connection opens |
| C11 | 256 MiB direct and relay slow-reader transfers | Hash/half-close correctness, bounded RSS, and a concurrent nonce remains responsive |
| C12 | Reservation lifetime crosses two renewal points | At least two renewals and a continuously dialable circuit address |
| C13 | 100 direct connect-close churn iterations | No leaked tasks, listeners, records, permits, RSS, or file descriptors |
| C14 | Two real hosts on separate networks | Relay succeeds; direct outcome and environment are recorded honestly |

## 1. Common prerequisites

From a clean checkout of the commit being verified:

```text
rustc --version
cargo --version
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny --version
cargo deny check
```

The repository pins Rust through `rust-toolchain.toml`. Dependency verification uses `cargo-deny 0.20.2`. Record the Git commit, OS/kernel, UTC time, and `git status --short` with externally collected evidence.

## 2. Native local matrix

Run on each supported native platform required by the change. The full Plan 02 local matrix is:

```text
./tests/connectivity/local.sh --case C01
./tests/connectivity/local.sh --case C05
./tests/connectivity/local.sh --case C06
./tests/connectivity/local.sh --case C07
./tests/connectivity/local.sh --case C08
./tests/connectivity/local.sh --case C09
./tests/connectivity/local.sh --case C10 --streams 64
./tests/connectivity/local.sh --case C10 --streams 128
./tests/connectivity/local.sh --case C11 --bytes 268435456 --path direct
./tests/connectivity/local.sh --case C11 --bytes 268435456 --path relay
./tests/connectivity/local.sh --case C12
./tests/connectivity/local.sh --case C13 --iterations 100
```

Run that exact matrix sequentially with:

```text
./tests/connectivity/local.sh --case all
```

Add `--exchange-transport quic` to repeat an applicable local case through the exchange QUIC listener; TCP is the default.

A case passes only when its emitted `summary.json` contains `"passed": true`, client and server observations agree with the required path/fault, each finite endpoint emits exactly one terminal, and final logical resource counts are zero. Do not infer a pass from process exit alone.

For a Plan 03 change that only affects composed product/auth behaviour, the minimum connectivity regression is C01, C05, C10 with 128 streams, and C13 over TCP and QUIC. Changes to Rust/libp2p versions, transport features, relay, DCUtR, Yamux, exact-stream handling, or connectivity timing require the complete affected Plan 02 matrix, and a Rust/libp2p baseline change requires C01-C14.

## 3. Linux namespace matrix

Use a disposable Linux host with root or `CAP_NET_ADMIN`, plus `ip`, `iptables` or `nft`, `tc`, `ps`, and `jq`:

```text
sudo ./tests/connectivity/manual-gates.sh --linux
```

If Cargo is not under the original sudo user's `~/.cargo/bin`:

```text
sudo P2X_CARGO="$(command -v cargo)" ./tests/connectivity/manual-gates.sh --linux
```

Linux mode compiles as the original `SUDO_USER` before creating namespaces, so Cargo does not run as root. By default it expects Cargo at that user's `~/.cargo/bin/cargo`; use `P2X_CARGO` for another installation layout.

The runner creates three run-scoped namespaces and scoped firewall/traffic-control rules, executes C02-C13, including 64/128 concurrency and direct/relay 256 MiB variants, and removes only resources derived from its validated run ID. After completion, confirm no test namespace remains with `ip netns list`. Detailed single-case setup is in [`../linux/C02-netns/README.md`](../linux/C02-netns/README.md).

## 4. C14 on two real networks

C14 requires two native hosts on separate networks, the same clean Git commit and run ID on both, synchronized UTC clocks, and reachable exchange TCP/UDP ports. Follow [`two-host.md`](two-host.md) exactly for exchange, server, client, firewall, environment capture, teardown, and redaction.

After merging `exchange.ndjson`, `server.ndjson`, `client.ndjson`, and `environment.txt` into one artifact directory, validate it with:

```text
./tests/connectivity/manual-gates.sh --c14-validate target/p2x-spike/<run-id>/C14-relay
```

C14 passes only when relay succeeds across the two physical networks, the server observes the relay probe, all components share the same run ID and Git commit, each has one final terminal with zero logical resources, and the validator writes `summary.json`. Direct success is topology-dependent and must be recorded honestly rather than forced.

## 5. Artifacts and retention

- Default output: `target/p2x-spike/<run-id>/`.
- Per-process evidence: `exchange.ndjson`, `server.ndjson`, `client.ndjson`, and separate stderr logs.
- Linux evidence: case summaries, topology, namespace/interface/rule state, and resource samples.
- C14 evidence: the three NDJSON files, manually assembled `environment.txt`, and validator-created `summary.json`.
- Preserve raw failures outside Git until diagnosed. Commit only scrubbed summaries/evidence selected by the project owner.
- Never commit seeds, private keys, reusable identities, or unsanitized public/private network details.
