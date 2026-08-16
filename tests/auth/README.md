# Plan 03 identity and authentication manual test runbook

Plan 03/03a verifies the bounded `/p2x/auth/1` protocol, persistent identities, exchange pinning, fixed-token authentication, tickets, long-running readiness recovery, secret redaction, and required connectivity non-regression.

Run commands from the repository root. The single owner-executed entry point is `tests/auth/manual.sh`.

## 1. Automated baseline and live auth cases

Before platform-specific testing, run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
cargo tree -e features
```

Canonical live cases use `./tests/auth/local.sh --case <name>`:

```text
valid-client              valid-server
wrong-token               wrong-peer
wrong-role                wrong-scope
revoked                   expired
pin-mismatch              rotation-overlap
rotation-revoke-old       unsupported-version
oversized-frame           malformed-frame
connection-limit          request-limit
session-limit             exchange-restart
```

Run every case above sequentially with:

```text
./tests/auth/local.sh --case all
```

Each case prepares run-scoped identities and credentials, validates schema and exact stable result codes, scans artifacts for secrets, and cleans up its process group. Results are written under `target/p2x-auth/<run-id>/`; `summary.json` is the case summary and `*.ndjson` files are the raw lifecycle records. The restart case passes only when the original client and server processes and PeerIds lose readiness and return at readiness generation 2.

## 2. Platform security check

Run once on native macOS and once on native Linux:

```text
./tests/auth/manual.sh --platform-security
```

The script creates temporary identities and proves that:

- group/other-readable identity permissions are rejected;
- a final-component identity symlink is rejected;
- backup/restore preserves the PeerId;
- generating replacement transport material changes the PeerId and therefore requires pin redistribution.

The temporary directory is removed automatically. A pass is one JSON line with the current platform and all four boolean fields set to `true`. No private key or temporary identity should be retained.

## 3. Linux connectivity regression

On a disposable Linux host with root or `CAP_NET_ADMIN`:

```text
sudo ./tests/auth/manual.sh --linux-connectivity
```

This delegates to the complete Plan 02 Linux namespace matrix. If Cargo is installed outside the sudo user's default Rustup location:

```text
sudo P2X_CARGO="$(command -v cargo)" ./tests/auth/manual.sh --linux-connectivity
```

All C02-C13 summaries must report `"passed": true`, including concurrency, large direct/relay transfer, renewal, and churn. Confirm `ip netns list` contains no run-scoped namespaces after completion.

## 4. Fuzz smoke

Install the required runner and nightly compiler once:

```text
cargo install cargo-fuzz
rustup toolchain install nightly --profile minimal
```

Then run:

```text
./tests/auth/manual.sh --fuzz-smoke
```

The script explicitly uses `cargo +nightly fuzz` even though the project compiler is pinned to stable Rust. It runs each target for ten seconds against its committed seed corpus:

- `auth_frame_decode`
- `token_parse`
- `ticket_claims_decode`
- `ticket_envelope_decode`

The fuzz check passes when all four commands finish normally without panic, sanitizer report, timeout artifact, out-of-bounds allocation behaviour, or accepted non-canonical value.

Fuzzing does not create a summary JSON. Evolved inputs are under `fuzz/corpus/<target-corpus>/`; crash/timeout inputs, if any, are under `fuzz/artifacts/<target>/`. An empty or absent `fuzz/artifacts` directory means no reproducer was emitted. Do not commit short smoke-run corpus growth by default; review and minimize a useful reproducer before deliberately adding it.

## 5. Packet, log, and artifact inspection

Start Wireshark or another packet capture on the loopback interface (`lo0` on macOS, normally `lo` on Linux), then run:

```text
./tests/auth/manual.sh --packet-inspection
```

Press Enter only after capture has started. The script runs the `valid-client` live flow and must print a passing summary containing `auth.pong`. Stop capture after the script returns.

Inspect packet bytes and application artifacts for plaintext secret markers. At minimum, search for `p2x1.`, `token_secret`, `token_sha256`, `raw_ticket`, private key/seed material, selectors, and private upstream values. None may appear. Transport metadata, PeerIds, protocol negotiation, packet sizes, and encrypted payload bytes are expected and are not secret leaks.

The live artifacts are under `target/p2x-auth/<run-id>/`. A PCAP is optional audit evidence and has no repository default path because Wireshark chooses it when saving. Store raw PCAPs outside Git unless they have been explicitly reviewed and scrubbed.

## 6. Required connectivity non-regression

For Plan 03 changes limited to the auth/product behaviour composition, rerun C01, C05, C10 with 128 streams, and C13 over both TCP and QUIC, plus the Linux namespace equivalents. Commands and pass criteria are in [`../connectivity/README.md`](../connectivity/README.md).

If Rust/libp2p versions, transport features, relay, DCUtR, Yamux, exact-stream handling, or connectivity timing changes, rerun the complete Plan 02 C01-C14 gate.

## 7. Completion record

Record the tested Git commit, host OS/kernel, command, UTC time, exit status, and relevant `summary.json` path. For owner-executed checks, a concise record may state:

- macOS platform security: passed;
- Linux platform security: passed;
- Linux namespace C02-C13: passed;
- four fuzz targets: passed with no artifact under `fuzz/artifacts`;
- packet/log/artifact inspection: passed with `auth.pong` and no plaintext secret marker.

Screenshots and PCAPs are optional unless required by an external audit. Never include reusable secrets in the completion record.
