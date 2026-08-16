# Connectivity test deployments

Each case is isolated in its own directory and contains its deployment/run script, required configuration, artifact contract, and collection instructions.

| Environment | Cases | Entry point |
|---|---|---|
| Native local | C01, C05-C13 | `tests/connectivity/local.sh --case <id>` |
| Linux namespaces | C02-C13 | `tests/connectivity/manual-gates.sh --linux` |
| Two native hosts | C14 | `tests/two-host/C14-relay/start-exchange.sh`, `start-server.sh`, `run-client.sh`, then the canonical validator |

Plan 03 owner-executed platform, Linux namespace, fuzz, and packet-inspection checks use the single `tests/auth/manual.sh` entry point with `--platform-security`, `--linux-connectivity`, `--fuzz-smoke`, or `--packet-inspection`.
The fuzz mode requires both `cargo-fuzz` and a rustup-managed nightly toolchain; it invokes `cargo +nightly fuzz` explicitly even though the project compiler is pinned to stable Rust.

Every run records the run ID, raw per-process NDJSON, topology/fault state, resource samples, client terminal result(s), server-observed paths, and cleanup status. Environment-unavailable cases fail with exit code 2 and are never reported as passed. `tests/local/run.sh` is a compatibility redirect to the canonical local runner; it does not define weaker case meanings.
