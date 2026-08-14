# C01 local smoke

Runs the three binaries with a shared run ID and validates versioned NDJSON. This case is a lifecycle smoke check; relay/path assertions belong to C05-C13.

## Prerequisites

- Rust toolchain from `rust-toolchain.toml`
- `jq`
- loopback TCP ports available

## Run

```sh
./run.sh
```

Artifacts are written below `${P2X_ARTIFACT_DIR:-target/p2x-spike/<run-id>}/C01-smoke/`:
`exchange.ndjson`, `server.ndjson`, `client.ndjson`, `summary.json`, and `processes.txt`.

Collect stdout/stderr, exit status, run ID, peer IDs, listen addresses, terminal count, and validation errors.
