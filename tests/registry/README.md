# Registry verification

Run `./tests/registry/local.sh --case <name>` from the repository root. The executable product-process cases are `valid-tcp`, `valid-quic`, and `exchange-restart`; `all` runs all three.

The harness builds the real binaries, creates run-scoped identities, credentials, ticket key, service configuration, and ports, then starts the exchange, server, and client. It machine-checks authenticated reservation/registration readiness, a registration refresh, client authentication, graceful server shutdown, lifecycle privacy, and—for `exchange-restart`—same-PID/PeerId readiness recovery. Summaries and NDJSON evidence are written below `target/p2x-registry/`.

Conflict, cross-tenant, authorization-denial, lease-expiry, request/service/relay boundary, revocation, packet-capture, and multi-host cases remain owner-executed verification. They are not accepted case names here and are not implied by `all`; the focused Rust tests cover their pure state and admission invariants where applicable.
