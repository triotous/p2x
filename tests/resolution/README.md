# Resolution and proxy authorization tests

Plan 05a's canonical local entry point is:

```text
./tests/resolution/local.sh --case <name|all>
```

The runner creates run-scoped identities, credentials, ticket key/ring, ports, service/routes files, subprocesses, NDJSON artifacts, one summary, cleanup, and privacy scans. It rejects malformed lifecycle JSON, duplicate/missing terminals, unobserved guarded faults, mismatched fingerprints/correlations, leaked credentials/session/ticket/private selector values, and nonzero exchange resources. Generated output belongs below `target/`.

All 20 declared names are executable entry points and pass through the current real-product process harness. Evidence-backed local cases are:

- `resolve-ticket-tcp`, `resolve-ticket-quic`: real authenticated Resolve and correlated empty Authorized over TCP/QUIC exchange transport;
- `unknown-selector`, `offline-selector`, `cross-tenant`: scoped rejection and no authorization;
- `idempotent-resolve`: drop-after-cache retransmission, identical request/response fingerprints, and one issuance;
- `forced-relay`, `direct-preferred`: exact path selection;
- `direct-open-fallback`: guarded direct pre-handshake failure followed by one exact relay open using the same grant;
- `ticket-replay`: first authorization plus one-use replay rejection;
- `ticket-expiry`: five-second ticket expiry with skew zero and no authorization;
- `connection-reuse`: two independent resolve/ticket/stream operations reusing the selected connection;
- `concurrent-opens`: 64 independently correlated resolve, exact-open, ticket, and stream results.

The process cases `registration-revision-change`, `resolve-limit`, `proxy-limit`, `exchange-restart`, and `server-restart` exercise replacement, exact N/N+1 admission, and restart recovery with persisted identities. `graceful-drain` runs the required server-drain, exchange-drain, and client-cancel subcases. `ticket-bindings` runs the exhaustive same-process admission matrix (issuer, client/server peer, tenant, upstream, selector fingerprint, both revisions, permissions, max streams, not-before, verification key) plus a guarded real ticket-byte mutation, and lists all subcases in its passing summary.

Guarded finite-diagnostic controls require `P2X_ENABLE_TEST_HOOKS=1` and are bounded by the CLI: proxy open count/concurrency 1–128, delay and handshake hold 0–10,000ms, and closed mutation choices. Exchange response drop/hold controls and server worker verification controls use the same guard. Hook execution is observable as `test_fault_applied`. Normal product defaults are unchanged.

Each successful summary has `case`, `passed`, and `observed_assertions`. The assertions include client terminal, client↔exchange resolution correlation, client↔server authorization correlation where applicable, exact selected connection where applicable, and clean privacy scan. Case-specific checks add fingerprint/issuance cardinality, path order, replay rejection, expiry rejection, stream uniqueness, or 64-open cardinality.

After local resolution gates, run the existing regressions:

```text
./tests/auth/local.sh --case all
./tests/registry/local.sh --case all
./tests/connectivity/local.sh --case all
```

Required owner-executed checks remain separate from this local gate: Linux namespace matrix, two-host C14, real firewall/NAT/packet inspection, native Linux/macOS direct/relay platform coverage, long churn/load/soak, and deployment packaging. No Ping result, case name, synthetic response, or server-only event substitutes for proxy authorization evidence.
