# Resolution and proxy authorization tests

Plan 05a's canonical local entry point is:

```text
./tests/resolution/local.sh --case <name|all>
```

The runner creates run-scoped identities, credentials, ticket key/ring, ports, service/routes files, subprocesses, NDJSON artifacts, one summary, cleanup, and privacy scans. It rejects malformed lifecycle JSON, duplicate/missing terminals, unobserved guarded faults, mismatched fingerprints/correlations, leaked credentials/session/ticket/private selector values, and nonzero exchange resources. Generated output belongs below `target/`.

All 20 declared names are executable entry points. Evidence-backed local cases are:

- `resolve-ticket-tcp`, `resolve-ticket-quic`: real authenticated Resolve and correlated empty Authorized over TCP/QUIC exchange transport;
- `unknown-selector`, `offline-selector`, `cross-tenant`: scoped rejection and no authorization;
- `idempotent-resolve`: drop-after-cache retransmission, identical request/response fingerprints, and one issuance;
- `forced-relay`, `direct-preferred`: exact path selection;
- `direct-open-fallback`: guarded direct pre-handshake failure followed by one exact relay open using the same grant;
- `ticket-replay`: first authorization plus one-use replay rejection;
- `ticket-expiry`: five-second ticket expiry with skew zero and no authorization;
- `connection-reuse`: two independent resolve/ticket/stream operations reusing the selected connection;
- `concurrent-opens`: 64 independently correlated resolve, exact-open, ticket, and stream results.

The runner intentionally fails these names with explicit missing-evidence errors until their complete required matrix is implemented: `ticket-bindings` (the full binding subcase matrix; only a ticket-byte representative is wired), `registration-revision-change`, `resolve-limit`, `proxy-limit`, `exchange-restart`, `server-restart`, and `graceful-drain`. They are not aliases for a normal successful authorization and do not emit passing summaries.

Guarded finite-diagnostic controls require `P2X_ENABLE_TEST_HOOKS=1` and are bounded by the CLI: proxy open count/concurrency 1–128, delay and handshake hold 0–10,000ms, and closed mutation choices. Exchange response drop/hold controls and server worker verification controls use the same guard. Hook execution is observable as `test_fault_applied`. Normal product defaults are unchanged.

Each successful summary has `case`, `passed`, and `observed_assertions`. The assertions include client terminal, client↔exchange resolution correlation, client↔server authorization correlation where applicable, exact selected connection where applicable, and clean privacy scan. Case-specific checks add fingerprint/issuance cardinality, path order, replay rejection, expiry rejection, stream uniqueness, or 64-open cardinality.

After local resolution gates, run the existing regressions:

```text
./tests/auth/local.sh --case all
./tests/registry/local.sh --case all
./tests/connectivity/local.sh --case all
```

Required owner-executed checks remain incomplete until performed: Linux namespace matrix, two-host C14, real firewall/NAT/packet inspection, native Linux/macOS direct/relay platform coverage, long churn/load/soak, and deployment packaging. No Ping result, case name, synthetic response, or server-only event substitutes for proxy authorization evidence.
