# Resolution and proxy authorization tests

Plan 05's canonical local entry point is:

```text
./tests/resolution/local.sh --case <name>
```

The runner is intentionally finite and validates real product binaries for the currently supported cases: TCP/QUIC resolve-to-Authorized, forced relay, direct preference, unknown selector, offline selector, and cross-tenant rejection. It checks client↔exchange resolution correlation, client↔server authorization correlation, exact selected connection, registration, cleanup, and privacy. Plan 05's empty `Authorized` gate does not require Phase 4 ingress; the remaining matrix cases return status 2 until their required fault injection/restart/concurrency controls exist. No Ping result is accepted as proxy evidence.

Supported cases are `resolve-ticket-tcp`, `resolve-ticket-quic`, `unknown-selector`, `offline-selector`, `cross-tenant`, `forced-relay`, and `direct-preferred`. The planned but currently incomplete cases are `idempotent-resolve`, `direct-open-fallback`, `ticket-replay`, `ticket-bindings`, `ticket-expiry`, `registration-revision-change`, `connection-reuse`, `concurrent-opens`, `resolve-limit`, `proxy-limit`, `exchange-restart`, `server-restart`, and `graceful-drain`; each returns status 2 with an explicit incomplete message.

All artifacts belong below `target/`, use run-scoped temporary identities and files, and are scanned for credentials, sessions, raw tickets, raw selector values, and private targets. Availability of loopback listeners is required.
