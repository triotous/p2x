# Resolution and proxy authorization tests

Plan 05's canonical local entry point is:

```text
./tests/resolution/local.sh --case <name>
```

The runner is intentionally finite and currently validates the automatable protocol/state seams: target-file validation, canonical resolve/proxy frames, metadata-only caching, ticket ownership, replay rejection, and product surface construction. Full live exchange/server route opens require the Phase 4 ingress/upstream implementation and remain incomplete rather than being represented by a Ping result.

The planned case names are `resolve-ticket-tcp`, `resolve-ticket-quic`, `unknown-selector`, `offline-selector`, `cross-tenant`, `idempotent-resolve`, `forced-relay`, `direct-preferred`, `direct-open-fallback`, `ticket-replay`, `ticket-bindings`, `ticket-expiry`, `registration-revision-change`, `connection-reuse`, `concurrent-opens`, `resolve-limit`, `proxy-limit`, `exchange-restart`, `server-restart`, and `graceful-drain`. Cases not yet backed by a complete product route-open flow return status 2 with an explicit incomplete message.

All artifacts belong below `target/`, use run-scoped temporary identities and files, and are scanned for credentials, sessions, raw tickets, raw selector values, and private targets. Availability of loopback listeners is required for future network cases.
