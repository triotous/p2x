# Client connection operations (Phase 3)

Product clients require `--routes-file <path>`. The strict YAML schema is:

```yaml
schema_version: 1
network:
  direct_preference_ms: 1500
  connection_setup_timeout_ms: 20000
targets:
  - route_id: orders
    selector:
      protocol: http
      metadata: {service: orders, environment: production, region: eu-west}
limits:
  max_peer_states: 64
  max_pending_setups: 128
  max_pending_per_server: 64
```

There are 1–256 unique bounded route IDs. Selectors are exact canonical protocol values. Direct preference is 0–5,000 ms; setup timeout is 1,000–20,000 ms; preference is strictly below setup timeout unless zero. Peer, global pending, and per-server pending defaults are 64, 128, and 64, with hard maximums 256, 512, and 128. The route file contains no domain, bind address, URL, upstream address, certificate, secret, or ingress policy.

The resolver caches metadata only: server PeerId, upstream ID, selector fingerprint, registration revision, relay addresses, capability intersection, and registration expiry. It never caches a ticket. Positive metadata is clipped to registration expiry. `registry.not_found` and `registry.offline` may be negative-cached for one second; authentication, protocol, limit, drain, and transport failures are not negative-cached. Cache keys include the session principal binding and complete selector. One logical waiter receives one eventual one-use ticket; metadata and peer-connect work may be shared, ticket ownership may not.

A route open has one absolute setup budget covering resolve, relay dial, DCUtR direct preference, exact connection selection, proxy negotiation, and authorization. A healthy confirmed direct connection is selected immediately. Otherwise one validated relay dial is shared per server, DCUtR is attempted, and a newly confirmed direct path wins before preference expiry. Relay is selected on terminal direct failure or deadline. Opens always target an exact `ConnectionId`, never a generic dial.

A pre-handshake direct exact-open failure may fall back once to the prepared relay with the same grant. After Open bytes may have reached the server, the ticket is ambiguous and cannot be reused; a retry requires a fresh resolve/ticket and the same absolute deadline. `peer.connection_failed`, `peer.setup_timeout`, and `limit.*` are bounded terminal/retry outcomes. Server drain and stale registration cause fresh resolution.

The current Phase 3 diagnostic proves only a correlated server `Authorized` response for an empty stream and exits. It is not a usable ingress/data tunnel. Phase 4 will attach fixed TCP ingress, server-local upstream routing, final `Accepted`, and bounded byte copying. Exchange/server restart, reservation loss, and registration replacement invalidate stale metadata or grants and later opens recover through fresh resolution.

Diagnostics use route/selector/peer fingerprints and opaque connection hashes. They do not contain raw selector metadata, tickets, ticket IDs, sessions, credentials, or private targets. Shutdown rejects new route opens, cancels bounded waiters/work, closes owned streams/connections, and zeroizes ticket buffers.
