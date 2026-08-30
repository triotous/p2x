# Client connection operations (Plan 05a)

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
  max_route_opens: 128
```

There are 1–256 unique bounded route IDs. Selectors are exact canonical protocol values. Direct preference is 0–5,000 ms; setup timeout is 1,000–20,000 ms; preference is strictly below setup timeout unless zero. Peer, global pending, and per-server pending defaults are 64, 128, and 64, with hard maximums 256, 512, and 128. `max_route_opens` defaults to 128 and is bounded to 128. Fixed raw TCP ingress is configured separately under `raw_tcp`; each listener is uniquely named, bound only to a loopback nonzero `SocketAddr`, and references exactly one TCP target. The route file contains no URL, upstream address, certificate, or secret. The client binds listeners before exchange dialing, starts setup timing at local accept, buffers at most one configured copy buffer before Accepted, and treats per-socket failures as nonfatal.

Accepted raw streams retain their selected P2P connection until tunnel terminal; active stream accounting is separate from pending setup accounting and is released exactly once. A direct or relay P2P loss resets that active local stream without transparent retry. The resolver caches metadata only: server PeerId, upstream ID, selector fingerprint, registration revision, relay addresses, capability intersection, and registration expiry. It never caches a ticket. Positive metadata is clipped to registration expiry. `registry.not_found` and `registry.offline` may be negative-cached for one second using the supplied state clock; authentication, protocol, limit, drain, and transport failures are not negative-cached. Cache keys include the session principal binding and complete selector. One logical waiter receives one eventual one-use ticket; metadata and peer-connect work may be shared, ticket ownership may not. Resolver state exposes pending, queued, waiter, cache, and zero-ticket counts for tests.

`RouteOpenSupervisor` owns independently correlated bounded opens: OpenId, canonical selector/binding/session, resolve request/wire ID, move-owned grant, server/revision, path attempt, selected connection, absolute setup deadline, retransmission count, fresh-ticket retry count, handshake state, and terminal state. Product success/rejection and repeated-open diagnostics use this owner; mutation, replay, delayed-restart, and forced-fallback controls retain their focused single-open diagnostic paths. It promotes queued resolver waiters after terminals/cancellation and rejects late or deadline-equal responses that do not match a live authoritative request owner. The main swarm remains the sole executor and applies bounded route actions.

A route open has one absolute setup budget covering resolve, relay dial, DCUtR direct preference, exact connection selection, proxy negotiation, and authorization. A healthy confirmed direct connection is selected immediately. Otherwise one validated relay dial is shared per server, DCUtR is attempted, and a newly confirmed direct path wins before preference expiry. Relay is selected on terminal direct failure or deadline. Opens always target an exact `ConnectionId`, never a generic dial.

A pre-handshake direct exact-open failure may fall back once to the prepared relay with the same grant. After Open bytes may have reached the server, the ticket is ambiguous and cannot be reused; a retry requires a fresh resolve/ticket and the same absolute deadline. `peer.connection_failed`, `peer.setup_timeout`, and `limit.*` are bounded terminal/retry outcomes. Server drain and stale registration cause fresh resolution.

Guarded finite-diagnostic controls are bounded and require `P2X_ENABLE_TEST_HOOKS=1`: repeated proxy-open count/concurrency (1–128), post-resolve delay, first-ticket replay, ticket/upstream/revision mutation, direct pre-handshake failure, and proxy handshake hold. The locally executable cases use these controls to prove idempotent Resolve, direct fallback, replay rejection, expiry, sequential connection reuse, 128 independent opens through a real 64-open owner window, N/N+1 resolve and proxy limits, registration replacement, exchange/server restart recovery, and graceful drain. The raw TCP process gate separately proves 64 concurrent Accepted streams with 128-stream server headroom. The complete binding matrix is covered by same-process admission tests plus a real ticket mutation.

Product-mode failures use one completion transaction for the affected local ingress: resolve, path, proxy, connection, deadline, capacity, and pre-Accept EOF/I/O failures remove the route/wire/resolver/manager/command/cancel owners, promote the next same-selector waiter, release the ingress, and continue the client loop. Pre-Accept local EOF/error emits one cancellation event immediately. Per-server capacity counts active plus pending setup owners literally against `max_streams_per_server`; setup and active records are moved or removed exactly once and their counts/high-water transitions are checked. Accepted path and setup duration are immutable active-owner fields used by both Accepted and terminal records.

Diagnostics use route/selector/peer fingerprints and opaque connection hashes. They do not contain raw selector metadata, tickets, ticket IDs, sessions, credentials, or private targets. Tunnel terminals carry an explicit component side, selected path, and terminal class (`complete`, `idle_timeout`, `cancelled`, `local_io`, or `remote_io`) with correlated request/stream hashes and directional counters. Shutdown rejects new route opens, cancels bounded waiters/work, closes owned streams/connections, emits cancelled active terminals, and zeroizes ticket buffers.
