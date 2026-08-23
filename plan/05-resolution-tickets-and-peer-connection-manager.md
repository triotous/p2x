# Plan: Resolution, Tickets, and Peer Connection Management

- **Document status:** implementation-ready
- **Scope:** Phase 3 from [`00-product-analysis.md`](00-product-analysis.md) §24
- **Depends on:** completed Plans 01–04/04a, accepted [`ADR 0001`](../docs/adr/0001-rust-libp2p-connectivity.md), and the current clean Phase 2 implementation at `b499c4c`
- **Required outcome:** an authenticated client resolves one exact tenant-scoped selector, receives a fresh one-use exchange-signed ticket, establishes or reuses the intended server connection, prefers a DCUtR-confirmed direct path within the shared setup budget, falls back to the authenticated relay path, and opens `/p2x/proxy/1` on the selected `ConnectionId`; the server validates and consumes the ticket exactly once before acknowledging an empty authorized stream

The work-package filenames in [`00-product-analysis.md`](00-product-analysis.md) §25 predate the corrective Plans 02–04a. The implemented sequence is authoritative: Plan 04 completed Phase 2 registry/availability and explicitly hands Phase 3 to Plan 05. This document therefore follows §24 Phase 3 rather than the old §25 item-5 server-registration title.

## 1. Goal and Scope

Implement the smallest complete Phase 3 control and connectivity path:

1. add a bounded, client-to-exchange `/p2x/resolve/1` protocol;
2. perform exact registry lookup, current-client/current-server authorization, ticket construction, and signing in one exchange event-loop transition;
3. add bounded resolve admission, rate limiting, idempotent response replay, and privacy-safe evidence;
4. add a strict client target file, resolver state, metadata/negative caches, and per-selector request pacing without ever sharing a one-use ticket;
5. enable product DCUtR and convert the Phase 0 connection/path primitives into a bounded per-server product connection manager;
6. add a role-restricted exact-connection `/p2x/proxy/1` substream opener without exposing `/p2x/spike/1` in product mode;
7. load the exchange ticket-verification ring on the server, verify every ticket binding, and atomically reject replay before acknowledging authorization;
8. prove client-authoritative empty-stream success over direct and forced relay, including reuse, fallback, invalidation, restart, concurrency, and cleanup.

This plan does **not** implement:

- fixed local TCP listeners, HTTP Host parsing, TLS ClientHello/SNI parsing, domain routing, or local protocol error rendering;
- server upstream host/port/TLS configuration, upstream health probes, upstream dialing, `Accepted`-after-upstream semantics, byte copying, backpressure, half-close, or application idle timeouts;
- reusable/batched tickets, `max_streams > 1`, anonymous access, load balancing, replicas, multiple exchanges, registry persistence, or transparent active-stream migration;
- dynamic target/service/key reload, full metrics/dashboards, deployment packaging, or final load/soak tuning assigned to later phases.

`/p2x/proxy/1` is deliberately introduced now because exact selected-connection opening and ticket validation are the Phase 3 exit gate. Plan 05 ends at an `Authorized` handshake and then closes the empty stream. `Authorized` means only that the transport peer and ticket passed the server gate; it never permits application bytes. Phase 4 must connect the configured upstream and return the distinct final `Accepted` response before any application byte can flow.

## 2. Current State and Confirmed Constraints

### 2.1 Verified baseline

- The workspace still produces exactly `p2x-exchange`, `p2x-client`, and `p2x-server`, with shared `p2x-protocol`, `p2x-config`, and `p2x-net` crates.
- `libp2p = 0.56.0` is pinned. The accepted custom `ProbeStreamBehaviour` can open a substream on an exact direct or relayed `ConnectionId`; ADR 0001 requires retaining that property.
- Product peers authenticate through `/p2x/auth/1`. The exchange owns current `AuthSession` principals containing tenant, role, scopes, quota profile, and authorization revision.
- `AuthState` correctly preserves an old session during reauthentication, but its public `current_session(now)` currently returns only the session ID. Phase 3 needs the complete committed session context on client and server.
- `/p2x/registry/1`, atomic service-set ownership, lease refresh, relay admission, server reservation/re-registration, and truthful server readiness are implemented.
- `Registry::resolve_exact` exists only as an exchange-internal seam. It returns the owning registration record, not the exact matched service needed to construct a ticket.
- Ticket claims, canonical encoding, Ed25519 envelope, deterministic vector, redacted `RawTicket`, signing-key file, and verification-key ring exist. The exchange loads a `TicketKey` but does not issue tickets; the server does not yet load its verification ring.
- `ConnectionBook` classifies direct versus expected-exchange relay paths and accepts a direct connection only after DCUtR confirmation. `PathAttempt` already models direct preference, exact open, one pre-handshake direct-to-relay fallback, cancellation, and the 20-second setup bound, but uses lab constants and probe request IDs.
- Product client/server swarms enable relay as needed, but product DCUtR and a product proxy-stream behaviour are absent. `/p2x/spike/1` remains lab-only.
- Product client configuration is still CLI-only and has no exact target catalog, resolver, cache, peer pool, or service-open command.
- With loopback socket access, `cargo test --workspace --all-targets --all-features` passes 130 tests at planning time. The same command fails only at socket-binding integration tests inside the restricted sandbox, so network tests must continue to run in a listener-capable environment.

### 2.2 Relevant code seams

| Area | Current repository seam | Required Plan 05 change |
| --- | --- | --- |
| Auth context | `crates/p2x-net/src/auth_state.rs` returns only `[u8; 16]` session ID | Retain and expose one committed `SessionLease` with tenant, role, scopes, quota profile, authorization revision, start, and expiry |
| Exact lookup | `apps/p2x-exchange/src/registry.rs::resolve_exact` returns `&RegistrationRecord` | Return an owned exact matched-service view and reject expired/offline state before ticket construction |
| Ticket signing | `p2x-config::TicketKey` signs bytes while envelope assembly lives in `p2x-protocol` | Add one shared signing interface so production issuance cannot duplicate the v1 envelope format |
| Exchange protocols | exchange supports inbound auth/registry | Add inbound resolve only in product mode, with independent admission and drain ownership |
| Client protocols | client supports outbound auth and relay client | Add outbound resolve, product DCUtR, and outbound-only proxy substreams |
| Server protocols | server supports outbound auth/registry and relay client | Add product DCUtR and inbound-only proxy substreams |
| Product connection state | Phase 0 `ConnectionBook`/`PathAttempt` are driven directly by lab logic in `p2x-client/main.rs` | Add reusable product ownership keyed by server `PeerId`, preserving exact-connection selection |
| Server ticket gate | verification ring and replay state are absent | Load strict verification keys and add bounded verify/recheck/consume ownership |
| App structure | the three `main.rs` files own most dispatch inline | Add focused modules and keep each `Swarm` owned by its existing single event-loop task |

### 2.3 Normative invariants

1. Transport `PeerId`, tenant, role, scopes, quota profile, authorization revision, and current session come from authenticated state, never from a resolve or proxy request.
2. Resolution is exact over the complete canonical `(tenant, protocol, metadata)` selector. There is no enumeration, prefix, subset, wildcard, or cross-tenant lookup.
3. Lookup and ticket issuance occur without an await or externally visible ownership gap. A ticket cannot bind a server/service/revision different from the exact registry entry checked in the same transition.
4. One ticket authorizes one proxy-open attempt at the server (`OPEN_PROXY_STREAM`, `max_streams = 1`). A ticket is never cached as reusable data or fanned out to multiple waiters.
5. Resolve response replay is idempotent only for the same authenticated peer, current session, request ID, and canonical request body. It returns the exact original ticket bytes.
6. Private upstream addresses do not exist in client or exchange configuration/protocols. An `upstream_id` is an opaque server-local routing key, not a dial target.
7. Existing healthy direct connectivity wins immediately. Otherwise a valid relay connection is established first, DCUtR runs over it, and only new proxy streams wait for the bounded direct-preference window.
8. Every proxy substream is opened on the exact selected `ConnectionId`. A generic `Swarm::dial` or untargeted request-response stream is not evidence of path selection.
9. A direct open failure before the proxy handshake may fall back once to the prepared relay connection. Once any ticket bytes may have reached the server, a retry requires a fresh resolve/ticket.
10. Server validation binds issuer, transport client, local server, tenant, service, selector fingerprint, registration revision, server authorization revision, permission, time, and max-stream count before replay consumption.
11. Replay consumption and live registration recheck are serialized by the server owner. Concurrent opens with one ticket produce at most one `Authorized` result.
12. The single absolute setup deadline covers resolve, ticket issuance, relay dial, DCUtR preference, exact open, and the authorization handshake. Subsystem timeouts may shorten this budget but cannot extend it.
13. Resolution, dial attempts, pending opens, handshake workers, peer states, cached metadata, idempotency entries, replay entries, event queues, and diagnostics are bounded before allocation.
14. Raw selectors, metadata values, tickets, session IDs, verification material, and future private targets are absent from normal logs and metrics.

## 3. Required Design

### 3.1 Repository boundaries and files

Add or extend these files:

```text
crates/p2x-protocol/
  src/resolve.rs                 # validated resolve request/response values
  src/proxy.rs                   # proxy-open handshake domain values
  src/ticket.rs                  # shared production signing interface; zeroizing ticket wrapper
  src/error.rs                   # stable resolve/proxy/replay/setup errors
  src/lib.rs
  testdata/resolve-v1.json       # canonical request/response vector with non-production ticket
  testdata/proxy-v1.json         # canonical Open/Authorized/Rejected vectors

crates/p2x-net/
  src/resolve_codec.rs           # /p2x/resolve/1 request-response codec
  src/proxy_codec.rs             # bounded async handshake framing on an opened stream
  src/proxy_stream/mod.rs
  src/proxy_stream/behaviour.rs  # exact selected-ConnectionId open ownership
  src/proxy_stream/handler.rs
  src/proxy_stream/upgrade.rs    # /p2x/proxy/1 negotiation
  src/auth_state.rs              # complete committed SessionLease
  src/connection_book.rs         # bounded product pool queries/closing markers
  src/path_selector.rs           # injected policy and absolute setup deadline
  src/builder.rs                 # exact role/mode protocol surfaces
  src/lib.rs

apps/p2x-exchange/
  src/resolution.rs              # atomic lookup + authorization + ticket issuance/idempotency
  src/resolution_admission.rs    # global/per-client/rate/terminal-event ownership
  src/main.rs                    # dispatch only; signer/session/registry/reservation handoff
  src/lib.rs

apps/p2x-client/
  src/config.rs                  # strict exact-target and path/limit configuration
  src/resolver.rs                # request correlation, pacing, metadata/negative cache
  src/connection_manager.rs      # per-server relay/DCUtR/pool/waiter ownership
  src/proxy_open.rs              # per-open deadline and handshake worker ownership
  src/main.rs                    # single swarm executor and finite Phase 3 diagnostic

apps/p2x-server/
  src/ticket_admission.rs        # live binding recheck + replay cache + stream permits
  src/proxy_open.rs              # bounded handshake workers and owner commands
  src/availability.rs            # expose current registration lease/revision context
  src/main.rs                    # verification-ring load and single-owner dispatch

docs/protocol/resolve-v1.md
docs/protocol/proxy-v1.md
docs/operations/client-connections.md
tests/resolution/README.md
tests/resolution/local.sh
crates/p2x-net/tests/resolve_network.rs
crates/p2x-net/tests/proxy_network.rs
fuzz/fuzz_targets/resolve_frame_decode.rs
fuzz/fuzz_targets/proxy_frame_decode.rs
```

Do not add a new crate, generic actor framework, shared mutable `Swarm`, or product dependency on `probe`, `probe_worker`, or `/p2x/spike/1`. The new proxy behaviour may follow the proven exact-open structure, but it owns product-specific admission and lifecycle separately so the accepted lab protocol does not become a production authorization surface.

### 3.2 Complete peer session context and ticket signing

Replace the session-ID-only accessor in `p2x-net::auth_state` with a private-field committed value:

```text
SessionLease {
  session_id,
  tenant,
  role,
  scopes,
  quota_profile,
  authorization_revision,
  established_at,
  expires_at,
}
```

- Build a pending lease from the complete correlated `Authenticated` response.
- Commit it only after the corresponding Pong. During reauthentication, retain the prior complete lease until the replacement Pong succeeds or the prior lease actually expires.
- `current_session(now)` returns the current complete lease only when `expires_at > now`.
- A normal session-ID renewal with identical principal binding does not invalidate healthy peer connections or cached resolution metadata. A tenant, role, scope, quota, or authorization-revision change invalidates pending resolution work and all metadata/negative cache entries.
- Client requests require `Role::Client` and `open_proxy_stream`; server ticket validation requires the committed server context used for its current registration.

Keep ticket envelope assembly in `p2x-protocol`:

- define a narrow `TicketSigningKey` interface exposing only `key_id()` and signing of the canonical ticket message;
- implement it for `p2x_config::ticket_key::TicketKey` without exposing its seed or inner signing key;
- make the existing deterministic `TicketSigner` use the same assembly path so the committed vector proves production bytes;
- make `RawTicket` zeroize its owned bytes on drop, retain redacted `Debug`, and require explicit cloning where idempotent response replay needs a second owned copy;
- never log or serialize a ticket through a generic debug/lifecycle path.

### 3.3 Bounded `/p2x/resolve/1` protocol

Add one protocol ID:

```text
/p2x/resolve/1
```

The product exchange supports it inbound and the product client supports it outbound. Product servers and all connectivity-lab peers have it disabled. Use libp2p request-response with a five-second request timeout and one request per substream.

Version 1 messages are:

```text
ResolveRequestV1::Resolve {
  request_id: [u8; 16],
  session_id: [u8; 16],
  selector: UnscopedSelector,
  client_capabilities: Capabilities,
}

ResolveResponseV1::Resolved {
  request_id: [u8; 16],
  server_peer_id: canonical PeerId bytes,
  upstream_id: UpstreamId,
  selector_fingerprint: [u8; 32],
  registration_revision: RegistrationRevision,
  relay_addresses: Vec<MultiaddrBytes>,
  compatible_capabilities: Capabilities,
  registration_expires_at: i64,
  ticket_expires_at: i64,
  ticket: RawTicket,
}

ResolveResponseV1::Rejected {
  request_id: Option<[u8; 16]>,
  error: PublicError,
}
```

The request omits client `PeerId`, tenant, role, scopes, and quota. The response omits server authorization revision, session IDs, raw tenant, raw selector, credential data, and private upstream data. The signed ticket contains every binding the server needs.

Wire and domain rules:

- frame is `u32` big-endian length plus exactly one canonical binary message;
- `MAX_RESOLVE_FRAME = 16_384` bytes; zero, oversized, truncated, trailing, unsupported-version, unknown-discriminant, unknown-capability, invalid PeerId, duplicate/non-canonical selector, and invalid multiaddress input are rejected before app dispatch;
- request canonical order reuses the selector encoding already committed by Plan 04;
- relay address count is 1–4 and each encoded multiaddress is at most 512 bytes;
- every returned address must contain the pinned exchange `PeerId` immediately before `/p2p-circuit` and the resolved server as the terminal `/p2p/<server>` component; the client revalidates this before dialing;
- `compatible_capabilities` is the closed intersection relevant to the two peers. Relay v2 must be present. Direct/DCUtR absence selects relay immediately rather than reporting false direct failure;
- `registration_expires_at > now`, `ticket_expires_at > now`, and `ticket_expires_at <= registration_expires_at` in every successful response;
- response decoding keeps ticket bytes in `RawTicket`; no intermediate plain `Vec<u8>` is retained longer than framing requires.

Add canonical vectors and a `resolve_frame_decode` fuzz corpus covering valid Resolve/Resolved/Rejected, all length boundaries, malformed PeerIds/multiaddresses, wrong circuit shape, unknown errors/capabilities, non-canonical selector order, truncation, trailing bytes, and ticket maximums.

### 3.4 Atomic exchange resolution and ticket issuance

Change `Registry::resolve_exact` to return an owned, privacy-safe view containing exactly the matched ready service:

```text
ResolvedRegistration {
  server_peer_id,
  upstream_id,
  selector_fingerprint,
  registration_revision,
  server_authorization_revision,
  server_capabilities,
  relay_addresses,
  registration_expires_at,
}
```

It must compare the complete selector after fingerprint index lookup, reject `expires_at <= now`, return `registry.offline` for an unavailable owner, and never return only a record that requires a later ambiguous service scan.

`apps/p2x-exchange/src/resolution.rs` owns one synchronous `resolve_and_authorize` transition. In this exact order it must:

1. reject drain before new work;
2. require the transport client to have a current matching session, `Role::Client`, `open_proxy_stream`, and the supported `standard` profile;
3. verify the request `session_id` and closed capability set;
4. scope the selector using the authenticated tenant and perform exact lookup;
5. require the selected server to still have a current server session whose tenant and authorization revision match the registration;
6. require the selected server to remain in the current accepted-reservation set;
7. compute compatible relay/direct/DCUtR capabilities without trusting client or server claims outside the closed bit set;
8. allocate a CSPRNG `ticket_id`, construct claims from the exact resolved view and transport client, and sign with the loaded production ticket key;
9. cache and return the exact response for idempotent retransmission.

Ticket policy is normative:

- default lifetime is 30 seconds, configurable from 5–60 seconds;
- `not_before` is the exchange Unix time at issuance;
- expiry is `min(now + configured_lifetime, registration_expires_at)`;
- if less than five seconds of usable lifetime remains, return retryable `registry.offline` instead of issuing a near-dead ticket;
- `authorization_revision` is the **server registration principal's** authorization revision. Client revocation stops new issuance through the client-session check; already issued tickets remain bounded by their expiry as approved in Plan 03;
- permissions are exactly `OPEN_PROXY_STREAM`, and `max_streams` is exactly 1;
- randomness/signing failure returns retryable `exchange.overloaded` without caching a partial result.

Add a bounded idempotency cache keyed by `(client PeerId, request_id)`:

- hash the complete canonical request, including `session_id`;
- authorize the current session before replay lookup so revocation/drain cannot retrieve an old ticket;
- exact same body replays the same response/ticket bytes and does not increment issuance count;
- same ID with different bytes is non-retryable `protocol.malformed`;
- retain entries through ticket expiry plus the maximum 5-second default skew so a late identical retry cannot silently receive a different ticket;
- defaults are 8 entries per client and 2,048 globally, with deterministic oldest expiry/eviction; never evict a still-live entry merely to admit an unbounded caller.

Add `resolution_admission.rs` rather than overloading registry admission. Defaults are:

| Limit | Default | Hard maximum |
| --- | ---: | ---: |
| Global in-flight resolve requests | 128 | 1,024 |
| In-flight requests per client | 16 | 128 |
| Accepted requests per client per rolling minute | 120 | 1,200 |
| Tracked rate buckets | 256 | 2,048 |

Ownership is `(peer_id, connection_id, inbound_request_id)`. Admission releases exactly once on `ResponseSent`, `InboundFailure`, owning connection close, response-channel failure, or shutdown. The exchange drain rejects new resolution with `exchange.draining`, continues polling already-owned responses up to the existing five-second drain deadline, then clears resolution admission/idempotency state before sessions and swarm close.

### 3.5 Client target configuration and resolver ownership

Add required `--routes-file <path>` for the Phase 3 product/diagnostic client path while retaining the established identity/trust/credential CLI. Load through `p2x_config::yaml::load`, deny unknown fields, and validate the whole file before listen or dial:

```yaml
schema_version: 1
network:
  direct_preference_ms: 1500
  connection_setup_timeout_ms: 20000
targets:
  - route_id: orders
    selector:
      protocol: http
      metadata:
        service: orders
        environment: production
        region: eu-west
limits:
  max_peer_states: 64
  max_pending_setups: 128
  max_pending_per_server: 64
```

- Accept 1–256 unique `route_id` entries; route IDs use the existing bounded identifier alphabet.
- Validate selectors through `p2x-protocol`; multiple local route IDs may intentionally point to the same exact selector.
- Default direct preference is 1,500 ms, allowed 0–5,000 ms. Default/hard maximum setup timeout is 20,000 ms, allowed 1,000–20,000 ms. Direct preference must be strictly below the setup timeout unless it is zero.
- Default peer-state limit is 64 with hard maximum 256. Default pending setup limit is 128 with hard maximum 512. Default per-server pending limit is 64 with hard maximum 128.
- This file contains no domain, bind address, host, port, URL, certificate, upstream secret, or ingress parsing policy. Phase 4 will attach fixed TCP binds; Phase 5 will attach Host/SNI routes.
- Existing Plan 04 relay-Ping diagnostics may omit the route file only when they do not instantiate the resolver/proxy path. Update their harness explicitly rather than weakening product route validation.

`apps/p2x-client/src/resolver.rs` owns request IDs, current-session correlation, timers, and caches. It returns:

```text
AuthorizationGrant {
  metadata: ResolvedServiceMetadata,
  ticket: RawTicket,
  ticket_expires_at,
}
```

Resolver rules:

- a successful metadata cache contains server identity, service ID, selector fingerprint, revision, relay addresses, compatible capabilities, and registration expiry; it contains **no ticket**;
- positive metadata expires no later than registration expiry. `registry.not_found` and `registry.offline` may be negative-cached for one second; auth, protocol, limit, draining, and transport failures are never negative-cached;
- cache keys include the committed principal binding and complete unscoped selector. A principal-binding change clears all entries; a session-ID-only renewal with the same binding retains metadata but restarts old-session requests with a fresh request ID;
- one logical waiter owns one eventual ticket. Concurrent waiters for one selector are kept in a bounded FIFO: the first owns the current resolve request, and later waiters are paced into fresh requests after it completes. They may share returned metadata and peer-connect work, but never the first waiter's ticket;
- a request-response timeout retransmits the exact request ID/body once while it remains within the absolute setup deadline, allowing exchange idempotency to return the same ticket. A changed session/body always uses a fresh request ID;
- rejected or stale responses, wrong server/selector/revision/address shape, response expiry, and late events cannot complete a waiter;
- `registry.stale_revision`, `registry.not_found`, `registry.offline`, or an authenticated proxy stale-revision result invalidates the affected positive entry. A peer/path failure invalidates only the matching peer connectivity state, not unrelated selectors.

This explicit separation resolves the apparent cache/singleflight conflict in the product analysis: metadata and dial work are reusable, but a one-use ticket is not.

### 3.6 Exact product protocol surfaces and DCUtR

Replace independently combinable peer booleans with one validated product role/surface selection so impossible protocol combinations fail during swarm construction:

| Surface | Auth | Registry | Resolve | Relay client | DCUtR | Probe | Proxy |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Product exchange | inbound | inbound | inbound | relay service | n/a | disabled | disabled |
| Product client | outbound | disabled | outbound | enabled | enabled | disabled | outbound only |
| Product server | outbound | outbound | disabled | enabled | enabled | disabled | inbound only |
| Connectivity lab | existing lab surface | disabled | disabled | existing | existing | enabled | disabled |

Requirements:

- product server registration now advertises `DCUTR` because the product behaviour is enabled; update the Phase 2 capability gate to accept the known bit while continuing to reject unknown bits;
- both peers retain Identify and Ping so DCUtR obtains observed addresses and connection health;
- proxy client handlers do not advertise inbound `/p2x/proxy/1`; server handlers do not expose an outbound app API;
- client/server cannot negotiate `/p2x/resolve/1` with each other, and no lab process can negotiate resolve/proxy;
- adding product DCUtR/proxy must not enable `/p2x/spike/1` or make a lab credential/config path valid in product mode.

### 3.7 Client connection manager and shared setup budget

`apps/p2x-client/src/connection_manager.rs` is a pure owner around the existing `ConnectionBook` and `PathAttempt`; `main.rs` executes returned swarm/proxy commands. Key state by resolved server `PeerId`, not selector, so services on one server reuse connectivity.

Per-server state owns:

- validated relay addresses and current registration revision observed from the latest grant;
- active direct and relay `ConnectionId` records;
- at most one relay dial generation and one DCUtR coordination generation;
- bounded setup waiters, each with its own grant, correlation ID, and absolute setup deadline;
- active proxy-open counts, last-used sequence, and explicit draining/eviction state.

Connection/path behavior:

1. If `ConnectionBook::direct(server)` returns a current, non-closing, DCUtR-confirmed connection, select it immediately.
2. Otherwise reuse an eligible expected-exchange relay connection or start exactly one dial to a validated returned circuit address. Concurrent waiters join that dial; they do not call `Swarm::dial` independently.
3. Once relay is ready, let product DCUtR attempt compatible TCP/QUIC direct connectivity. Each waiter observes the configured direct-preference deadline clipped to its absolute setup deadline.
4. Select a newly confirmed direct connection before that waiter's deadline; otherwise select relay. An explicit DCUtR terminal failure commits relay early.
5. Open `/p2x/proxy/1` on the exact selected `ConnectionId`. If negotiation fails before the ticket handshake starts and relay is still eligible, perform one fresh exact relay open with the same grant.
6. After the Open frame is written or ownership is ambiguous, never replay that ticket on another connection. Acquire a fresh authorization once if the public result is retryable and time remains.
7. A late direct success is retained for subsequent opens but cannot move an already opened substream. Relay loss does not close a healthy direct stream; direct loss affects only streams on that connection and later waiters reacquire according to policy.

Refactor `PathAttempt` to accept a validated `PathPolicy` and absolute deadline instead of using scattered lab constants. Preserve the existing default values and every Phase 0 race/cancellation invariant. Keep `ConnectionBook`'s expected-exchange relay validation and add only the queries/closing markers needed for bounded peer-pool ownership.

Pool/resource rules:

- enforce configured peer-state, pending-global, and pending-per-server limits before allocating a waiter;
- retain at most one selected relay plus one preferred direct TCP and one preferred direct QUIC connection per server; mark surplus idle connections for close rather than silently dropping ledger state;
- evict only a least-recently-used peer state with zero pending/active streams. If all states are busy, return `limit.peer_connections`;
- one slow or failing server setup cannot block auth renewal, another selector/server, swarm polling, or response delivery;
- cancellation and every connection/proxy terminal release waiter/connection/worker ownership exactly once.

### 3.8 `/p2x/proxy/1` opening handshake and exact stream behaviour

Add the product protocol ID:

```text
/p2x/proxy/1
```

`ProxyStreamBehaviour` follows the accepted exact-open ownership model: it records known `(PeerId, ConnectionId)` pairs, admits bounded outbound commands, notifies exactly `NotifyHandler::One(connection_id)`, returns the opened raw stream, and produces one terminal for timeout, cancellation, negotiation failure, connection close, queue rejection, or shutdown. Keep independent product limits and event names; do not route product traffic through `ProbeStreamBehaviour`.

The bounded handshake is:

```text
OpenProxyStreamV1 {
  request_id: [u8; 16],
  ticket: RawTicket,
  upstream_id: UpstreamId,
  registration_revision: RegistrationRevision,
  ingress_kind: FixedTcp | HttpHost | TlsSni,
}

ProxyOpenResponseV1::Authorized {
  request_id: [u8; 16],
  stream_id: [u8; 16],
}

ProxyOpenResponseV1::Accepted {       # defined for Phase 4; never emitted by Plan 05
  request_id: [u8; 16],
  stream_id: [u8; 16],
  selected_upstream_mode: Tcp,
}

ProxyOpenResponseV1::Rejected {
  request_id: Option<[u8; 16]>,
  error: PublicError,
}
```

- `MAX_PROXY_HANDSHAKE_FRAME = 4_096` bytes; use `u32` length framing, fixed-width integers, closed enums, canonical IDs, exact body consumption, flush, and write-half close for the Open frame.
- The duplicated `upstream_id` and `registration_revision` are untrusted routing/correlation hints and must equal the verified claims. They never replace claim validation.
- `Authorized` consumes the ticket but is not permission to send bytes. Plan 05's diagnostic closes the empty stream after observing it. Any application byte before future `Accepted` is `protocol.malformed` and closes the stream.
- A normal client API does not report tunnel success on `Authorized`; only the explicit finite Phase 3 diagnostic treats it as this phase's gate result. Phase 4 must wait for `Accepted` after upstream success.
- Commit proxy vectors and fuzz `Open`, every response, exact maximum, oversized ticket/frame, unknown ingress/mode/error, truncation, trailing bytes, and malformed canonical IDs.

### 3.9 Server ticket validation and replay consumption

Require `--ticket-verification-keys-file <path>` in product server mode. Load the existing strict public-key ring before starting listeners or dialing exchange. Default clock skew is five seconds and configurable only within 0–30 seconds. No dynamic key reload is introduced.

Inbound ownership has two stages so the swarm owner never awaits stream I/O and a worker cannot commit stale authorization:

1. `ProxyStreamBehaviour` applies global/per-client inbound limits and yields the stream with authenticated transport peer and connection IDs.
2. A bounded worker reads one Open frame and verifies the signature/bindings against an immutable snapshot/key ring.
3. The worker sends a bounded validation candidate to the server owner and awaits a one-shot decision.
4. The server owner rechecks the current availability/registration generation, service mapping, revision, server authorization revision, and drain state, then atomically consumes `ticket_id` in the replay cache and allocates `stream_id`.
5. The worker writes exactly one `Authorized` or `Rejected`, closes the empty Phase 3 stream, and releases all permits. A dropped one-shot/worker/connection follows the same release path.

The expected ticket validation inputs are all mandatory:

- issuer equals the pinned exchange `PeerId`;
- client equals the inbound transport `PeerId`;
- server equals the local persisted server `PeerId`;
- tenant equals the current committed server session tenant;
- `upstream_id` exists in the immutable enabled service set;
- selector fingerprint equals that service's tenant-scoped fingerprint;
- registration revision equals the current unexpired registration lease;
- authorization revision equals the committed server principal used for that registration;
- permissions equal `OPEN_PROXY_STREAM`, `max_streams == 1`, and time/key activation/retirement/skew checks pass;
- Open request `upstream_id` and revision equal the verified claims.

Replay cache rules:

- key by verified `ticket_id`; store only expiry plus a privacy-safe owner fingerprint needed for diagnostics;
- consume in the single server owner before returning `Authorized`;
- retain through `ticket.expires_at + configured_clock_skew`;
- default capacity is 8,192 live entries with hard maximum 65,536;
- sweep expired entries deterministically. Never evict an unexpired entry to make a replay potentially valid again; reject new work with `limit.proxy_streams` when full;
- invalid/expired tickets never allocate replay state. Once a valid ticket is consumed, later worker failure, cancellation, or Phase 4 upstream failure does not make it reusable.

Handshake-worker defaults are 256 global and 32 per client, matching the approved server limits. The behaviour queue, worker channel, one-shot decisions, and pending owner map use the same or smaller bounds.

### 3.10 Stable errors and retry ownership

Extend `PublicErrorCode` without renaming existing codes:

| Code | Source/meaning | Client action |
| --- | --- | --- |
| `auth.ticket_replayed` | server already consumed the ticket ID | never retry the ticket; security diagnostic |
| `limit.resolve_requests` | exchange resolve admission/rate bound | bounded backoff within setup deadline |
| `limit.peer_connections` | client peer-state/connection pool full | reject or retry after local capacity frees |
| `limit.proxy_streams` | client/server open, worker, permit, or replay capacity full | bounded retry with a fresh ticket only |
| `peer.connection_failed` | relay/direct/exact-open path unavailable | invalidate peer state; re-resolve only if time remains |
| `peer.setup_timeout` | the single absolute setup budget expired | terminal for this local open |
| `peer.draining` | target server stopped new streams | fresh resolve after backoff |

Reuse existing codes deliberately:

- `registry.not_found` and `registry.offline` for exact lookup outcomes;
- `registry.stale_revision` when the server no longer owns the ticketed service revision;
- `auth.ticket_invalid` for malformed/signature/key/binding failures and `auth.ticket_expired` only for time expiry;
- `auth.session_required`, `auth.role_forbidden`, `protocol.*`, `exchange.overloaded`, `exchange.timeout`, and `exchange.draining` at their existing boundaries;
- Circuit Relay v2 denial remains its native protocol response with privacy-safe local `relay.unauthorized`, `relay.quota`, or dial classifications.

Retry rules are centralized in `resolver`/`connection_manager`, not scattered across event arms. Never retry malformed, role/scope, ticket-invalid/replayed, or capability failures. At most one fresh-ticket retry is allowed after a retryable proxy/path result, and the same absolute setup deadline remains authoritative.

### 3.11 Recovery, shutdown, and privacy-safe evidence

- Exchange control loss cancels unresolved/ticket requests and schedules existing auth redial. It does not close healthy direct server connections or any future already-active proxy stream.
- Exchange restart empties registry/idempotency state. The server re-registers under Plan 04; client not-found/offline negative cache expires or is invalidated and later opens resolve the new revision.
- Reservation loss removes the registration and makes old tickets fail the server's current-revision/readiness recheck even if their signature/time remain valid.
- Server begins shutdown by marking proxy admission draining and rejecting new Opens, waits up to five seconds for Phase 3 handshake workers, then follows the existing readiness-false/Withdraw/reservation-close ordering.
- Client shutdown rejects new route opens, cancels resolve/path/proxy waiters, closes owned streams and surplus connections, drains bounded worker results, and zeroizes all ticket copies.
- Exchange shutdown drains auth/registry/resolve response owners together and emits zero final logical counts.

Add lifecycle records for resolve outcome/latency, cache outcome, ticket issuance count (never ticket value/ID), peer dial generation, DCUtR outcome, selected path, exact-open outcome, ticket validation class, replay rejection, active/pending counts, and setup terminal. Use route/selector/peer/ticket fingerprints where correlation is necessary. A machine-readable client terminal is authoritative only after it correlates its request with the server's `Authorized` response; a server-only event cannot mark client success.

## 4. Implementation Plan

### 4.1 Lock protocol and state invariants with failing tests

- Add ticket-production signing parity, `RawTicket` zeroization/redaction, complete `SessionLease` renewal, exact resolved-service lookup, atomic issuance/idempotency, and authorization-revision tests first.
- Add pure resolver queue/cache tests proving that metadata may be shared while tickets never are.
- Add configurable `PathAttempt` and peer-manager race tests before enabling product DCUtR.
- Add proxy codec, exact-open, live-recheck, and concurrent replay tests before advertising `/p2x/proxy/1`.

### 4.2 Implement shared resolve/proxy/ticket protocol values

- Add private-field domain constructors, canonical body encoders, bounds, error mappings, and committed vectors in `p2x-protocol`.
- Centralize production/test ticket signing bytes and make ticket ownership zeroizing.
- Add the request-response resolve codec and raw-stream proxy codec; fuzz both before app integration.

### 4.3 Implement exchange atomic resolve-and-authorize

- Correct the registry exact-lookup return type.
- Add resolution admission, request idempotency, ticket lifetime/randomness/signing, live server session/reservation recheck, and one response mapping.
- Wire resolve terminals, connection close, auth revocation, registry removal, and drain into exactly-once cleanup.
- Add TCP/QUIC same-process tests for successful issuance and every rejection/race before client caching is introduced.

### 4.4 Add client target configuration and resolver

- Parse and fully validate the strict routes file before networking.
- Implement per-selector waiter queues, session-aware request correlation, exact-timeout retransmission, metadata/negative cache, and invalidation.
- Keep grants move-only at the app boundary and prove a ticket is delivered to only one waiter.

### 4.5 Enable role-correct product DCUtR and proxy surfaces

- Replace inconsistent peer behaviour toggles with validated product client/server surfaces.
- Enable product DCUtR and Phase 3 server capability advertisement.
- Add product proxy exact-open behaviour/handler/upgrade with the accepted `NotifyHandler::One` semantics.
- Run negotiation-surface and Phase 0 exact-open regression tests immediately after composition changes.

### 4.6 Build the bounded client peer connection manager

- Integrate `ConnectionBook`, configurable path policy, relay-address validation, dial singleflight, DCUtR events, exact proxy open, one safe pre-handshake relay fallback, and pool eviction.
- Carry one absolute setup deadline from the route-open command through every resolver/path/handshake action.
- Add multi-route/same-server reuse, slow/failing server isolation, stale event, cancellation, and capacity tests.

### 4.7 Add server ticket/replay admission and empty authorization handshake

- Load verification keys before network startup and expose the current registration lease/service context from availability ownership.
- Add bounded stream workers, immutable cryptographic verification, owner-side live recheck, replay consumption, stream ID allocation, `Authorized`, and exactly-once release.
- Reject application bytes and never emit `Accepted` in Plan 05.
- Add an explicit finite client diagnostic that opens a configured route once, requires a correlated `Authorized`, closes cleanly, writes one terminal, and exits. It must not be mistaken for a data tunnel.

### 4.8 Complete live verification, regression, and documentation

- Add the canonical resolution/proxy harness and privacy scan.
- Update Plan 04 registry fixtures for the new server verification-key/product capability requirements.
- Rerun auth, registry, and full connectivity regressions because auth context, behaviour composition, DCUtR, and exact-open ownership changed.
- Document exact wire bytes, ticket/cache semantics, path/fallback behavior, recovery, limits, and the explicit Phase 4 handoff before marking Plan 05 complete.

## 5. Verification

### 5.1 Local static and automated checks

Run from the repository root:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
cargo tree -e features
```

Run every fuzz target for the repository's bounded CI duration, including `resolve_frame_decode`, `proxy_frame_decode`, and the existing ticket/auth/registry targets. Any panic, excessive allocation, non-canonical acceptance, raw-ticket leak, unknown error coercion, or unbounded queue fails the phase.

### 5.2 Required unit and state-machine coverage

Tests must cover at least:

- complete session-context initial auth/reauth/Pong commit, old-session expiry race, principal-binding change, and stale response handling;
- production signer/test signer byte parity, CSPRNG failure, lifetime/skew boundaries, zeroization/redaction, and every existing ticket mutation/binding test;
- resolve request/response round trips, exact frame/address/ticket bounds, canonical selector reuse, unknown version/bit/discriminant/error, invalid PeerId/circuit address, truncation, and trailing data;
- exact service selection among multiple services, ready/offline/expired/cross-tenant lookup, live server session/reservation mismatch, and removal races;
- resolve idempotent replay, request-ID/body/session mismatch, cache bound/expiry, deterministic eviction, authorization-before-replay, and one issuance count;
- resolution admission global/per-client/rate `N`/`N+1` and release on every response/failure/close/drain terminal;
- metadata positive/negative expiry, no auth negative cache, no cached ticket, one ticket per waiter, paced same-selector concurrency, timeout same-body retry, session-change fresh ID, and late-response rejection;
- path policy bounds, absolute setup deadline, existing-direct fast path, relay dial singleflight, DCUtR success/failure/no-terminal deadline, stale generation, direct exact-open-to-relay fallback, post-handshake fresh-ticket rule, cancellation, and busy-pool rejection;
- proxy frame round trips/bounds, exact selected-connection open, role negotiation, handshake timeout, application-byte-before-Accepted rejection, and one terminal/release;
- every ticket binding mismatch, expired versus invalid mapping, concurrent replay, replay capacity/no-live-eviction, registration/auth revision race, drain, and worker/one-shot/connection cancellation.

### 5.3 Same-process network integration

Add TCP and QUIC tests using real product behaviours to prove:

1. product exchange/client negotiate resolve while server/lab cannot; product client/server negotiate proxy in only the intended direction;
2. an authenticated exact selector returns the matched service/revision/addresses and a server-verifiable one-use ticket;
3. unknown/offline/cross-tenant/wrong-role/wrong-scope requests return the stable result without ticket issuance or information from another tenant;
4. a lost Resolve response followed by an identical request returns byte-identical ticket/response and one issuance;
5. client dials the returned relay circuit, product DCUtR records the resulting direct connection when available, and the exact chosen `ConnectionId` carries `/p2x/proxy/1`;
6. forced direct selects a confirmed direct connection; blocked direct selects relay within the configured preference/setup bound;
7. direct exact-open negotiation failure before Open causes one relay exact-open, while a post-Open failure never reuses the ticket;
8. server returns one correlated `Authorized`, consumes replay once, and rejects concurrent/late replay;
9. multiple route selectors resolving to one server share peer connections but receive independent tickets/substreams;
10. exchange/server restart, reservation loss, registration replacement, and auth revision changes invalidate stale work and recover later opens without restarting the client.

### 5.4 Canonical live process cases

Create `tests/resolution/local.sh --case <name>` with at least:

```text
resolve-ticket-tcp
resolve-ticket-quic
unknown-selector
offline-selector
cross-tenant
idempotent-resolve
forced-relay
direct-preferred
direct-open-fallback
ticket-replay
ticket-bindings
ticket-expiry
registration-revision-change
connection-reuse
concurrent-opens
resolve-limit
proxy-limit
exchange-restart
server-restart
graceful-drain
```

Each case creates run-scoped identities, credentials, signing/verification key files, service/route files, ports, and artifacts; starts the real product binaries; validates NDJSON and a machine-readable summary; scans artifacts for credentials, session IDs, full tickets, raw selector/metadata values, and private targets; and removes every process/secret on exit.

The direct/relay cases pass only when the client terminal and server authorization event correlate the same request/stream, the client-selected `ConnectionId` is classified as the required path, and the exchange reports one ticket issuance. A case label, server-only success, generic Ping, or `/p2x/spike/1` traffic is not proxy evidence.

### 5.5 Concurrency, churn, and deadline checks

- Exercise 64 concurrent empty proxy opens and the 128-open headroom across multiple services/servers; every stream receives a distinct ticket and unrelated selectors make progress.
- Exercise 32 active peer connections and 64-connection headroom with bounded LRU cleanup; no active/busy peer is evicted.
- Run repeated direct/relay loss and re-resolution cycles; pending requests, peer states, replay entries, workers, tasks, connections, and ticket buffers return to baseline.
- Saturate resolve and proxy admission while auth Ping and server registration Refresh remain timely.
- Inject delay at each setup stage and prove the total observed time never exceeds the configured 20-second absolute deadline plus test scheduling tolerance.

### 5.6 Required regression and owner-executed checks

Rerun:

```text
./tests/auth/local.sh --case all
./tests/registry/local.sh --case all
./tests/connectivity/local.sh
```

Because this phase changes peer behaviour composition, product DCUtR, connection selection, and exact-opening code, rerun the complete accepted C01–C14 connectivity matrix, including Linux namespaces and the two-host C14 environment. Add real two-host product cases for direct-preferred and forced-relay ticketed proxy authorization over TCP and QUIC exchange transports.

Linux and native macOS must pass resolve/ticket/relay and product direct-preference checks. macOS VM-backed containers must pass resolve and forced relay; direct remains measured best effort. Environment-dependent two-host, firewall/NAT, packet inspection, long soak, and platform results are owner-executed final-phase checks and must be recorded as incomplete rather than passed when unavailable.

## 6. Documentation Updates

Add [`docs/protocol/resolve-v1.md`](../docs/protocol/resolve-v1.md) with byte-exact layouts, bounds, authoritative/omitted fields, exact lookup, capability intersection, ticket lifetime, idempotency, errors, and compatibility rules.

Add [`docs/protocol/proxy-v1.md`](../docs/protocol/proxy-v1.md) with exact Open/Authorized/Accepted/Rejected framing, ticket binding/replay semantics, selected-connection requirement, and the rule that application bytes are forbidden until future `Accepted`.

Add [`docs/operations/client-connections.md`](../docs/operations/client-connections.md) with the routes-file schema, metadata-versus-ticket cache distinction, absolute setup budget, relay-first/DCUtR/direct-preference lifecycle, pool limits, fallback/retry behavior, exchange/server restart behavior, finite diagnostic, privacy rules, and current lack of a usable ingress/data tunnel.

Update:

- [`docs/protocol/auth-v1.md`](../docs/protocol/auth-v1.md) for production ticket issuance/consumption;
- [`docs/protocol/registry-v1.md`](../docs/protocol/registry-v1.md) for Phase 3 DCUtR capability and the internal exact-lookup consumer;
- [`docs/security/identity-and-credentials.md`](../docs/security/identity-and-credentials.md) for server verification-ring deployment, ticket revocation limits, and replay retention;
- [`docs/operations/server-availability.md`](../docs/operations/server-availability.md) for stale-ticket invalidation and proxy drain ordering;
- [`tests/README.md`](../tests/README.md) for the Plan 05 canonical runner and environment-dependent gates.

## 7. Definition of Done

- `/p2x/resolve/1` is canonical, bounded, fuzzed, role-restricted, and available only between an authenticated product client and exchange.
- Exact lookup returns one matched service and ticket issuance atomically binds the current client, server, tenant, service, selector fingerprint, registration revision, server authorization revision, time, permission, and one-use limit.
- Resolve retransmission is idempotent and bounded; revocation/drain authorization precedes cached replay.
- Client metadata/negative caches and request pacing are bounded, while every logical open owns a distinct non-cached ticket.
- Product client/server enable DCUtR and retain exact direct-versus-relay `ConnectionId` selection without exposing `/p2x/spike/1`.
- Per-server relay dial/DCUtR work is coalesced, peer connections are reused within limits, and all setup stages share one absolute deadline.
- `/p2x/proxy/1` opens on the selected connection, and server verification/replay ownership yields at most one correlated `Authorized` for a valid ticket.
- `Authorized` never carries application data or masquerades as final upstream `Accepted`; Plan 05 implements no upstream or byte tunnel.
- Stale registration, reservation/auth loss, ticket expiry/replay, exchange/server restart, concurrency saturation, cancellation, and drain fail closed and recover only according to the documented policy.
- Static checks, unit/integration tests, fuzzing, canonical live cases, concurrency/deadline checks, Plan 03/04 regressions, and the required connectivity rerun pass with zero leaked logical resources or sensitive artifacts.
- Protocol, security, client-connection, server-availability, and test documentation match executable behavior.
- Only after these criteria pass may Plan 06 implement Phase 4 fixed TCP ingress, server-local upstream routing/connection policy, final `Accepted`, bounded bidirectional copy, half-close, idle timeout, cancellation, and stream permits.
