# Plan: Raw TCP Proxy Tunnel

- **Document status:** implementation-ready
- **Scope:** Phase 4 from [`00-product-analysis.md`](00-product-analysis.md) §24
- **Depends on:** completed Plans 01–05/05a, accepted [`ADR 0001`](../docs/adr/0001-rust-libp2p-connectivity.md), and the clean Plan 05a implementation at `39c3e1d`
- **Required outcome:** a local application connects to a configured loopback TCP listener on `p2x-client`; the client resolves and opens the exact direct-preferred or relay-fallback `/p2x/proxy/1` substream; `p2x-server` authorizes the ticket, selects only the immutable server-local upstream, obtains bounded capacity, connects that TCP upstream, returns `Accepted`, and then proxies opaque bytes bidirectionally with bounded buffers, half-close propagation, idle timeout, cancellation, and exact resource release

The work-package names in [`00-product-analysis.md`](00-product-analysis.md) §25 predate the implemented corrective sequence. Plans 04/04a completed registry/availability and Plans 05/05a completed resolution, one-use ticket authorization, and exact peer connection ownership. The authoritative next delivery item is therefore §24 **Phase 4 — Raw proxy tunnel**, not the old §25 wire-protocol work-package title.

## 1. Goal, Scope, and Boundaries

### 1.1 Required result

Implement the smallest complete raw TCP product path:

1. add validated fixed TCP listeners to the existing client route configuration;
2. begin the existing absolute setup deadline at local `accept`, before resolution or path work;
3. run every accepted local connection through the completed `RouteOpenSupervisor`, resolver, connection manager, exact-connection proxy opener, and one-use ticket gate;
4. replace the Phase 3 empty `Authorized` terminal with a final `Accepted` response sent only after the configured upstream TCP connection succeeds;
5. map a verified `upstream_id` to an immutable server-local socket address without accepting a host, port, URL, DNS name, or Unix path from the client or exchange;
6. enforce global, per-client, per-server, per-service, ingress, upstream-dial, and buffer bounds before creating unbounded work;
7. proxy both directions independently so a slow consumer applies backpressure only to its stream, EOF in one direction shuts down the opposite writer, and the other direction may continue;
8. terminate an idle, cancelled, failed, or shutdown stream once and return every listener, setup, connection-manager, behavior, worker, dial, service, and active-stream permit once;
9. prove the same behavior over selected direct and forced-relay connections with large transfers, half-close, slow readers, concurrency, control loss, path loss, and overload.

### 1.2 Non-goals

Do not add:

- HTTP Host or `:authority` parsing, TLS ClientHello/SNI parsing, domain normalization, route locking across HTTP requests, or protocol-specific local error bodies; those are Phase 5;
- TLS termination, server-initiated upstream TLS, HTTP header rewriting, HTTP CONNECT, HTTP/2 termination, request-level pooling, UDP, Unix sockets, or an open forward proxy;
- client- or ticket-supplied upstream destinations, dynamic service/route reload, DNS upstream targets, active upstream health probes, replicas, load balancing, or multiple exchanges;
- transparent migration or replay of an active TCP stream after its selected P2P connection fails;
- dashboards, alerts, final deployment packaging, full graceful-drain policy, or final timeout/limit tuning assigned to product §24 Phase 6.

Phase 4 supports IP-literal TCP upstream socket addresses. Private-DNS resolution and its rebinding policy require a separate security decision before they are enabled. A configured but unavailable upstream remains advertised according to its explicit `enabled` flag; this phase reports dial failures but does not convert them into an active health probe.

## 2. Current State and Confirmed Constraints

### 2.1 Verified baseline

- The workspace still produces exactly `p2x-exchange`, `p2x-client`, and `p2x-server`, with shared `p2x-protocol`, `p2x-config`, and `p2x-net` crates.
- The worktree is clean at `39c3e1d`. `cargo test --workspace --all-targets --all-features` passes when the test environment permits loopback TCP/QUIC listeners.
- `RouteOpenSupervisor` owns bounded, independently correlated resolve/path/proxy setup attempts; `ConnectionManager` owns peer metadata, relay/DCUtR generations, exact selected connections, pending counts, active counts, reuse, fallback, and eviction constraints.
- `/p2x/proxy/1` already has bounded `Open`, `Authorized`, `Accepted`, and `Rejected` wire values, byte-exact vectors, a framed codec, fuzz coverage, exact-connection behavior, and role-correct client/server protocol surfaces.
- The server worker verifies immutable ticket material outside the swarm owner. The server owner live-rechecks authentication, availability, service/revision binding, consumes replay state, and allocates a stream ID exactly once.
- `ProxyStreamBehaviour` already holds an inbound admission until the worker releases it, so extending the worker lifetime through upstream dial and byte streaming preserves the existing global/per-client protocol boundary.
- `ConnectionBook` and the connectivity lab have already proved direct/relay coexistence, exact `ConnectionId` selection, large bidirectional streams, half-close, slow readers, control loss, concurrency, and connection recovery at the libp2p layer.

### 2.2 Required corrections at the Phase 3/4 boundary

| Current behavior | Phase 4 correction |
| --- | --- |
| `proxy_codec::write_frame` flushes and closes the stream write half after every handshake frame. | Separate frame flushing from stream half-close. A product Open and Accepted response must leave both directions usable for application bytes. |
| `read_open_and_require_half_close` waits for EOF and rejects an application byte after Open. | Read exactly one bounded Open frame, then stop reading until authorization and upstream connection finish. The product client sends no application bytes before Accepted; any bytes queued by a malicious peer are not consumed or forwarded until admission succeeds. |
| The server returns `Authorized` immediately after ticket consumption and closes the empty stream. | Reserve limits, consume the ticket, dial the server-local upstream, then return one final `Accepted`; return `Rejected` on every pre-Accepted failure. `Authorized` remains decodable for committed vector compatibility but is not emitted or treated as tunnel success. |
| The client worker returns only request/stream IDs and drops the libp2p stream. | Return the still-open stream with the correlated Accepted result and hand it to the local ingress worker. |
| The multi-open route owner is enabled for finite diagnostics, while normal product mode has no local ingress producer. | Instantiate the same owner for long-running product mode, route ingress events into it, and treat per-ingress failure as a local connection terminal rather than a process terminal. |
| Server services contain advertisement data but no connect target or upstream policy. | Extend the immutable service entry with a redacted IP-literal `SocketAddr`, connect timeout, idle timeout, and service concurrency limit. |
| Proxy worker limits end at the authorization handshake. | Hold behavior and task admission through dial and streaming; add upstream-dial and per-service ownership. |
| Existing lifecycle output proves authorization but has no production tunnel counters. | Add privacy-safe setup/stream terminals with path, duration, byte counts, half-close state, and stable error class; never record payload hashes or upstream addresses. |

### 2.3 Invariants to preserve

- The client setup deadline starts at local TCP acceptance and ends only when a correlated `Accepted` is decoded before that same absolute deadline. Resolve retransmission, relay dial, DCUtR preference, exact open, fresh-ticket retry, ticket verification, server admission, and upstream dial may not extend it.
- One local ingress connection owns one logical open, one ticket, one `/p2x/proxy/1` substream, and—after Accepted—one upstream TCP connection.
- Metadata and peer connectivity may be reused; a ticket and application substream may not be shared.
- The pre-handshake direct-to-relay fallback and post-Open fresh-ticket rules from Plan 05 remain unchanged. Phase 4 does not automatically retry `upstream.*` failures, because a retry would create another private upstream dial; the local caller may reconnect.
- No application byte is read from the P2P stream by the server or written to it by the product client before Accepted. Local bytes received during setup are retained only in a fixed-size pre-Accept buffer and the kernel socket buffer.
- A client message can select only `upstream_id` and revision values already bound by the ticket. The actual `SocketAddr` comes solely from the server's immutable configuration object.
- Ticket consumption remains final after upstream refusal, Accepted write failure, cancellation, connection loss, or process shutdown. Stream admission rejection performed before consume leaves replay state untouched.
- Registration/auth/exchange-control loss does not terminate an already Accepted direct stream. Loss of its selected P2P connection resets that active v1 stream; only a subsequent local connection obtains a new ticket/path.
- Normal logs and metrics contain no raw ticket, ticket ID, selector/metadata, payload, upstream socket address, credential, verification material, or pre-Accept application bytes.

## 3. Required Design

### 3.1 Repository boundaries and files

Use the component ownership already established; do not move swarm state into a shared lock or add a general actor framework.

| Path | Required change |
| --- | --- |
| `Cargo.toml` | Add the `p2x-proxy` workspace member and pinned workspace dependency entries needed for Tokio/futures compatibility. |
| `crates/p2x-proxy/Cargo.toml` | Add one shared library with no component state and no libp2p dependency. |
| `crates/p2x-proxy/src/lib.rs` | Export the bounded duplex pump, prefixed local stream adapter, result/stat types, and stable internal terminal classes. |
| `crates/p2x-protocol/src/registry.rs` | Add a closed `PROXY_STREAM_V1` capability bit and keep unknown bits rejected. |
| `crates/p2x-protocol/src/error.rs` | Add stable upstream connect-timeout, connect-failure, and idle-timeout public codes without renaming existing codes. |
| `crates/p2x-protocol/src/proxy.rs` | Keep the v1 frame schema and protocol ID unchanged; document `Authorized` as legacy/pre-data and `Accepted` as the only Phase 4 success. |
| `crates/p2x-net/src/proxy_codec.rs` | Make handshake writes flush without closing; expose an explicit close helper only for diagnostics/tests that actually need EOF. |
| `crates/p2x-net/tests/proxy_network.rs` | Turn the synthetic Authorized round trip into Accepted-plus-opaque-data coverage over TCP and QUIC. |
| `apps/p2x-client/src/config.rs` | Add strict `raw_tcp` listener configuration plus ingress/active-stream/buffer limits. |
| `apps/p2x-client/src/ingress.rs` | New fixed-listener and per-local-connection owner: bounded acceptance, pre-Accept buffering, main-loop commands, cancellation, tunnel execution, and terminal reporting. |
| `apps/p2x-client/src/proxy_open.rs` | Replace `authorize_empty_stream` with a final handshake that returns the open libp2p stream only for a correlated Accepted. |
| `apps/p2x-client/src/route_open.rs` | Add the Accepted/streaming transition and a handoff that drops setup/ticket state while retaining server/path correlation for active accounting. |
| `apps/p2x-client/src/connection_manager.rs` | Enforce configured active-plus-pending streams per server and retain active peer state until each tunnel terminal. |
| `apps/p2x-client/src/main.rs` | Bind ingress before connecting, run the route owner in product mode, correlate ingress/open/handshake/tunnel events, keep per-connection errors nonfatal, and cancel only pending/active work owned by shutdown. |
| `apps/p2x-server/src/config.rs` | Build an immutable service router containing advertisement plus redacted TCP policy; add strict dial/buffer limits. |
| `apps/p2x-server/src/upstream.rs` | New IP-literal TCP connector with deadline clipping, redacted errors, and injectable deterministic test outcomes. |
| `apps/p2x-server/src/stream_admission.rs` | New pure owner for global dial and per-service pending/active counts with preflight, promote, and exactly-once release. |
| `apps/p2x-server/src/proxy_open.rs` | Extend the worker from Open verification through owner decision, upstream dial, Accepted, duplex pump, and one terminal release. |
| `apps/p2x-server/src/ticket_admission.rs` | Split live binding validation from replay consumption so stream/dial capacity can be preflighted before a valid ticket is consumed. |
| `apps/p2x-server/src/main.rs` | Route candidate/admission/task events without socket I/O in the swarm owner; track streaming tasks through shutdown and emit privacy-safe evidence. |
| `apps/p2x-server/tests/owner_pipeline.rs` | Extend the actual ticket-owner path through stream admission and immutable local upstream selection. |
| `tests/tunnel/local.sh`, `tests/tunnel/live.py`, `tests/tunnel/README.md` | Add the canonical real-process raw tunnel suite, run-scoped upstream fixtures, strict summaries, cleanup, resource assertions, and privacy scans. |

Add `tokio-util` with only the compatibility/runtime features needed to adapt futures `libp2p::Stream` to Tokio I/O. `p2x-proxy` remains generic over I/O traits; it must not know peer IDs, tickets, selectors, routes, or upstream configuration.

### 3.2 Protocol compatibility and final handshake

Add `Capabilities::PROXY_STREAM_V1 = 1 << 4` and allow bits `0..=4` only. Product client Resolve requests and product server registrations advertise this bit in addition to the existing relay/direct/DCUtR capabilities. The exchange requires the bit on both sides before issuing a proxy ticket and includes it in `compatible_capabilities`. The client also checks the returned compatible bit before opening a Phase 4 stream.

This capability is the mixed-version gate:

- a Plan 06 client does not resolve/open against a Plan 05 server that still requires Open-side EOF;
- a Plan 05 client or exchange rejects the new unknown bit instead of appearing compatible;
- the `/p2x/proxy/1` protocol ID and encoded Open/Accepted/Rejected frames remain version 1 because the final Accepted variant and opaque post-handshake bytes were already committed;
- existing committed vectors remain byte-identical, and new capability vectors cover the bit without regenerating expected bytes during assertions.

The Phase 4 sequence is exactly:

```text
client                         server                         local upstream
  | Open (framed, flush)          |                                  |
  |------------------------------>| verify + live recheck             |
  |                               | reserve stream/dial capacity      |
  |                               | consume one-use ticket            |
  |                               | TCP connect (bounded)             |
  |                               |--------------------------------->|
  | Accepted (framed, flush)      |                                  |
  |<------------------------------|                                  |
  | opaque application bytes      | opaque application bytes         |
  |<=============================>|<================================>|
```

Required codec/worker rules:

- `write_open` and `write_response` write one bounded frame and flush but do not call `close`/`shutdown`.
- The server reads one Open under the existing five-second handshake bound. It does not read a sentinel byte or wait for EOF.
- The product client holds local application bytes until Accepted and rejects `Authorized`, a wrong request ID, a wrong upstream mode, malformed framing, or a response at/after the absolute deadline.
- The server emits `Accepted { request_id, stream_id, selected_upstream_mode: Tcp }` only after TCP connect success. Pre-Accepted failure emits one Rejected when the stream remains writable, then closes it.
- After Accepted, neither side adds application framing, compression, retries, content inspection, or payload hashes.
- Existing Plan 05 tests that assert Authorized are migrated to Accepted and supplied a run-scoped loopback upstream. No product-only test hook may preserve the obsolete Authorized success path.

Add these stable error codes:

| Wire/lifecycle code | Meaning | Retryable field |
| --- | --- | --- |
| `upstream.connect_timeout` | Configured TCP connect did not finish within its bound | `true` |
| `upstream.connect_failed` | Refused, unreachable, or other pre-Accepted TCP connect failure | `true` |
| `upstream.idle_timeout` | No bytes were successfully forwarded in either direction for the configured active-stream idle interval | post-Accepted lifecycle only |

All admission saturation continues to use `limit.proxy_streams`; internal lifecycle fields distinguish ingress, behavior, per-client, per-server, per-service, and dial-limit sources without expanding the public wire registry unnecessarily.

### 3.3 Strict configuration and immutable routing

Extend the current client file without duplicating selectors in listener entries:

```yaml
schema_version: 1
network:
  direct_preference_ms: 1500
  connection_setup_timeout_ms: 20000
targets:
  - route_id: postgres
    selector:
      protocol: tcp
      metadata:
        service: postgres
        environment: production
raw_tcp:
  - name: postgres-local
    bind: 127.0.0.1:15432
    route_id: postgres
limits:
  max_peer_states: 64
  max_pending_setups: 128
  max_pending_per_server: 64
  max_route_opens: 128
  max_ingress_connections: 512
  max_streams_per_server: 128
  copy_buffer_bytes: 32768
```

Client validation must:

- keep `targets` as the single selector source and require every `raw_tcp.route_id` to resolve exactly once;
- require a unique nonempty listener name, unique nonzero `SocketAddr`, and a referenced `ProtocolClass::Tcp` target;
- accept only loopback bind addresses in this phase, preventing accidental LAN/public exposure;
- allow `raw_tcp` to be absent for existing finite auth/registry diagnostics, but require at least one entry for long-running product tunnel mode;
- load and aggregate every schema error before binding; bind every listener before dialing the exchange, and roll back all listeners if any bind fails;
- keep normal help/config free of test-only port or listener overrides.

Extend each server service entry in place so the advertised identity and private policy cannot diverge:

```yaml
schema_version: 1
registration:
  requested_lease_seconds: 30
  refresh_seconds: 10
services:
  - upstream_id: postgres
    selector:
      protocol: tcp
      metadata:
        service: postgres
        environment: production
    enabled: true
    connect: 127.0.0.1:5432
    connect_timeout_ms: 3000
    idle_timeout_ms: 300000
    concurrency_limit: 64
proxy:
  max_workers: 256
  max_workers_per_client: 32
  max_upstream_dials: 64
  copy_buffer_bytes: 32768
  max_replay_entries: 8192
  ticket_clock_skew: 5
```

`LocalUpstream` is immutable and has a custom redacted `Debug` implementation:

```text
LocalUpstream {
    advertisement: ServiceAdvertisementV1,
    connect: SocketAddr,          // never Debug/log/metric/wire
    connect_timeout: Duration,
    idle_timeout: Duration,
    concurrency_limit: usize,
}
```

Server validation must:

- require one IP-literal, nonzero-port TCP `SocketAddr` for every service, including disabled entries;
- reject hostnames, URLs, paths, userinfo, schemes, Unix sockets, duplicate IDs/selectors, zero timeouts, and unknown fields;
- keep `connect` completely outside `ServiceAdvertisementV1`, service-set hashes, registry frames, ticket claims, lifecycle output, and public error messages;
- require Phase 4-ready services used by fixed TCP ingress to have `ProtocolClass::Tcp`; reject other ingress/selector combinations as `protocol.capability_mismatch` before replay consume or dial;
- continue treating `enabled: false` as `Health::Unavailable` and never dial it.

Selected defaults and hard maxima are:

| Limit | Default | Hard maximum / validation |
| --- | ---: | ---: |
| Client accepted local connections, pending plus active | 512 | 2,048 |
| Client simultaneous route setups | 128 | 128 (existing protocol/owner bound) |
| Client pending plus active streams per server | 128 | 512 |
| Server proxy tasks globally | 256 | 2,048 (existing `max_workers`) |
| Server proxy tasks per client | 32 | 256 (existing `max_workers_per_client`) |
| Server concurrent upstream dials | 64 | 512 and no greater than global workers |
| Per-service active/dialing streams | 64 | 1,024 and no greater than global workers |
| Per-direction user-space copy buffer | 32 KiB | 4 KiB–256 KiB |
| Client pre-Accept buffered bytes | same as copy buffer | 256 KiB per admitted ingress |
| Upstream connect timeout | 3,000 ms | 100–20,000 ms |
| Active-stream idle timeout | service-configured, example 300,000 ms | 1,000–3,600,000 ms |

The memory budget attributable to copy buffers is at most two configured buffers per active tunnel worker in each component, plus at most one fixed pre-Accept buffer per client ingress still in setup. Configuration tests must compute these bounds with checked arithmetic and reject a value combination that overflows the platform size type.

### 3.4 Client fixed-ingress ownership

Add one accept loop per validated listener in `apps/p2x-client/src/ingress.rs`. The loop owns its `TcpListener`, route ID, and shutdown signal. It accepts a socket, immediately obtains a global ingress permit with `try_acquire`; if full, it closes the socket and emits `limit.proxy_streams` without enqueueing route work.

Each admitted socket receives an `IngressId` and one task that owns:

```text
IngressId / route_id / accepted_at / absolute setup deadline
TcpStream
fixed-size pre-Accept buffer
one bounded command receiver: StartTunnel or Reject
global ingress permit
event sender: Accepted, CancelledBeforeAccepted, TunnelFinished
terminal-delivered flag
```

The task sends `IngressAccepted` to the main loop and then selects between its command and local reads:

- buffer at most `copy_buffer_bytes` while setup runs; after the buffer is full, stop reading and let the kernel receive window apply backpressure;
- if EOF or a local error is observed before StartTunnel, notify the main loop so it cancels the corresponding route open and all losing setup work;
- on Reject or command-channel closure, close the local socket and release the ingress permit;
- on StartTunnel, wrap the socket in `PrefixedIo` so buffered bytes are the first local-to-P2P bytes, run the shared pump, report one terminal, and release the permit;
- never copy a pre-Accept byte into the P2P stream before the final Accepted handoff.

The main loop owns the bounded `IngressId <-> OpenId` map and the one-shot command sender. It rejects a new ingress immediately when auth is not ready, the route is missing, the route/setup owner is full, or its deadline is already expired. These are per-connection failures: the daemon remains alive, listeners remain bound, and later callers may recover.

### 3.5 Route, path, and active-stream handoff

Use `RouteOpenSupervisor` for normal product connections, not a second resolution/open state machine. Extend it with an explicit final transition:

```text
ExactOpenSucceeded
  -> HandshakeRunning
  -> Accepted(request_id, stream_id, selected_connection)
  -> PathEventKind::PayloadAccepted
  -> TunnelHandoff
```

`TunnelHandoff` contains only `OpenId`, server peer, selected `ConnectionId`/path, request/stream fingerprints, and setup duration. The actual libp2p stream stays in the handshake result and the local socket stays in the ingress task. Creating the handoff removes and zeroizes/drops the grant/ticket and resolve setup state.

Required ownership changes:

- Instantiate `RouteOpenSupervisor` whenever a product route file is loaded; finite diagnostics may drive it through their existing producer, while raw listeners drive it through ingress events.
- Replace the fixed 16-entry handshake-result channel with a configured bounded channel no larger than `max_route_opens`.
- A successful handshake result contains the still-open libp2p stream. Apply Accepted and `PayloadAccepted` before removing setup ownership.
- Extend `SetupLimits` with `max_streams_per_server`. `ConnectionManager::admit` must reject when that server's pending plus active count is full, guaranteeing capacity before Open rather than discovering it after Accepted.
- On handoff, atomically change one server count from pending to active, release its waiter, keep the peer state non-evictable, and send StartTunnel to the matching ingress task.
- On tunnel terminal, decrement active once. Do not close the shared peer connection merely because one substream ended.
- A late resolve, path, handshake, ingress-cancel, or tunnel event for a removed generation is ignored and may not release a newer owner.
- Existing fresh-ticket retry applies only before Accepted. `Authorized` from an old peer is `protocol.capability_mismatch`; upstream Rejected is terminal for that local connection; no event after Accepted can trigger automatic ticket/path retry.

On exchange auth reconnect, preserve active tunnel tasks and connection-manager active counts. Pending route work follows the existing binding/session invalidation rules. New local connections received while auth is unavailable close promptly instead of waiting without a bounded owner.

### 3.6 Server service routing, admission, and upstream dial

`ServiceConfig` constructs both the canonical advertisement `ServiceSet` and an immutable `HashMap<UpstreamId, Arc<LocalUpstream>>`. The map is the only code path allowed to obtain a connect target. Do not add a connect field to Open, ticket, resolve, registry, or worker lifecycle messages.

Split ticket handling into these single-owner transitions:

1. worker decodes Open and verifies signature/time/static claims;
2. server owner finds the current enabled `LocalUpstream` and validates all live ticket/open/service/revision/tenant/peer bindings without consuming replay state;
3. `TicketAdmissionLedger::preflight_candidate` rejects replay or full live replay capacity without mutation;
4. `StreamAdmission::preflight(peer, upstream_id)` verifies per-service and concurrent-dial capacity without mutation;
5. owner consumes the preflighted candidate, inserts replay state, and allocates the stream ID;
6. owner inserts one `Dialing` admission entry keyed by stream ID; because steps 2–6 are synchronous in one owner turn, successful preflight cannot race another mutation;
7. owner returns `ServerDecision::Admit { stream_id, upstream }` to the worker;
8. worker connects to the configured `SocketAddr` under `connect_timeout`, reports dial promotion, writes Accepted, and begins copying;
9. every reject, decision-channel loss, dial failure, response-write failure, copy terminal, cancellation, or shutdown produces one release event.

If stream/dial admission is full, reject with `limit.proxy_streams` before replay consume. If replay consume succeeds but the worker/decision channel disappears, the ticket remains consumed and the newly inserted admission is rolled back exactly once.

`apps/p2x-server/src/upstream.rs` must:

- accept only a prevalidated `LocalUpstream`; expose no function taking client-provided strings;
- clip the TCP connect operation to the configured timeout and classify timeout versus other connect failure without embedding the address in returned/displayed errors;
- avoid automatic address iteration or retry in this phase because the target is one IP-literal socket;
- expose a narrow connector trait/function seam for unit tests; production uses `tokio::net::TcpStream::connect`;
- provide guarded, bounded `P2X_ENABLE_TEST_HOOKS=1` controls for holding/failing a dial only when a canonical live case cannot create the condition reliably through a loopback fixture.

The server worker owns the libp2p stream, upstream socket, configured buffer/idle policy, and admission until terminal. The swarm owner performs no DNS, connect, read, write, copy, or timeout wait.

### 3.7 Bounded duplex pump and half-close semantics

`p2x-proxy` adapts a futures I/O stream and a Tokio I/O stream, then runs two independently scheduled directional copies. Each direction owns exactly one fixed buffer and follows:

```text
read up to buffer size
  -> write_all to the opposite side
  -> increment bytes only after the write succeeds
  -> publish coalesced activity
EOF
  -> shutdown the opposite writer
  -> keep the reverse direction alive
```

The supervisor resets one shared idle deadline whenever either direction successfully forwards bytes. It waits for both clean EOF terminals. Idle expiry, explicit cancellation, or an I/O error aborts the losing direction, closes both streams by ownership drop/shutdown, and returns one `PumpResult`:

```text
PumpResult {
    local_to_remote_bytes,
    remote_to_local_bytes,
    local_eof,
    remote_eof,
    duration,
    terminal: Complete | IdleTimeout | Cancelled | LocalIo | RemoteIo,
}
```

Requirements:

- no whole-payload buffer, unbounded queue, `read_to_end`, application frame, retry buffer, or payload hash;
- activity notification is coalescing (`watch` or equivalent), not one queued message per chunk;
- a blocked writer exerts backpressure on its matching reader and is subject to the shared idle timeout;
- local write-half close propagates through client P2P write-half and server upstream write-half while the response direction remains readable; upstream EOF propagates in reverse;
- clean bidirectional EOF is success even with zero bytes; a single-direction EOF is not terminal until the reverse direction ends or times out;
- cancellation is idempotent and joins/aborts both directional tasks before returning, so no detached copy task retains a socket or permit;
- client uses no competing application idle timeout in this phase; server `LocalUpstream.idle_timeout` is authoritative and closes the P2P stream, causing the client pump to finish.

Unit tests use `tokio::io::duplex` and deliberately small buffers to prove exact bytes, concurrent directions, prebuffer ordering, half-close continuation, slow-reader backpressure, idle reset by either direction, idle expiry, error/cancellation cleanup, and exact counters.

### 3.8 Lifecycle, failure, and shutdown behavior

Add privacy-safe lifecycle records for:

- ingress accepted/rejected/cancelled with hashed listener/route and current pending/active counts;
- setup Accepted with request/stream/connection fingerprints, selected path, and setup duration;
- server upstream dial started/succeeded/failed with hashed upstream ID, latency, and stable code but no address;
- tunnel terminal with component side, request/stream fingerprints, path where known, duration, directional byte counters, half-close observations, and terminal class;
- current ingress tasks, route opens, active peer streams, proxy behavior admissions, proxy tasks, upstream dials, service admissions, and replay entries in final resource evidence.

Do not place production payload hashes in `TerminalResult`; the existing probe fields remain for the connectivity lab only. The tunnel harness validates payload integrity at its run-scoped local application/upstream endpoints.

Failure ownership is:

| Failure point | Required result |
| --- | --- |
| Local close during setup | Cancel its `OpenId`, pending wire/path/open work, and permits; no server dial if Open was not sent. |
| Resolve/path/Open failure | Close only the matching local socket; keep daemon/listeners/other streams alive. |
| Server stream/dial/service limit | Rejected `limit.proxy_streams` before replay consume and no upstream socket. |
| Upstream timeout/refusal | Consume ticket, send matching upstream Rejected when possible, release task/dial/service state, close local socket. |
| Accepted write failure | Close upstream, retain replay consumption, release every stream owner. |
| Local or upstream half-close | Propagate writer shutdown and continue reverse traffic. |
| Idle timeout | Server reports `upstream.idle_timeout`, closes both sides, client observes stream closure. |
| P2P connection loss after Accepted | Active stream resets; task/active counts release; a later local connection re-resolves/reconnects. |
| Exchange control loss during healthy direct stream | Existing stream continues; new ingress fails or recovers through normal auth/resolution ownership. |
| Process shutdown | Stop listener acceptance and new inbound proxy admission, cancel pending and active Phase 4 tasks, await bounded task acknowledgements using the existing shutdown window, then continue withdrawal/reservation cleanup. Final graceful byte draining remains product §24 Phase 6. |

## 4. Ordered Implementation Plan

### 4.1 Lock protocol and state transitions with failing tests

- Add `PROXY_STREAM_V1`, upstream public errors, Accepted-only product handshake tests, flush-without-close codec tests, mixed-capability resolution rejection, and request/stream correlation failures.
- Add failing route/path tests for Accepted-to-streaming, per-server pending-plus-active admission, active release, late handshake/tunnel events, and no retry after Accepted.
- Update committed protocol fixtures only where new capability/error values require new vectors; retain every existing expected byte sequence.

### 4.2 Add the shared bounded pump

- Create `p2x-proxy`, the futures/Tokio compatibility boundary, `PrefixedIo`, duplex pump, activity/idle supervisor, stats, and focused tests from §3.7.
- Prove fixed allocation and task cleanup before integrating sockets or libp2p streams.
- Add the dependency to client/server only; do not expose component configuration or lifecycle types from the crate.

### 4.3 Extend and validate client/server configuration

- Implement `raw_tcp`, ingress/per-server/buffer limits, immutable `LocalUpstream`, connect/idle/service limits, redacted Debug, and strict aggregate validation.
- Update every checked-in auth/registry/resolution fixture to the new required service schema without exposing private targets in generated summaries.
- Bind all client listeners as one startup transaction and cover duplicate/conflicting/missing/non-loopback/zero-port cases.

### 4.4 Complete server Accepted and stream ownership

- Split ticket live validation from consume, add `StreamAdmission`, add the connector, and replace response-only worker decisions with Admit/Reject decisions.
- Keep behavior admission held through streaming, emit Accepted only after dial, run the pump, and release every owner from one terminal path.
- Add owner/state tests for preflight-before-consume, dial N/N+1, per-service N/N+1, consumed-ticket dial failure, decision loss, Accepted write failure, idle, half-close, cancellation, and shutdown.

### 4.5 Add long-running client ingress and handoff

- Build the fixed listener/per-socket tasks and bounded pre-Accept buffer.
- Route `IngressAccepted` through the existing route owner under the accept-time deadline; handle auth-not-ready and per-connection failures without terminating the process.
- Return the open libp2p stream from the handshake worker, apply PayloadAccepted, promote connection-manager state to active, and hand the stream to the exact ingress task.
- On terminal, release ingress and peer-active state once; preserve unrelated streams and shared connections.

### 4.6 Migrate existing proxy authorization evidence

- Update `proxy_network`, `owner_pipeline`, and all 20 resolution cases to use a real run-scoped loopback upstream and assert Accepted rather than Authorized.
- Preserve ticket replay, binding, expiry, direct fallback, connection reuse, concurrency, limits, restart, and drain assertions.
- Ensure a Plan 05 regression cannot pass using a server-only authorization event when Accepted/upstream correlation is absent.

### 4.7 Add canonical raw tunnel cases and documentation

- Implement the cases in §5.3 in dependency order: basic direct/relay, failure/idle, half-close, slow/large, concurrency/limits, control/path loss, then shutdown cleanup.
- Update protocol, configuration, operations, security, and test docs only after the matching executable cases pass.
- Keep owner-executed platform/topology checks separate and explicitly incomplete until run.

Implement and review each subsection as an independent commit. Keep one append-only `rlogs/06-raw-tcp-proxy-tunnel__<timestamp>.rlog` for the implementation session; do not modify this plan during execution.

## 5. Verification

### 5.1 Static and automated checks

Run from the repository root:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
cargo tree -e features
```

Listener tests require an environment that permits loopback TCP/QUIC binding. A sandbox listener denial is an environment failure, not a pass.

Run all existing fuzz targets, with particular attention to `proxy_frame_decode`. The new post-handshake data path is opaque and must not be passed to the handshake decoder. Any panic, excessive allocation, Accepted/Authorized confusion, unknown-code coercion, or raw-ticket/upstream-address leak fails the phase.

### 5.2 Required unit and same-process coverage

- client config/listener aggregate validation, accept-time deadline, prebuffer bound/order, setup cancellation, nonfatal per-ingress errors, active/per-server limits, and exact release;
- server immutable router, redacted Debug/errors, unsupported ingress/selector mode, admission preflight ordering, dial classification, ticket retention, and every release path;
- pump bidirectional transfer, half-close in both directions, slow-reader backpressure, idle reset/expiry, cancellation/error, exact byte counts, and no surviving tasks;
- proxy codec flush without EOF, final Accepted correlation, old Authorized rejection, capability mismatch, and TCP/QUIC Accepted-plus-bytes network tests;
- one actual exchange-issued ticket through current server owner, configured upstream connection, Accepted, bytes, replay rejection, and resource cleanup.

### 5.3 Canonical local process gates

Expose one entry point:

```text
./tests/tunnel/local.sh --case <name|all>
```

Required cases are:

| Case | Required evidence |
| --- | --- |
| `fixed-tcp-direct` | Local caller reaches only the configured echo upstream; Accepted and both component stream fingerprints correlate on a selected direct connection. |
| `fixed-tcp-relay` | The identical payload path succeeds when direct is blocked/disabled and the exact selected connection is relay. |
| `upstream-refused` | Ticket is consumed, server reports `upstream.connect_failed`, no Accepted/application forwarding occurs, local socket closes, and later healthy ingress succeeds. |
| `upstream-timeout` | Deterministic held dial exceeds configured timeout, emits the guarded fault and `upstream.connect_timeout`, and returns dial/service/task counts to zero. |
| `idle-timeout` | Accepted idle stream closes at the configured bound with server `upstream.idle_timeout`; unrelated active traffic continues. |
| `half-close-direct` | Caller sends bytes, shuts down its write half, upstream observes EOF and sends a response, caller reads the complete response, and both directional counts match. |
| `half-close-relay` | The same half-close contract and counts pass over forced relay. |
| `large-slow-direct` | 256 MiB bidirectional transfer with a slow consumer matches endpoint hashes, remains within the declared buffer-derived RSS allowance, and a small concurrent stream finishes first. |
| `large-slow-relay` | The same large/slow isolation passes over forced relay without control-plane starvation. |
| `concurrent-streams` | 64 active streams and the 128-stream headroom run use independent upstream sockets/substreams while reusing bounded peer connectivity; all bytes/correlations are unique. |
| `stream-limits` | Exact client ingress/per-server and server global/per-client/per-service/dial `N`/`N+1` bounds reject at the specified owner, existing streams progress, and released capacity is reusable. |
| `control-loss-direct` | Exchange control is interrupted after Accepted on direct; that stream continues, readiness degrades, and a later ingress recovers after auth/registry recovery. |
| `path-loss-recovery` | Selected P2P loss resets the active local stream, releases counts, and the same client process succeeds on a subsequent local connection through current path policy. |
| `shutdown-cancellation` | Client and server shutdown subcases stop new admission, cancel setup/active work, retain consumed replay semantics, and end with zero Phase 4 logical resources. |

Every case uses run-scoped identities, credentials, key ring, service/routes files, listener ports, upstream fixtures, processes, and artifacts under `target/`. It must validate strict NDJSON, exactly one process terminal, ingress-to-request-to-stream correlation, endpoint-observed bytes, test-hook observation where used, process cleanup, and a privacy scan including the configured upstream address and payload sentinel.

After the new suite passes, rerun all prior local regressions:

```text
./tests/resolution/local.sh --case all
./tests/auth/local.sh --case all
./tests/registry/local.sh --case all
./tests/connectivity/local.sh --case all
```

### 5.4 Timing, memory, and cleanup gates

- Measure setup from local `accept` to Accepted. No successful or failed setup exceeds its configured 20-second deadline plus bounded scheduler tolerance.
- Hold each phase separately—resolve, relay dial, direct preference, exact open, ticket worker, owner decision, upstream dial—and prove the original deadline is never restarted.
- For the 128-stream profile, assert user-space copy/prebuffer allocation remains within the formula in §3.3 and returns near baseline after closure; record RSS/file-descriptor/task samples rather than inferring from success.
- Under slow upstream, slow local reader, half-close, reset, and cancellation, unrelated auth Ping, registry Refresh, Resolve, and small proxy streams continue within their existing bounds.
- After repeated direct/relay open-close cycles, ingress maps, route opens, resolver waiters, connection-manager pending/active counts, proxy behavior admissions, tasks, dial entries, service entries, and replay entries after retention return to baseline.

### 5.5 Final owner-executed platform phase

After local gates pass, run or hand off:

- Linux namespace direct and forced-relay raw TCP cases with firewall/traffic-shaping evidence;
- two-host C14-style raw tunnel over real networks, including one forced relay and one direct-capable topology where available;
- native Linux and macOS client/server behavior, with macOS VM-backed containers required to pass relay and direct recorded as measured best effort;
- long-running 64-stream soak and 128-stream headroom runs with packet loss, exchange reconnect, upstream churn, RSS/file-descriptor sampling, and no control starvation.

Unavailable environments remain incomplete, not passed. Final dashboards, alert thresholds, packaging, and tuned SLO evidence remain product §24 Phase 6.

## 6. Documentation Updates

After executable evidence passes, update:

- `docs/protocol/proxy-v1.md`: capability gate, flush-without-close handshake, Accepted-only Phase 4 success, opaque bytes, rejection ordering, and no active retry;
- `docs/operations/client-connections.md`: fixed listeners, accept-time deadline, bounded prebuffer, active ownership, local failure behavior, connection reuse, control loss, and path-loss reset contract;
- `docs/operations/server-availability.md`: immutable upstream mapping, dial/service limits, Accepted-after-connect, idle policy, stream behavior during control loss, and shutdown cancellation;
- `docs/security/identity-and-credentials.md`: capacity-before-consume ordering, consumed-ticket dial failure, no arbitrary destination, IP-literal Phase 4 restriction, and redaction rules;
- a focused `docs/operations/raw-tcp-tunnels.md`: client/server YAML, loopback exposure rule, local application usage, upstream/certificate non-applicability, half-close, idle timeout, error diagnosis, and v1 reset semantics;
- `tests/tunnel/README.md`, `tests/resolution/README.md`, and `tests/README.md`: executable cases, environment, summary schema, artifact/privacy checks, and owner-executed remainder.

Do not claim HTTP/TLS domain ingress, DNS upstream support, active health checks, seamless active-stream migration, graceful byte draining, dashboards, deployment packaging, or platform evidence that this phase has not implemented and run.

## 7. Definition of Done and Phase Gate

Plan 06 is complete only when:

- long-running `p2x-client` binds validated loopback fixed TCP listeners and drives every local socket through the completed route/connection owner under an accept-time absolute deadline;
- mixed Plan 05/06 peers fail at the explicit `PROXY_STREAM_V1` capability gate instead of hanging on incompatible half-close/Authorized behavior;
- `p2x-server` derives the actual IP-literal destination only from immutable local configuration, reserves capacity before consume, connects it, and emits Accepted only after connect success;
- opaque bytes pass bidirectionally over exact direct and relay streams with fixed buffers, backpressure, two-way half-close, authoritative server idle timeout, cancellation, and no application framing or payload logging;
- every pre-Accepted failure returns one bounded rejection where possible, every post-Accepted failure closes the stream without transparent retry, and ticket replay semantics remain safe;
- client and server enforce the selected ingress, setup, peer, behavior, per-client, per-server, per-service, dial, replay, buffer, connect, and idle bounds;
- existing resolution/auth/registry/connectivity suites remain passing after migration from Authorized to real Accepted/upstream evidence;
- all canonical tunnel cases pass with endpoint byte verification, exact correlation, privacy scans, timing/memory evidence, and zero locally owned resources;
- documentation matches executable behavior and owner-executed topology/platform/soak work is clearly separated.

Only after this gate may Plan 07 add exact HTTP Host routing and TLS SNI passthrough above the same route, ticket, connection, Accepted, and bounded tunnel core.
