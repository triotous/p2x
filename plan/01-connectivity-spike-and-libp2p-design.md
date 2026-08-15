# Plan: Connectivity Spike and rust-libp2p Design

- **Document status:** implementation-ready Stage 2 design; spike results are not yet available
- **Date:** 2026-08-14
- **Parent baseline:** [`plan/00-product-analysis.md`](00-product-analysis.md), especially §§10–15, 23.1, 24 Phase 0, 25.1, 27, and 28
- **Architecture gate:** registry, ticket, ingress, and production proxy work must not begin until §9 passes
- **Target baseline:** Rust 1.96.0 and `libp2p` 0.56.0, subject to the post-spike freeze in §7.7

## 1. Goal, Scope, and Required Outcome

This plan proves and fixes the P2X connectivity foundation before product protocols are built. The implementation must demonstrate that one private server can reserve relay capacity at `p2x-exchange`, a private client can establish a relayed connection to that server, DCUtR can add a direct TCP or QUIC connection, and P2X can open a new application substream on an explicitly selected `ConnectionId`.

The spike is successful only when all of the following are supported by repeatable evidence:

1. a server reservation becomes reachable through Circuit Relay v2 and renews without process restart;
2. a client can always use the prepared relay path when peer-to-peer traffic is blocked;
3. DCUtR can produce direct TCP and QUIC connections in supported topologies;
4. direct and relayed connections to the same `PeerId` may coexist, and a caller can target either one for a new substream;
5. lack of a terminal DCUtR event cannot block fallback beyond the configured direct-preference deadline;
6. losing exchange connectivity does not terminate an already healthy direct stream;
7. relay limits, slow readers, concurrent streams, cancellation, and TCP-style half-close remain bounded and observable.

### 1.1 In scope

- Bootstrap the workspace shape required for the connectivity spike while preserving exactly three product binaries.
- Pin a provisional Rust and rust-libp2p baseline and commit `Cargo.lock`.
- Compose the exchange and peer swarms with TCP, QUIC, DNS, Noise, Yamux, Circuit Relay v2, Identify, Ping, and DCUtR.
- Implement a small custom `/p2x/spike/1` stream behaviour that targets one exact `ConnectionId`.
- Implement pure reservation and path-selection state machines around libp2p events.
- Add same-process, three-process, Linux namespace, forced-path, two-host, concurrency, and interruption tests.
- Record machine-readable evidence and an ADR accepting or rejecting this foundation.

### 1.2 Out of scope

- Fixed-token enrollment, exchange identity pinning, tenant authorization, and relay authorization; these belong to Plan 02/03. Until then, the relay is lab-only and must bind loopback by default.
- Registry, selector resolution, tickets, ticket replay protection, and `/p2x/proxy/1`.
- HTTP Host, TLS SNI, fixed TCP ingress, and private upstream dialing.
- Production metrics endpoints, dashboards, deployment manifests, dynamic configuration, or multi-exchange support.
- Active-stream migration. If the selected direct or relay connection dies after the probe stream is committed, that stream fails; only a later stream may select another path.
- AutoNAT, rendezvous, UPnP, WebRTC, custom STUN/TURN, or copied RustDesk/`peer-gateway` traversal code.
- Selecting the repository's final license. The spike must set `publish = false`, must not distribute artifacts, and must not copy or adapt RustDesk source while the repository license remains undecided. AGPL is considered only if future approved RustDesk source use requires it; it is not the current default.

## 2. Confirmed Evidence and Provisional Decisions

### 2.1 Repository and toolchain state

- The repository currently contains product analysis and editor metadata only. There is no Rust workspace, source, test harness, dependency convention, remote CI provider, or existing implementation to preserve.
- Rust 1.96.0 and Cargo 1.96.0 are installed locally. Use `rust-toolchain.toml` to make the spike reproducible; do not claim this as the long-term MSRV until the matrix passes.
- `.gitignore` currently ignores `Cargo.lock`. Remove that rule because P2X produces applications and needs reproducible dependency resolution.

### 2.2 rust-libp2p API evidence

Use the current stable [`libp2p` 0.56.0 release](https://github.com/libp2p/rust-libp2p/releases/tag/libp2p-v0.56.0) as the provisional baseline.

Confirmed properties of that release:

- The official DCUtR example composes TCP/Noise/Yamux, QUIC, DNS, the relay client transport, Identify, Ping, and `dcutr::Behaviour` in one peer swarm.
- `dcutr::Event.result` returns the successful direct `ConnectionId` or a terminal error.
- `SwarmEvent::ConnectionEstablished` and `ConnectionClosed` expose a `ConnectionId` and `ConnectedPoint`; `ConnectedPoint::is_relayed()` distinguishes a circuit connection from a direct connection.
- A custom `NetworkBehaviour` can emit `ToSwarm::NotifyHandler { handler: NotifyHandler::One(connection_id), ... }`, so its `ConnectionHandler` can request a substream on one exact connection.
- `NotifyHandler::One` silently drops an event if the connection has already disappeared. P2X must therefore combine close-event handling with an explicit open timeout; awaiting handler notification alone can hang.
- The separate `libp2p-stream` 0.4 alpha helper chooses an arbitrary existing connection for a peer. It is useful reference code but cannot meet P2X's direct-versus-relay selection contract and must not be the spike's stream opener.
- Circuit Relay v2 exposes hard counts, duration, byte limits, and reservation/circuit rate limiters. Authentication-aware relay admission is not provided by those numeric settings and remains a Plan 03 requirement.

### 2.3 Dependency contract

The root manifest must use the meta-crate with default features disabled:

```toml
[workspace.dependencies]
libp2p = { version = "=0.56.0", default-features = false, features = [
  "dcutr",
  "dns",
  "ed25519",
  "identify",
  "macros",
  "noise",
  "ping",
  "quic",
  "relay",
  "tcp",
  "tokio",
  "yamux",
] }
```

Do not enable `full`, `autonat`, `rendezvous`, `request-response`, `tls`, `websocket`, or `upnp` for this spike. QUIC already supplies its authenticated encryption; TCP uses Noise and Yamux. Add only the ordinary runtime/test dependencies used by code (`tokio`, `futures`, `clap`, `tracing`, `tracing-subscriber`, `serde`, `serde_json`, `thiserror`, and test utilities), define them once under `[workspace.dependencies]`, and let the committed lockfile freeze their exact transitive versions.

The release's relevant internal crate baseline is `libp2p-swarm` 0.47.0, `libp2p-dcutr` 0.14.0, `libp2p-relay` 0.21.0, `libp2p-quic` 0.13.0, `libp2p-tcp` 0.44.0, `libp2p-noise` 0.46.1, and `libp2p-yamux` 0.47.0. Depend on the `libp2p` meta-crate rather than pinning these crates independently; verify their resolved versions from `Cargo.lock` in the evidence report.

## 3. Target Workspace and Ownership

Create only the files needed to prove the architecture:

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml
deny.toml
crates/
  p2x-net/
    Cargo.toml
    src/
      lib.rs
      builder.rs
      connection_book.rs
      path_selector.rs
      reservation.rs
      probe.rs
      probe_stream/
        mod.rs
        behaviour.rs
        handler.rs
        upgrade.rs
apps/
  p2x-exchange/
    Cargo.toml
    src/main.rs
  p2x-client/
    Cargo.toml
    src/main.rs
  p2x-server/
    Cargo.toml
    src/main.rs
tests/
  connectivity/
    README.md
    local.sh
    netns.sh
    two-host.md
plan/
  evidence/
    01-connectivity-spike-results.md
docs/
  adr/
    0001-rust-libp2p-connectivity.md
```

`p2x-net` owns reusable networking mechanics. The three apps own process lifecycle and remain the only binaries. Shell fixtures orchestrate those binaries but contain no networking logic. Generated logs and JSON results go under `target/p2x-spike/<run-id>/` and remain untracked; the compact, scrubbed conclusion is committed under `plan/evidence/`.

### 3.1 Type ownership

| Owner | Types | Rule |
| --- | --- | --- |
| `builder.rs` | `ExchangeBehaviour`, `PeerBehaviour`, builder functions | Construct transports/behaviours only; no background tasks or global state |
| `connection_book.rs` | `ConnectionBook`, `ConnectionRecord`, `PathKind`, `TransportKind` | Derive connection truth only from swarm/DCUtR events; socket addresses are not identity |
| `path_selector.rs` | `PathAttempt`, `PathState`, `PathDecision`, `FallbackReason` | Pure deterministic state machine with injected timestamps; no sleeps or socket I/O |
| `reservation.rs` | `ReservationState`, `ReservationEvent` | Combine relay acceptance, relayed listen address, renewal, listener closure, and exchange connection loss |
| `probe_stream/*` | `ProbeStreamBehaviour`, `ProbeStreamHandler`, `ProbeUpgrade` | Negotiate raw streams on one specified `ConnectionId`; no product authorization or proxy framing |
| `probe.rs` | bounded test header/ack and byte-pattern helpers | Spike-only evidence protocol; must not be reused as `/p2x/proxy/1` |
| each `main.rs` | one `Swarm`, command/event loop, cancellation, CLI, result output | A swarm is polled by exactly one owning task; workers communicate through bounded channels |

## 4. Swarm Composition

### 4.1 Shared transport settings

Both peer apps listen on ephemeral TCP and QUIC sockets even though no public endpoint is configured. Exchange listens on configured stable TCP and QUIC addresses.

Build peer swarms in this order, matching the 0.56 builder contract:

```text
with_existing_identity
  -> with_tokio
  -> with_tcp(tcp nodelay, Noise, Yamux)
  -> with_quic_config
  -> with_dns
  -> with_relay_client(Noise, Yamux)
  -> with_behaviour
  -> with_swarm_config
  -> build
```

Load one Ed25519 key per process and use it for every transport in that process. Deterministic seed-based keys are allowed only behind the spike CLI. Production key persistence and exchange identity pinning are Plan 02 work.

The spike must set and log these provisional bounds rather than inherit invisible defaults:

| Setting | Spike value | Purpose |
| --- | ---: | --- |
| Yamux maximum streams per connection | 256 | Covers the 128-stream headroom plus protocol overhead |
| QUIC maximum bidirectional streams | 256 | Same bound for direct QUIC |
| Concurrent inbound protocol negotiations per connection | 64 | Bounds handshake work without limiting established streams |
| Probe substream negotiation timeout | 5 s | Prevents a lost handler event or negotiation from hanging |
| Swarm idle connection timeout | 120 s | Keeps a reusable direct and relay pair alive during tests |
| Ping interval / timeout | 15 s / 5 s | Supplies liveness evidence without deciding path selection alone |
| Direct-preference window | 1.5 s | Approved product default |
| Total setup deadline | 20 s | One absolute budget from test request to probe acceptance |

Yamux must retain its on-read window-update behavior so slow application reads exert backpressure. Do not use deprecated receive-buffer/window APIs. Log the QUIC and Yamux stream limits in the evidence output.

### 4.2 Exchange swarm

`ExchangeBehaviour` contains only:

```text
relay: relay::Behaviour
identify: identify::Behaviour
ping: ping::Behaviour
```

Create the relay with `relay::Behaviour::new(exchange_peer_id, relay_config)`. The default lab profile is intentionally not a production capacity recommendation:

- 64 reservations globally and 2 per peer;
- 128 circuits globally and 4 per source peer;
- 60-second reservation duration so renewal is observable in a short test;
- 60-minute circuit duration and 1 GiB per-circuit byte cap for transfer tests;
- explicit, test-friendly reservation/circuit rate limiters that do not trip during the 100-iteration run.

Add a separate `limit-test` profile with very small limits so acceptance and denial events can be asserted without changing code. Emit structured events for reservation accepted/renewed/closed/timed out and circuit accepted/denied. The spike relay is not authorization-complete: non-loopback binding requires an explicit `--unsafe-lab-public-relay` flag and a runbook warning to firewall the listener to the test peers.

### 4.3 Peer swarm

The same `PeerBehaviour` is used by client and server:

```text
relay_client: relay::client::Behaviour
dcutr: dcutr::Behaviour
identify: identify::Behaviour
ping: ping::Behaviour
probe_stream: ProbeStreamBehaviour
```

Use an Identify protocol string such as `/p2x/connectivity/0.1.0`, enable pushed listen-address updates, and advertise only addresses emitted/confirmed by the swarm. Do not synthesize public peer addresses from observed socket ports.

The server calls `listen_on` for local TCP and QUIC addresses, dials exchange, then calls `listen_on(<exchange-address>/p2p-circuit)`. Use exactly one configured direct connection to exchange for each spike run so reservation ownership and loss are unambiguous; run the relay baseline once over exchange TCP and once over exchange QUIC. The client also listens on local TCP/QUIC, dials the complete server circuit address, and lets DCUtR act on the resulting relayed peer connection.

## 5. Event and State Design

### 5.1 Connection inventory

`ConnectionBook` is the authority for usable P2P connections. Key it by `(PeerId, ConnectionId)` and assign an internal monotonic sequence number for deterministic selection; do not parse or order the opaque `ConnectionId`.

```text
ConnectionRecord {
  peer_id,
  connection_id,
  path: Direct(Tcp | Quic) | Relay { exchange_peer_id } | UnknownDirect,
  endpoint_role: Dialer | Listener,
  established_at,
  dcutr_confirmed: bool,
  last_ping_ok_at?,
  closing: bool,
}
```

Event rules:

- Insert on `SwarmEvent::ConnectionEstablished`. Determine relay versus direct with `ConnectedPoint::is_relayed()`, then classify TCP/QUIC from the local/dial multiaddress.
- Mark a direct record as DCUtR-confirmed when `dcutr::Event { result: Ok(connection_id), ... }` arrives.
- Accept either ordering between `ConnectionEstablished` and the DCUtR success event; join them by `ConnectionId` before declaring the new direct path selectable for the current attempt.
- Remove and fail related pending opens on `ConnectionClosed`. Ignore later stale success/failure events for that connection.
- Record Ping results for diagnostics. Do not switch or close a path from one missed Ping alone; normal swarm close events remain authoritative in the spike.
- Preserve direct connections when the exchange peer disconnects. Remove only records whose own `ConnectionId` closed.

Existing healthy direct connections are immediately reusable. If several exist, prefer QUIC over TCP and the oldest still-open record within that class. During a new DCUtR attempt, the first confirmed direct connection wins; do not wait for a preferred transport after one direct path is usable.

### 5.2 Server reservation state machine

```text
Disconnected
  -> ExchangeDialing
  -> ExchangeConnected
  -> ReservationRequested
  -> ReservationAccepted
  -> RelayAddressConfirmed
  -> Ready

Any exchange connection/listener/address loss
  -> Degraded
  -> jittered retry in the owning process
  -> Ready
```

`Ready` requires both `relay::client::Event::ReservationReqAccepted` and a matching relayed `SwarmEvent::NewListenAddr`; these events may arrive in either order. Store the relay listener ID, exchange `PeerId`, canonical full circuit address, last acceptance time, renewal count, and generation number.

Treat `renewal: true` as evidence that the library renewed the reservation. Treat `ExpiredListenAddr`, `ListenerClosed`, closure of the exchange connection used for the reservation, or disappearance of the confirmed relay address as degradation. Recreate the circuit listener only after the previous generation is closed or invalidated. Backoff is 250 ms initially, doubles to 10 s, adds 20% jitter, and resets only after a confirmed reservation. The spike must remain running while degraded so existing direct streams can continue.

### 5.3 Client path state machine

One `PathAttempt` owns one absolute setup deadline, direct-preference timer, relay `ConnectionId`, optional direct `ConnectionId`, pending substream request, and cancellation token.

```text
Absent
  -> RelayDialing
  -> RelayReady
  -> DirectWaiting
  -> Committed(Direct(connection_id) | Relay(connection_id))
  -> StreamOpening
  -> Streaming | Failed
```

Selection algorithm:

1. At request creation, set `setup_deadline = now + 20 s`. Never add independent sequential timeouts that can exceed it.
2. If `ConnectionBook` already contains a healthy direct connection to the target, commit it immediately.
3. Otherwise reuse or dial the complete server circuit address and wait for a relayed `ConnectionEstablished` event for the server `PeerId`.
4. When relay is ready, set `direct_deadline = min(now + 1.5 s, setup_deadline)`. The relay connection remains open and DCUtR proceeds automatically.
5. If a DCUtR-confirmed direct record appears before `direct_deadline`, atomically commit that direct `ConnectionId`.
6. On explicit DCUtR failure or `direct_deadline`, commit the relay `ConnectionId` if it remains open. A missing DCUtR terminal event is therefore an expected timer path, not a hang.
7. Once committed, do not let a late direct event switch the current stream. Keep that direct record for future streams.
8. Open exactly one probe substream on the committed connection. If negotiation fails or the connection closes before the probe is accepted, one fallback to the still-open relay is allowed within the original setup deadline and before application payload is committed.
9. After the probe is accepted and payload transfer starts, connection loss fails the stream. Do not reopen or replay bytes on another path.
10. On setup expiry, cancel all losing work, close the pending stream, and emit `setup_timeout` with the last direct and relay outcomes.

Use a monotonically increasing `AttemptId` so late timer, dial, DCUtR, close, or open events cannot complete a newer request. Every terminal transition releases its pending-open entry and permit exactly once.

## 6. Exact-Connection Probe Stream

### 6.1 Why a custom behaviour is required

P2X cannot use an API that accepts only `PeerId`, because the swarm may hold direct and relayed connections to that peer simultaneously. The custom behaviour must expose this application-side command:

```text
OpenProbe {
  request_id: RequestId,
  peer_id: PeerId,
  connection_id: ConnectionId,
}
```

`ProbeStreamBehaviour::open_on` validates queue capacity and enqueues:

```text
ToSwarm::NotifyHandler {
  peer_id,
  handler: NotifyHandler::One(connection_id),
  event: HandlerCommand::Open { request_id },
}
```

The per-connection handler converts the command to `ConnectionHandlerEvent::OutboundSubstreamRequest` using `SubstreamProtocol::new(ProbeUpgrade, request_id).with_timeout(5 s)`. `OutboundOpenInfo` carries `request_id`, so multiple negotiations may be in flight without relying on queue order.

`ProbeUpgrade` negotiates only `StreamProtocol::new("/p2x/spike/1")` and returns the raw `libp2p::swarm::Stream`. The behaviour emits:

```text
OutboundOpened { request_id, peer_id, connection_id, stream }
OutboundFailed { request_id, peer_id, connection_id, error }
InboundOpened { peer_id, connection_id, stream }
```

The owning swarm loop matches outbound events to one-shot replies and passes inbound streams to a bounded worker pool. It must also time out every open request and fail it on `ConnectionClosed`, because a targeted notify may be silently dropped during a close race.

### 6.2 Required bounds and invariants

- Swarm command channel: 128 entries; a full channel returns `limit.command_queue_full` immediately.
- Pending outbound probe opens: 128 globally and no more than 64 per peer.
- Inbound probe workers: 128 globally and 64 per remote peer; excess streams are reset without buffering payload.
- Probe header and acknowledgement: one length-prefixed JSON frame, maximum 4 KiB, parsed before allocating payload buffers.
- Copy buffers: fixed 32 KiB per direction. Tests may transfer large bodies but may not allocate the body size in advance.
- No unbounded channel or `VecDeque` exists on the command, behaviour, handler, or payload path.
- A request ID belongs to one peer and connection; mismatched events are protocol/internal errors, not successful completions.
- `InboundOpened` records the server's observed `PathKind` and `ConnectionId` in its acknowledgement. The client compares that with its requested path, so a false direct/relay result cannot pass by logging only the client decision.
- Dropping a stream or cancellation token closes both directions and releases all permits once.

### 6.3 Spike payload modes

The bounded spike header selects one of three test-only modes:

- `nonce_echo`: server returns the nonce plus its observed path; proves exact connection selection.
- `half_close`: both sides exchange deterministic byte patterns, independently close their write halves, read to EOF, and verify byte counts plus hashes.
- `slow_reader`: receiver reads in delayed 32 KiB chunks while the sender streams a deterministic pattern; the harness samples RSS, task count, queue depth, and completion time to prove backpressure.

These modes are evidence tooling, not the future proxy handshake. Plan 05/06 must define production authorization and wire compatibility separately.

## 7. Implementation Plan

### 7.1 Bootstrap the workspace

1. Add a virtual root `Cargo.toml` with resolver 2, the three app members, `crates/p2x-net`, shared dependency declarations, and workspace lint settings.
2. Add `rust-toolchain.toml` pinned to 1.96.0 with `rustfmt` and `clippy` components.
3. Remove the `Cargo.lock` ignore rule, generate the lockfile, and keep every package `publish = false` during the spike.
4. Add `deny.toml` for advisories, duplicate/version review, allowed registries/Git sources, and dependency license checks. Do not encode the unresolved P2X project SPDX choice as if it were approved.
5. Add minimal CLI skeletons for the three existing product names. `--identity-seed` and `--unsafe-lab-public-relay` must be visibly lab-only flags.
6. Verify all three binaries print their `PeerId`, start, receive cancellation, and exit without orphan tasks.

### 7.2 Implement transport and swarm builders

1. Implement Yamux and QUIC configuration helpers with the explicit limits from §4.1.
2. Implement `build_exchange_swarm` and `build_peer_swarm` in `builder.rs`; return concrete swarm types rather than boxed dynamic behaviours.
3. Map derived behaviour events into small `ExchangeEvent` and `PeerEvent` enums so app code does not match nested generated enums throughout the codebase.
4. Start TCP and QUIC listeners before dialing the relay so Identify can advertise usable local addresses.
5. Add unit tests that inspect supported protocol IDs and fail if an accidental feature/protocol (for example rendezvous) is enabled.

### 7.3 Implement exact-connection opening

1. Implement `ProbeUpgrade` with only `/p2x/spike/1` and no application read/write during negotiation.
2. Implement a per-connection handler with bounded open commands, request IDs in `OutboundOpenInfo`, 5-second negotiation timeouts, and explicit negotiation/IO/unsupported errors.
3. Implement `ProbeStreamBehaviour` with `NotifyHandler::One(connection_id)` and the events in §6.1.
4. Reject unknown/stale `(PeerId, ConnectionId)` pairs before enqueueing. Still retain close-event and timeout cleanup for races.
5. Unit-test two fake connection handlers for one peer and assert that opening on A never reaches B. Test connection-close before notify, during negotiation, after negotiation, and after stream delivery.

### 7.4 Implement connection and reservation tracking

1. Implement multiaddress classification and `ConnectionBook` insertion/removal from actual swarm events.
2. Reconcile out-of-order DCUtR and connection-established events by `ConnectionId`.
3. Implement `ReservationState` as a pure transition function, then wire it to server events and retry timers.
4. Make `p2x-server` ready only after reservation acceptance and matching relayed listen address confirmation. Print the canonical circuit address as structured JSON for the harness.
5. Verify at least one renewal, then force exchange connection loss and prove the server enters `Degraded` without exiting or closing unrelated direct connections.

### 7.5 Implement client path selection and probe actors

1. Implement `PathAttempt` with injected time and the one 20-second absolute budget described in §5.3.
2. Wire relayed connection establishment, DCUtR success/failure, deadline expiry, and connection closure into the pure state machine.
3. Open the probe only after a path is committed; never race application substreams on direct and relay.
4. Implement the single pre-payload fallback when direct stream negotiation fails and relay remains usable.
5. Add structured result fields: attempt ID, peer IDs, selected local/server path, selected connection ID hashes, relay-ready latency, DCUtR latency/outcome, substream-open latency, total setup latency, fallback reason, bytes, half-close result, and stable error code.
6. Ensure a late direct success after relay commitment is retained for the next request but cannot move the current stream.

### 7.6 Build the repeatable lab

1. `tests/connectivity/local.sh` starts exchange, server, and client as three processes, uses process groups for cleanup, allocates free ports safely, waits on structured readiness rather than fixed sleeps, and stores artifacts under `target/p2x-spike/`.
2. `tests/connectivity/netns.sh` creates three Linux namespaces and explicit firewall/traffic-shaping rules for TCP-only, QUIC-only, all-direct-blocked, high-latency, and packet-loss cases. It must validate targets before teardown and clean only resources bearing the run ID.
3. `tests/connectivity/two-host.md` documents exchange firewall ports, native Linux/macOS peer commands, expected JSON fields, clock/environment capture, and safe teardown. A public lab relay is firewall-limited because Plan 02 authentication does not exist yet.
4. Add a same-process Rust integration test for deterministic state/event races. Use the three-process fixtures for OS socket, process-loss, and namespace behavior.
5. Make every harness failure print component logs and the last state transition; `connected=true` without path evidence is not a passing assertion.

### 7.7 Record results and freeze the decision

1. Create `plan/evidence/01-connectivity-spike-results.md` from the scrubbed test summaries. Record OS/runtime, Rust/Cargo versions, exact `Cargo.lock` libp2p versions, commands, topology, path evidence, latency, resource peak/baseline, failures, and rerun count.
2. Create `docs/adr/0001-rust-libp2p-connectivity.md` only after the gate runs. The ADR must state `Accepted`, `Accepted with required custom handler`, or `Rejected`; it must not predeclare success.
3. If accepted, retain exact `libp2p = "=0.56.0"`, commit the passing `Cargo.lock`, and make subsequent plans depend on the `ConnectionBook`, `PathAttempt`, and exact-connection opener contracts.
4. If a dependency change is required to pass, rerun the entire matrix before changing the baseline in this plan, the evidence, and ADR.

## 8. Verification

### 8.1 Static and unit checks

Run from the repository root:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo deny check
```

Required unit coverage:

- direct/relay/TCP/QUIC multiaddress classification;
- connection insertion, close, duplicate, stale DCUtR, and out-of-order event handling;
- direct-first, existing-direct, explicit failure, silent timeout, relay loss, late direct, setup timeout, and cancellation transitions;
- reservation event reordering, renewal, listener loss, exchange loss, retry generation, and stale retry suppression;
- exact `ConnectionId` targeting and close races;
- queue/permit limits and exactly-once release;
- bounded probe header/ack parsing and invalid-size rejection;
- deterministic byte pattern and half-close verification.

### 8.2 Mandatory connectivity matrix

| ID | Setup | Required assertion |
| --- | --- | --- |
| C01 | Same host, TCP and QUIC enabled | Relay becomes ready; DCUtR selects a direct path; probe succeeds |
| C02 | Direct QUIC only between peers | Selected path is direct QUIC, not relay |
| C03 | Direct TCP only between peers | Selected path is direct TCP, not relay |
| C04 | All peer-to-peer packets blocked; exchange TCP allowed | Relay probe succeeds within the 20-second setup deadline |
| C05 | Direct and relay both established | Opening on the direct ID is observed direct; opening on the relay ID is observed relay |
| C06 | Suppress/ignore terminal DCUtR outcome | Relay commits after approximately 1.5 seconds and never waits indefinitely |
| C07 | Kill exchange during an active direct half-close transfer | The direct stream completes; server becomes degraded for new relay reachability |
| C08 | Kill the selected P2P connection during payload | Active stream fails; a subsequent request reconnects and succeeds without process restart |
| C09 | Low relay reservation/circuit limits | Excess work is denied, classified, and does not starve existing control/events |
| C10 | 64 concurrent mixed probes, then 128 headroom probes | Independent results, no wrong-connection opens, queues stay bounded, resources return to baseline |
| C11 | 256 MiB direct and relay slow-reader transfers | Hashes match, RSS does not grow with payload size, and unrelated nonce probes remain responsive |
| C12 | Reservation duration elapsed twice | At least two renewals are observed and the advertised circuit remains dialable |
| C13 | 100 direct/relay connect-close iterations | No leaked tasks, listeners, connection records, permits, or monotonically growing RSS/FD count |
| C14 | Two real machines on separate networks | Relay succeeds; direct outcome and environment are recorded without treating relay as failure |

For timing assertions, allow a documented scheduler margin around the 1.5-second preference timer, but never allow total setup beyond 20 seconds. Store raw monotonic durations; wall-clock timestamps are diagnostic only.

### 8.3 Result schema

Each run writes one JSON summary with at least:

```text
run_id, case_id, git_revision, dirty_worktree,
rustc_version, cargo_version, libp2p_version,
client_peer_id, server_peer_id, exchange_peer_id,
client_path, server_observed_path,
relay_ready_ms, dcutr_outcome, dcutr_ms,
direct_preference_ms, stream_open_ms, setup_total_ms,
fallback_reason, bytes_up, bytes_down, half_close_ok,
peak_rss_bytes, final_rss_bytes, peak_fd_count, final_fd_count,
terminal_code, passed
```

Peer IDs may be present in local artifacts but should be shortened or hashed in the committed evidence. Never include private keys, seed values, payload, or future credentials.

## 9. Architecture Gate and Acceptance Criteria

The implementation may proceed to Plan 02/03 only when:

- `libp2p` 0.56.0 builds reproducibly on the pinned Rust toolchain and the exact lockfile is recorded;
- server relay reservation, renewal, loss detection, and recovery work without restarting the server;
- TCP relay works when direct UDP and TCP are both blocked;
- DCUtR produces direct QUIC and direct TCP in the controlled supported cases;
- the client and server independently prove that `/p2x/spike/1` opened on the requested direct or relay `ConnectionId` while both connections coexist;
- an absent/late DCUtR result falls back on the timer and total setup never exceeds the absolute deadline;
- exchange loss does not destroy an established direct stream;
- connection loss has the approved v1 reset behavior and later requests recover;
- 64-stream expected load and 128-stream headroom pass without wrong-path selection, control starvation, unbounded memory, or leaked tasks/file descriptors;
- large direct and relay transfers prove bounded backpressure and half-close;
- all static, unit, integration, namespace, and at least one two-host run are captured in the evidence document;
- the ADR records the observed result rather than the intended architecture.

If exact connection targeting fails, stop before registry/proxy implementation. First correct the custom `NetworkBehaviour`/`ConnectionHandler` while retaining `NotifyHandler::One`; if the public 0.56 APIs cannot make that reliable, evaluate a narrowly scoped rust-libp2p upgrade and rerun the full matrix. Do not hide the failure by opening streams by `PeerId`, by closing the relay as soon as direct appears, or by reporting a preferred path that the server did not observe.

If direct connectivity is weak only in real NAT cases, keep relay as the availability floor and record the measured direct rate; that result does not by itself reject rust-libp2p. Reject the foundation only for a correctness, bounded-fallback, supported-platform, or explicit-connection-selection failure that remains after the allowed custom handler work.

## 10. Primary References

- [rust-libp2p 0.56.0 release](https://github.com/libp2p/rust-libp2p/releases/tag/libp2p-v0.56.0)
- [libp2p 0.56.0 features](https://docs.rs/crate/libp2p/0.56.0/features)
- [Official rust-libp2p hole-punching tutorial](https://docs.rs/libp2p/0.56.0/libp2p/tutorials/hole_punching/index.html)
- [rust-libp2p `NetworkBehaviour`](https://docs.rs/libp2p/0.56.0/libp2p/swarm/trait.NetworkBehaviour.html)
- [rust-libp2p `ToSwarm` and targeted handler notification](https://docs.rs/libp2p/0.56.0/libp2p/swarm/enum.ToSwarm.html)
- [Circuit Relay v2 `Config`](https://docs.rs/libp2p/0.56.0/libp2p/relay/struct.Config.html)
