# Fix Plan: Complete the Connectivity Architecture Gate

- **Document status:** implementation-ready corrective follow-up to Plan 02
- **Date:** 2026-08-14
- **Reviewed baseline:** commit `298c0ff` on `feat/02-connectivity-gate-remediation`
- **Parent documents:** [`02-connectivity-gate-remediation.md`](02-connectivity-gate-remediation.md), [`01-connectivity-spike-and-libp2p-design.md`](01-connectivity-spike-and-libp2p-design.md), and [`00-product-analysis.md`](00-product-analysis.md)
- **Decision:** Plan 03 remains blocked. ADR 0001 is still `Deferred`, and the reviewed implementation does not satisfy the Phase 0 connectivity gate.

## 1. Goal and Scope

Finish the incomplete Plan 02 implementation, prove the exact-connection and bounded-fallback architecture with the mandatory C01-C14 matrix, and update the evidence and ADR from observed results.

This follow-up is corrective rather than a new product phase. It must not add persistent production identity, enrollment/authentication, registry, signed tickets, ingress, upstream dialing, or `/p2x/proxy/1`. Those remain blocked until every acceptance criterion in this document passes and ADR 0001 is accepted.

## 2. Review Result

### 2.1 Verification performed

| Check | Reviewed result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed. |
| `cargo test --workspace --all-targets` | Passed 13 unit tests; all three application crates have zero tests. No live relay, DCUtR, exact-path, payload, lifecycle, or harness test ran. |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed. |
| `cargo deny check` | Failed because `cargo-deny` is not installed. |
| `tests/connectivity/local.sh --case C01` | Exited 2 with `terminal_code: unsupported`; it did not start any P2X process. |
| Evidence and ADR | [`01-connectivity-spike-results.md`](evidence/01-connectivity-spike-results.md) says C01-C14 are not passed; [`ADR 0001`](../docs/adr/0001-rust-libp2p-connectivity.md) remains `Deferred`. |

The passing static/unit checks show that the current skeleton compiles. They do not close the Plan 02 architecture gate.

### 2.2 Confirmed defects and omissions

| ID | Priority | Confirmed finding | Required correction |
| --- | --- | --- | --- |
| 02A-01 | P0 | The three binaries only construct and poll swarms. Exchange listens on TCP only with `relay::Config::default()`. Server never dials exchange or creates a circuit listener. Client can dial exchange but never dials the server circuit address, observes DCUtR, selects a path, opens a probe, or emits a terminal result. | Implement the exchange, server, and client lifecycle described in Plan 02 §§3.7 and 4.4, including both TCP and QUIC listeners, server reservation/recovery, client relay-first dialing, exact-path selection, probe execution, and graceful cancellation. |
| 02A-02 | P0 | `ProbeUpgrade` returns the negotiated stream, but `ProbeHandler` discards both inbound and outbound streams and reports only a `RequestId`. `ProbeOutput` contains neither stream, peer, nor connection. No probe payload can be exchanged or independently classified by the server. | Carry the raw `libp2p::swarm::Stream` plus `RequestId`, `PeerId`, and `ConnectionId` through all success events, and carry stable errors plus the same identifiers through failure events. Emit inbound streams to the bounded server worker path. |
| 02A-03 | P0 | `local.sh` and `netns.sh` are fixed unsupported-result writers. The C14 commands invoke a server that has no exchange/circuit arguments and a client that produces no required terminal result. C01-C14 therefore cannot run. | Build real process orchestration for every case, update C14 to match the implemented CLI, validate all result fields, and preserve failure artifacts. |
| 02A-04 | P1 | Exact-open accounting is incorrect: `OpenProbe` owns only `RequestId`; the alleged per-peer limit counts all pending IDs globally; connection close does not fail/remove matching pending requests; there is no request deadline or cancellation; handler and event `VecDeque`s are unbounded; and a late handler event re-inserts a connection into `known`. | Key each request by request/peer/connection, maintain real global and per-peer counts, bound every queue, expire/cancel requests, drain them on exact connection close, reject mismatches, and release capacity exactly once on every terminal path. |
| 02A-05 | P1 | `PathAttempt` is still a mutable bag of optional fields. It has no `AttemptId`, relay-open truth, stream-opening/payload-commit phases, cancellation, setup-timeout transition, selected-connection close handling, or one permitted pre-payload direct-to-relay fallback. `fallback` does not check either deadline. | Replace it with the Plan 02 §3.4 state/action model and table-test all event orderings, deadline boundaries, stale attempts, close races, and exactly-once terminal cleanup. |
| 02A-06 | P1 | Reservation events carry no generation, exchange connection, listener, or address identity. `ExchangeConnected` clears `degraded` while leaving old `accepted` and `address_confirmed` facts set, so a reconnect can become falsely ready. The context does not implement canonical circuit address, last acceptance time, retry delay/jitter, generation replacement, or stale-event suppression. | Make readiness generation-scoped, clear stale facts on a new generation, match all loss/renewal/retry events to their owner, and implement the 250 ms-to-10 s jittered retry policy without disturbing active direct streams. |
| 02A-07 | P1 | `ConnectionBook` classifies from a supplied `Multiaddr` instead of the authoritative `ConnectedPoint`, omits endpoint role, never actively expires pending DCUtR entries, and retains tombstones forever. It cannot meet the C13 no-growth invariant. | Consume real swarm endpoints, retain the required record fields, drive expiry from the owning loop/timer, bound or expire tombstones, and provide exact close hooks for pending probe opens and DCUtR successes. |
| 02A-08 | P1 | `probe.rs` implements only a synchronous header frame and a CPU-bound hash helper. It has no acknowledgement, async stream I/O, mode-specific bounds, payload transfer, half-close, slow reader, fixed 32 KiB copy loop, or inbound worker admission. `write_frame` panics on oversize instead of returning a protocol error. | Implement the complete bounded spike protocol and workers from Plan 02 §3.6, with incremental generation/hash verification and stable terminal errors. |
| 02A-09 | P1 | Builder constants are not applied to Yamux or swarm negotiation settings; the default QUIC value happens to be 256 but is not explicitly configured or logged. DNS, pushed Identify address updates, relay profiles, and QUIC listeners are missing. `SwarmConfig` listener fields are validated but ignored, and the server passes an empty config before listening on an unchecked CLI address. | Apply every declared transport/relay bound, validate the actual addresses before `listen_on`, add both relay profiles, enable the required builder phases, and test constructed behaviour/configuration rather than a separate one-element constant array. |
| 02A-10 | P2 | Lifecycle JSON is assembled with `println!`, contains no schema/version or guaranteed terminal record, and cannot satisfy the evidence schema. The committed evidence does not enumerate resolved component versions (`libp2p-swarm 0.47.1`, `dcutr 0.14.1`, `relay 0.21.1`, `quic 0.13.1`, `tcp 0.44.1`, `noise 0.46.1`, `yamux 0.47.0`). | Define serializable event/result types, use `serde_json`, make exactly one terminal result mandatory, pin the verification tool, and generate the scrubbed evidence only from validated run summaries. |

## 3. Required Completion Contract

### 3.1 Networking configuration

Refactor [`builder.rs`](../crates/p2x-net/src/builder.rs) so configuration values are applied rather than exposed as unused constants.

- Define separate validated exchange and peer configs. Listener addresses used by the binaries must be part of validation; do not validate one value and pass a different value to `Swarm::listen_on`.
- Build in the required order: Tokio, TCP with `nodelay`/Noise/Yamux, explicitly configured QUIC, DNS, relay client for peers, behaviours, then swarm config.
- Set Yamux maximum streams to 256, QUIC bidirectional streams to 256, maximum inbound negotiations to 64, idle timeout to 120 seconds, Ping to 15/5 seconds, and Identify pushed listen-address updates to enabled.
- Add `RelayProfile::{DefaultLab, LimitTest}`. `DefaultLab` uses 64 global/2 per-peer reservations, 128 global/4 per-source circuits, 60-second reservations, 60-minute circuits, and a 1 GiB circuit cap. `LimitTest` uses deterministic small limits suitable for C09. Configure explicit rate limiters that allow C12/C13 under the default profile.
- Exchange must refuse non-loopback TCP or QUIC listeners unless `--unsafe-lab-public-relay` is supplied. Peer CLI addresses remain explicit lab settings and must be logged in structured readiness.
- Replace `supported_protocols()` as the sole surface check with tests that instantiate the real behaviours and assert the Cargo feature set excludes AutoNAT, rendezvous, request-response, TLS, WebSocket, and UPnP.

### 3.2 Connection, reservation, and path state

Implement the following as pure state transitions with injected monotonic time; app loops execute returned actions.

1. `ConnectionBook` receives `ConnectedPoint` from `SwarmEvent::ConnectionEstablished`, stores endpoint role and actual endpoint address, uses `ConnectedPoint::is_relayed()`, validates the relay exchange peer ID, and exposes only open DCUtR-confirmed direct records. Pending DCUtR successes and close tombstones have explicit expiry plus hard caps and are swept by a timer even when no later connection event arrives.
2. `ReservationContext` owns one generation containing the expected exchange peer/connection, relay `ListenerId`, canonical circuit address, acceptance/address facts, last acceptance time, renewal count, retry attempt, and retry deadline. Events include those identities. A new generation clears old readiness facts; stale loss, renewal, address, and retry events are no-ops.
3. `PathAttempt` uses an `AttemptId` and data-bearing variants: `Absent`, `RelayDialing`, `DirectWaiting`, `Committed`, `StreamOpening`, `Streaming`, and `Failed`. It owns one immutable 20-second setup deadline and a 1.5-second direct deadline. It commits once, permits one relay fallback only before payload acceptance, and terminates on cancellation, setup expiry, or loss of the selected connection without replaying accepted bytes.
4. All three state modules expose bounded counts needed by C10/C13 diagnostics and explicit cleanup methods used on shutdown.

Required unit tables include every Plan 01 §8.1 case plus:

- `ConnectionBook`: both DCUtR/establish orders, endpoint-role/path classification, wrong peer, duplicate establish, close-before-success, expiry without a later network event, bounded tombstones, QUIC preference, and oldest-record tie breaking.
- Reservation: both acceptance/address orders, two renewals while ready, new generation after exchange loss, stale old-generation loss/retry, listener/address mismatch, backoff cap/jitter bounds, and retry reset only after readiness.
- Path: existing direct, direct before/at/after the boundary, explicit and silent DCUtR failure, relay loss before commitment, direct-open failure with one relay fallback, close before/after payload acceptance, cancellation, setup timeout, repeated terminal events, and stale `AttemptId` events.

### 3.3 Exact-connection stream lifecycle

Refactor [`probe_stream/behaviour.rs`](../crates/p2x-net/src/probe_stream/behaviour.rs), [`handler.rs`](../crates/p2x-net/src/probe_stream/handler.rs), and [`upgrade.rs`](../crates/p2x-net/src/probe_stream/upgrade.rs) around these contracts:

```text
OpenProbe { request_id, peer_id, connection_id }

OutboundOpened { request_id, peer_id, connection_id, stream }
OutboundFailed { request_id, peer_id, connection_id, code }
InboundOpened { peer_id, connection_id, stream }
```

- The behaviour stores the full request and deadline before emitting `NotifyHandler::One(connection_id)`. A handler success/failure must match all stored identifiers before it can complete the request.
- The handler returns the negotiated raw stream in both inbound and outbound success events; it never drops a successful stream merely to signal an ID.
- Enforce 128 pending opens globally and 64 per peer with separate counters keyed by `PeerId`. Cap the behaviour command/event queues and each handler command/event queue. Queue-full paths fail immediately with `limit.command_queue_full`.
- On exact `ConnectionClosed`, fail all matching queued and in-flight requests. An explicit timer handles the `NotifyHandler::One` close race. Cancellation, timeout, negotiation failure, mismatch, success delivery, and shutdown each release counters exactly once.
- Never reinsert a known connection from a handler event. Only connection-established events add it, and connection-close removes it.
- Add same-process integration tests that maintain one relayed and one direct connection to the same peer, open concurrently on both exact IDs, assert the receiver's independently observed path, then close each selected connection at every pre-delivery race point.

### 3.4 Bounded probe protocol and workers

Extend [`probe.rs`](../crates/p2x-net/src/probe.rs) and the server/client worker paths:

- Define bounded `ProbeHeader` and `ProbeAck` schemas for `nonce_echo`, `half_close`, and `slow_reader`. Ack fields include nonce/request correlation, receiver-observed `PathKind`, receiver-local connection-ID hash, byte counts, incremental hashes, half-close result, and terminal code.
- Validate the 4-byte declared frame length before allocation, reject unknown/oversized mode parameters, reject trailing or malformed content as specified by the schema, and return errors from `write_frame` rather than panicking.
- Perform asynchronous stream reads/writes with a reusable 32 KiB buffer. Generate and hash payload bytes incrementally; a 256 MiB case must never allocate a payload-sized buffer or execute an unyielding 256 MiB CPU loop on the swarm task.
- Implement real write-half closure and EOF verification in both directions. `slow_reader` delays each bounded chunk without blocking swarm polling or unrelated workers.
- Admit at most 128 inbound workers globally and 64 per remote peer before reading a header. Reject excess streams immediately, keep per-peer accounting bounded, and release permits once on every exit path.

### 3.5 Process event loops and structured output

Implement component-specific CLIs in the existing three `main.rs` files and keep each swarm owned by exactly one task.

- `p2x-exchange`: deterministic lab identity, TCP and QUIC listen addresses, relay profile, public-lab acknowledgement, artifact/result destination, structured listen/readiness/relay events, and graceful drain.
- `p2x-server`: deterministic identity, complete exchange address and expected peer ID, local TCP and QUIC listeners, circuit-listener generation, reservation renewal/recovery, bounded inbound probe workers, structured readiness/degraded events, and a canonical circuit address.
- `p2x-client`: deterministic identity, exchange/server identities and circuit address, requested/forced path, probe mode/size/count/concurrency, timing budget, structured result destination, and a finite run mode used by the harness.
- The server dials exactly one configured exchange connection, then creates `<exchange-address>/p2p-circuit`; the client listens locally and dials the server's complete circuit address so DCUtR operates on the relayed peer connection.
- Map swarm, relay-client, DCUtR, Ping, timer, worker, and cancellation events into the corrected state machines. Workers communicate over bounded channels and never own or poll the swarm.
- Define `Serialize` event/result structs with a schema version and use `serde_json::to_writer`/`to_string`. Every finite client run emits exactly one terminal result; early process exit without it is a harness failure.

### 3.6 Executable connectivity harness

Replace the unsupported stubs in [`tests/connectivity/local.sh`](../tests/connectivity/local.sh) and [`netns.sh`](../tests/connectivity/netns.sh).

- `local.sh` builds once, allocates collision-safe ports, starts exchange/server/client in one owned process group, waits for structured readiness, supports the documented `--streams`, `--bytes`, and `--iterations` selectors, applies faults only to its own processes, validates terminal JSON, and cleans up through a trap.
- `netns.sh` validates Linux, effective privileges, required tools, a strict run-ID pattern, and every target before mutation. Create exchange/server/client namespaces plus explicit TCP/UDP filtering and traffic-control profiles for C02-C04 and the relevant fault cases. Teardown may address only names bearing the validated run ID.
- Implement C01-C13 with the exact commands and assertions in Plan 02 §5.2. Local relay cases run once with exchange TCP and once with exchange QUIC. C02/C03 prove direct QUIC/TCP independently; C04 blocks all direct peer traffic while preserving exchange TCP.
- Sample process RSS, file descriptors, worker/task counts, connection records, pending opens, queue depth, and permits for C10-C13. Compare post-run values to the captured baseline and fail on monotonic growth or unreleased logical resources.
- Every case writes raw per-process logs and one summary below `target/p2x-spike/<run-id>/`. Validate every Plan 01 §8.3 field, both sides' path observations, the 20-second maximum, and exactly one terminal result before setting `passed: true`.
- Update [`two-host.md`](../tests/connectivity/two-host.md) with commands that match the finished CLIs, TCP/UDP firewall requirements, readiness extraction, result validation, redaction, and teardown. Run C14 on two native hosts on separate real networks; relay success is mandatory and the direct outcome is reported rather than forced.

### 3.7 Evidence and gate closure

1. Pin `cargo-deny` 0.20.2 in the verification environment and document the reproducible install/invocation so `cargo deny check` is a required pass, not an optional local tool.
2. Run formatting, Clippy, all targets/tests, and dependency policy checks on Rust 1.96.0 with the committed lockfile.
3. Run C01-C13 from a supported Linux environment with the required namespace privileges. Also run C01 and applicable local cases as native macOS processes to cover the second supported platform, then run C14 on two real networks.
4. Generate [`plan/evidence/01-connectivity-spike-results.md`](evidence/01-connectivity-spike-results.md) from validated, scrubbed JSON. Enumerate exact resolved libp2p component versions, commands, topology, path evidence, timing, resource baseline/peak/final values, rerun counts, and all failures.
5. If every invariant passes, set ADR 0001 to `Accepted` or `Accepted with required custom handler` and record the observed constraints. If exact targeting or another mandatory invariant still fails, set it to `Rejected`, preserve the failing evidence, and stop before Plan 03.

## 4. Implementation Order

1. Add the missing deterministic state, accounting, codec, and close-race tests so 02A-04 through 02A-09 fail for the reviewed code.
2. Correct `ConnectionBook`, `ReservationContext`, and `PathAttempt`; keep time and side effects injected.
3. Correct the exact-connection behaviour/handler so raw streams and complete identifiers survive negotiation and every request has bounded lifecycle accounting.
4. Implement the async probe codec, payload modes, half-close semantics, and bounded worker admission.
5. Apply transport/relay settings and complete both TCP/QUIC swarm construction.
6. Wire exchange, server, and client event loops and schema-validated terminal output.
7. Add same-process integration tests, then implement and run the local and namespace harnesses.
8. Run C14, update evidence, and decide ADR 0001. Start Plan 03 only after the ADR is no longer `Deferred` and all mandatory checks pass.

## 5. Verification and Acceptance Criteria

Plan 02a is complete only when all of the following are true:

- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-targets`, and `cargo deny check` all pass.
- Unit/integration tests prove exact `ConnectionId` targeting, receiver-observed path agreement, close-race termination, timeout/cancellation, real per-peer/global limits, and exactly-once cleanup.
- Both peers listen on configured TCP and QUIC addresses; exchange relay profiles and every declared stream/negotiation/time bound are applied and emitted in run metadata.
- Server reservation becomes ready only from matching acceptance plus address facts, stays ready across renewals, degrades on matching loss, and recovers with a new generation without process restart.
- Client commits one path within the original 20-second budget, cannot switch after commitment, and uses at most one pre-payload relay fallback.
- Nonce, half-close, slow-reader, 256 MiB, 64-stream, 128-stream, renewal, interruption, and 100-iteration cases complete without false path claims, starvation, unbounded memory, leaked tasks, records, file descriptors, or permits.
- C01-C14 all have schema-valid, scrubbed evidence with client-selected and server-observed paths. Unsupported scripts, skipped platforms, or missing C14 evidence are failures.
- ADR 0001 records the observed accept/reject decision. Plan 03 remains absent until the decision is accepted and this checklist is complete.
