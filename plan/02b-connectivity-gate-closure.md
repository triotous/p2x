# Fix Plan: Close the Remaining Connectivity Gate

- **Document status:** implementation-ready second corrective follow-up to Plans 02 and 02a
- **Date:** 2026-08-14
- **Reviewed baseline:** commit `fbaeff1` on `feat/02-connectivity-gate-remediation`
- **Parent documents:** [`02a-connectivity-gate-completion.md`](02a-connectivity-gate-completion.md), [`02-connectivity-gate-remediation.md`](02-connectivity-gate-remediation.md), and [`01-connectivity-spike-and-libp2p-design.md`](01-connectivity-spike-and-libp2p-design.md)
- **Decision:** do not create Plan 03 yet. ADR 0001 is still `Deferred`, C01-C14 are unexecuted, and the implementation does not close the Phase 0 architecture gate.

## 1. Goal and Scope

Finish the live relay/DCUtR/exact-connection spike, correct the remaining state and accounting defects, execute the mandatory connectivity matrix, and make ADR 0001 an evidence-backed accept/reject decision.

This plan preserves the useful partial work after Plan 02a: oversized probe writes now return an error, exact-open success events retain the raw stream and observed peer/connection identity, path selection has explicit time constants, and connection tombstones have an expiry/sweep API. Those changes are foundations only; none has been proved end-to-end.

Production identity persistence, enrollment/authentication, the registry, signed tickets, ingress, upstream dialing, and `/p2x/proxy/1` remain out of scope. Plan 03 may start only after §7 passes and ADR 0001 is accepted.

## 2. Review Result

### 2.1 Verification performed

| Check | Result at `fbaeff1` |
| --- | --- |
| `cargo fmt --all -- --check` | Passed. |
| `cargo test --workspace --all-targets` | Passed 13 `p2x-net` unit tests. All three application crates still have zero tests; no live connection or payload test ran. |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed. |
| `cargo deny check` | Failed because the `cargo-deny` subcommand is not installed. |
| `tests/connectivity/local.sh --case C01` | Exited 2 and wrote `terminal_code: unsupported`; it started no P2X component. |
| Evidence and ADR | The evidence explicitly says C01-C14 are not passed, and ADR 0001 remains `Deferred`. |

The resolved networking baseline is `libp2p 0.56.0`, `libp2p-swarm 0.47.1`, `libp2p-dcutr 0.14.1`, `libp2p-relay 0.21.1`, `libp2p-quic 0.13.1`, `libp2p-tcp 0.44.1`, `libp2p-noise 0.46.1`, and `libp2p-yamux 0.47.0`. The final evidence must enumerate these values instead of referring generically to `Cargo.lock`.

### 2.2 Confirmed findings

| ID | Priority | Confirmed finding | Required result |
| --- | --- | --- | --- |
| 02B-01 | P0 | [`p2x-exchange`](../apps/p2x-exchange/src/main.rs) listens only on TCP with the default relay profile. [`p2x-server`](../apps/p2x-server/src/main.rs) never connects to exchange or creates a circuit listener. [`p2x-client`](../apps/p2x-client/src/main.rs) can dial only an exchange address and has no server circuit dial, DCUtR/path state, exact open, payload, or finite terminal result. | Implement the complete exchange, server, and client lifecycles in §3.5. |
| 02B-02 | P0 | [`ProbeStreamBehaviour`](../crates/p2x-net/src/probe_stream/behaviour.rs) removes requests on connection close without removing queued commands or emitting terminal failures. It has no deadline, cancellation, shutdown drain, or expected-versus-observed peer/connection validation. Behaviour event queues and both handler queues remain unbounded. | Give every exact open a bounded, exactly-once terminal lifecycle as specified in §3.1. |
| 02B-03 | P0 | [`PathAttempt`](../crates/p2x-net/src/path_selector.rs) remains a unit-state enum plus optional fields. `DirectDeadline` can commit relay before the deadline, committed opens are exempt from setup expiry, cancellation ignores committed work, `AttemptId` is not attached to events, and no API implements stream opening, payload acceptance, selected-connection close, or the one pre-payload direct-to-relay fallback. | Replace it with the event/action state machine in §3.2; do not patch the current setters further. |
| 02B-04 | P0 | [`ReservationContext`](../crates/p2x-net/src/reservation.rs) still accepts identity-free events. `ExchangeConnected` clears `degraded` while retaining old acceptance/address facts, so a reconnect can become falsely ready. There is no canonical circuit address, listener identity, generation replacement, retry deadline/jitter, or stale-event suppression. | Implement generation-scoped reservation readiness and recovery in §3.3. |
| 02B-05 | P1 | [`ConnectionBook`](../crates/p2x-net/src/connection_book.rs) still classifies a caller-supplied `Multiaddr`, not the authoritative `ConnectedPoint`; it omits endpoint role and endpoint address. Its sweep is not called by an app loop, close does not clean exact opens, and a full tombstone map silently stops recording closes. | Consume real swarm endpoints, wire periodic expiry and close cleanup, and prove bounded high-churn behavior in §3.3. |
| 02B-06 | P1 | [`probe.rs`](../crates/p2x-net/src/probe.rs) has only synchronous header framing and a CPU-bound byte-at-a-time hash. It has no acknowledgement schema, mode-specific limits, async payload I/O, half-close, slow reader, 32 KiB copy loop, stable I/O errors, or inbound worker admission. | Implement the bounded protocol and workers in §3.4. |
| 02B-07 | P1 | [`builder.rs`](../crates/p2x-net/src/builder.rs) exposes stream/negotiation constants but does not apply them. TCP nodelay, Yamux limits, explicit QUIC limits, DNS, inbound negotiation limits, Identify push, relay profiles, and configured TCP/QUIC listener startup are missing. The protocol test checks a standalone one-element constant. | Apply and test the actual networking configuration in §3.5. |
| 02B-08 | P1 | [`local.sh`](../tests/connectivity/local.sh) and [`netns.sh`](../tests/connectivity/netns.sh) remain fixed unsupported writers; the C14 commands do not match a functional server/client lifecycle. No same-process exact-path integration test exists. | Implement the harness and execute C01-C14 as specified in §3.6. |
| 02B-09 | P2 | Lifecycle JSON is still assembled with `println!`, has no schema version or guaranteed terminal record, and the evidence/ADR correctly describe an incomplete gate but contain no observed connectivity or resource results. ADR 0001 also says “Plans 02/03” remain blocked even though Plans 02-02b are the corrective gate work. | Use typed serialization, validate terminal output, and update evidence/ADR only from passing artifacts in §3.7. |

## 3. Required Completion Contract

### 3.1 Exact-connection open lifecycle

Refactor [`probe_stream/behaviour.rs`](../crates/p2x-net/src/probe_stream/behaviour.rs) and [`handler.rs`](../crates/p2x-net/src/probe_stream/handler.rs) around a `PendingOpen` containing the request, creation/deadline times, and terminal-delivery state.

- Keep `OpenProbe { request_id, peer_id, connection_id }` and the raw-stream output contracts already added. Allocate `RequestId` with checked monotonic increment; exhaustion is a stable terminal error, not wraparound.
- Before accepting a command, verify the exact connection and reserve one global/per-peer permit. Keep at most 128 requests globally and 64 per peer. A request retains its permit until its terminal event is delivered or explicitly discarded during shutdown.
- On a handler event, compare the callback peer/connection and the stored `OpenProbe`. A mismatch completes that request as `probe.internal_identity_mismatch`; it must never be reported as a successful open.
- On exact connection close, remove matching commands that have not reached the handler, mark every matching queued/in-flight request `probe.connection_closed`, and deliver one failure per request. Do not silently delete pending state.
- Add `expire(now)`, `cancel(request_id)`, and `shutdown()` paths. The owning swarm loop must drive expiry often enough to enforce the five-second negotiation/open deadline and handle the documented `NotifyHandler::One` close race.
- Replace every unbounded `VecDeque`. Bound behaviour commands, outbound terminal delivery, and per-handler command/event queues. Tie terminal queue admission to pending permits so a burst of inbound streams cannot consume capacity reserved for outbound completion. Reset/drop excess inbound streams with `limit.inbound_queue_full` accounting before reading application bytes.
- Do not add connections from handler callbacks. Only swarm connection-established events add them; exact close removes them.

Add unit tests for unknown connection, real per-peer/global limits, request-ID exhaustion, mismatched identity, queue full, cancel before/after notify, close before notify/during negotiation/after negotiation, timeout without a close event, success/late-failure reordering, shutdown drain, and exactly-once permit release. Add a same-process integration test that keeps direct and relayed connections to one `PeerId` open simultaneously and proves concurrent exact opens reach only their selected `ConnectionId`.

### 3.2 Path-attempt state machine

Replace the current public optional-field structure with data-bearing state and one transition entry point:

```text
PathAttempt { id, started_at, setup_deadline, state }

Absent
RelayDialing
DirectWaiting { relay_id, direct_deadline }
Committed { decision }
StreamOpening { decision, request_id, relay_id, relay_fallback_used }
Streaming { decision }
Failed { reason }
```

Every input is `PathEvent { attempt_id, now, kind }`; `apply` ignores stale IDs and returns explicit actions such as `DialRelay`, `OpenExact`, `CancelOpen`, `CloseStream`, or `Finish`. App code executes actions and feeds results back; the state module performs no I/O or sleeps.

Required transition rules:

1. `setup_deadline` is fixed at creation plus 20 seconds and applies through exact-open completion. Commitment alone does not stop the setup clock.
2. A healthy pooled direct connection may commit immediately. Otherwise relay must be confirmed open before starting the 1.5-second preference window.
3. `DirectDeadlineElapsed` commits relay only when `now >= direct_deadline`; a caller-provided enum reason cannot force early fallback. A matching confirmed direct connection wins only before that boundary.
4. Direct exact-open failure in `StreamOpening`, before any payload is accepted, may issue one relay exact open if the original relay is still open and the original setup deadline has not expired. It cannot return to DCUtR waiting or reset either deadline.
5. Payload acceptance moves to `Streaming` and forbids replay/fallback. Selected-connection close then fails only that stream; a later request starts a new attempt.
6. Cancellation, setup expiry, relay loss without an eligible direct/relay action, or repeated terminal events releases resources exactly once. Late direct success remains in `ConnectionBook` for a future attempt but cannot change this attempt.

Table-test existing direct, relay readiness, direct before/at/after boundary, explicit/silent DCUtR failure, early timer events, setup expiry from every non-streaming state, both exact-open outcomes, one fallback, payload commitment, cancellation, selected/unselected close, relay loss, stale IDs, and repeated events.

### 3.3 Connection and reservation truth

Refactor [`connection_book.rs`](../crates/p2x-net/src/connection_book.rs) so `on_connection_established` accepts the actual `ConnectedPoint` and records endpoint role, actual endpoint address, path, sequence, establishment time, DCUtR confirmation, ping time, and closing state.

- Use `ConnectedPoint::is_relayed()` as relay truth. For relayed endpoints, extract and validate the configured exchange `PeerId`; for direct endpoints classify QUIC before TCP.
- Keep pending DCUtR successes and recent-close tombstones at hard caps with explicit expiry and deterministic oldest-expiry eviction. A full cap must remain bounded without allowing a closed connection to become selectable.
- Expose counts and one injected-time `sweep(now)`. Drive it from the owning peer loop even when no connection event arrives. Exact close must also call the probe opener and current path attempt cleanup.
- Preserve only open, DCUtR-confirmed direct selections; prefer QUIC then oldest sequence. Exchange control loss removes only its exact records, not unrelated direct connections.

Replace `ReservationEvent` with identity-bearing events for generation, exchange peer/connection, relay `ListenerId`, and canonical circuit address. `ReservationContext` must own those values plus acceptance/address facts, last acceptance time, renewal count, retry attempt, and retry deadline.

- Creating or reconnecting a generation clears old readiness facts. Acceptance and address confirmation commute and repeat idempotently only within the same generation.
- Renewal preserves readiness and increments the matching generation. Stale loss, listener, address, renewal, and retry events are no-ops.
- Matching exchange/listener/address loss degrades readiness and schedules injected-jitter retry starting at 250 ms, doubling to 10 seconds. Reset retry state only after matching readiness is restored.
- The server advertises ready only when both facts belong to the current generation and emits the canonical circuit address used by the client.

Retain all Plan 02a §3.2 unit tables and add a high-churn test that closes more than the tombstone cap, advances time, runs `sweep`, and proves no false direct selection or retained logical resources.

### 3.4 Bounded probe protocol and workers

Extend [`probe.rs`](../crates/p2x-net/src/probe.rs) with `ProbeHeader`, `ProbeAck`, stable terminal codes, and async readers/writers for `nonce_echo`, `half_close`, and `slow_reader`.

- Keep the four-byte big-endian frame prefix and 4096-byte frame maximum. Reject oversized declarations before allocation, deny unknown fields where the schema requires exactness, validate mode-specific length/delay/count caps, and distinguish malformed/truncated/timeout/I/O terminal codes.
- Include nonce/request correlation, receiver-observed `PathKind`, receiver-local connection-ID hash, directional byte counts/hashes, half-close result, and terminal code in `ProbeAck`.
- Stream deterministic bytes and hashes in reusable 32 KiB buffers. Do not call `pattern_hash(length)` for large payloads on the swarm task and do not allocate payload-sized buffers.
- Implement async write-half closure and read-to-EOF verification in both directions. `slow_reader` delays bounded chunks in a worker without blocking swarm polling.
- Admit inbound workers before reading a header: 128 globally and 64 per peer. Use bounded worker-result channels and release all permits exactly once on success, rejection, timeout, I/O failure, cancellation, and shutdown.

Test schema limits, invalid/trailing data, all terminal codes, short reads/writes, 0-byte and maximum configured transfers, half-close, slow-reader concurrency, worker rejection, cancellation, and constant-buffer behavior.

### 3.5 Networking configuration and process lifecycle

Refactor [`builder.rs`](../crates/p2x-net/src/builder.rs) into separate validated exchange/peer configuration types and make the values used by each `listen_on` call come from those validated configs.

- Build Tokio, TCP with nodelay/Noise/Yamux, explicit QUIC, DNS, relay client for peers, behaviours, then swarm config. Apply 256 Yamux/QUIC streams, 64 inbound negotiations, five-second probe negotiation, 120-second idle timeout, Ping 15/5 seconds, and Identify pushed listen-address updates.
- Add `RelayProfile::{DefaultLab, LimitTest}` with the exact limits from Plan 02a §3.1. Exchange must start configured TCP and QUIC listeners and reject either public listener unless the unsafe lab acknowledgement is present.
- Replace the standalone `supported_protocols()` assertion with tests that construct actual behaviours/config and verify the exact feature/protocol surface and effective bounds.

Complete the existing binaries without adding product binaries:

1. `p2x-exchange` starts both listeners, uses the selected relay profile, emits typed readiness/relay events, writes to an optional artifact destination, and drains gracefully.
2. `p2x-server` listens on TCP/QUIC, dials exactly one configured exchange connection with an expected exchange `PeerId`, creates and renews the circuit listener, runs bounded inbound probe workers, degrades/recovers by generation, and publishes typed readiness with its canonical circuit address.
3. `p2x-client` listens on TCP/QUIC, validates exchange/server identities and the server circuit address, establishes relay first, observes DCUtR, drives `ConnectionBook` and `PathAttempt`, opens the selected exact connection, runs the requested probes, and exits finite mode with exactly one terminal result.
4. Workers communicate with the one swarm owner through bounded channels. Cancellation closes admissions, drains or cancels bounded work, releases all permits, and leaves no child tasks.

Define shared `Serialize` lifecycle/result structs with a schema version. Use `serde_json::to_writer`/`to_string`; do not assemble JSON with formatting strings. No finite client exit path may omit its one terminal result.

### 3.6 Executable connectivity harness

Replace the unsupported stubs while preserving the stable C01-C14 definitions from Plan 02 §5.2 and Plan 01 §8.2.

- `local.sh` builds once, validates case-specific arguments, allocates collision-safe TCP/UDP ports, owns all child processes, waits for schema-valid readiness, validates exactly one client terminal record plus the server-observed path, captures resources, and cleans only its run.
- `netns.sh` validates Linux, privileges, tools, and a strict run ID before mutation. Create exchange/client/server namespaces and scoped firewall/traffic-control rules for direct QUIC, direct TCP, all-direct-blocked, latency/loss, and interruption cases. Teardown may target only names derived from the validated run ID.
- Store raw per-process logs and one validated summary per case below `target/p2x-spike/<run-id>/`. Missing fields, process exit without terminal JSON, path disagreement, setup over 20 seconds, unreleased logical counts, or unsupported cases fail.
- Measure RSS, file descriptors, worker/task counts, connection records, pending opens, queue depths, listeners, and permits for C10-C13. Compare final values with the captured baseline and fail monotonic growth.
- Update `two-host.md` only after the CLIs exist, then execute C14 on two native hosts on separate networks. Relay success is mandatory; report the direct result honestly.

Run local relay coverage once through exchange TCP and once through exchange QUIC. C02-C13 require the supported Linux namespace environment; platform unavailability is not a passing artifact.

### 3.7 Evidence and decision

1. Provision and pin `cargo-deny 0.20.2` in the verification environment; record the reproducible installation/invocation and require `cargo deny check` to pass.
2. Generate [`01-connectivity-spike-results.md`](evidence/01-connectivity-spike-results.md) from validated, scrubbed case summaries. Record exact component versions, commands, git revision/dirty state, topology, both path observations, monotonic timings, payload/hash/half-close results, resource baseline/peak/final values, rerun counts, and failures.
3. Keep ADR 0001 `Deferred` until every mandatory artifact exists. Then set it to `Accepted` or `Accepted with required custom handler` only if §7 passes; otherwise set `Rejected` with the exact failed invariant.
4. Correct the ADR gate wording so corrective Plans 02-02b are allowed while product Plan 03 remains blocked.

## 4. Implementation Order

1. Add failing unit tables for exact-open lifecycle, path state, reservation generations, connection churn, and probe framing/workers.
2. Replace `PathAttempt` and `ReservationContext`; refactor `ConnectionBook` to consume authoritative endpoints and injected-time expiry.
3. Make the exact-connection opener bounded and terminal on success, mismatch, close, timeout, cancellation, and shutdown; add its same-process coexistence test.
4. Implement the async probe codec, payload modes, half-close, slow-reader behavior, and bounded inbound workers.
5. Apply all transport/relay limits and listener validation, then implement the exchange and server lifecycles.
6. Implement the finite client attempt/open/probe lifecycle and typed terminal output.
7. Implement `local.sh`, pass same-host and exact-coexistence cases, then implement and run the Linux namespace matrix.
8. Run C14, dependency policy checks, and all resource cases; fix and rerun every affected case.
9. Generate scrubbed evidence and update ADR 0001. Create Plan 03 only after the accepted gate is committed.

## 5. Verification

Run from the repository root with the committed Rust 1.96.0 toolchain and lockfile:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo deny check
```

Then run every command/case from Plan 02 §5.2, including C01/C05-C13 local cases over both exchange transports where applicable, C02-C13 under Linux namespaces, and C14 on two real networks. Preserve raw failing artifacts during development; only scrubbed summaries are committed.

The worktree must remain clean after verification except ignored `target/p2x-spike/` artifacts. Changing the libp2p/Rust baseline or exact-open protocol requires a full C01-C14 rerun and updated evidence.

## 6. Definition of Done

- All 02B-01 through 02B-09 findings are closed by implementation, automated tests, and observed artifacts.
- Exact direct/relay `ConnectionId` selection is independently observed by the receiver while both connections coexist; no result is manufactured by opening only by `PeerId` or closing the other path.
- Every attempt has one immutable setup deadline, one path commitment, at most one pre-payload fallback, one terminal result, and exactly-once resource cleanup.
- Reservation readiness and recovery are generation-scoped; healthy renewal does not flap readiness and stale events cannot alter a newer generation.
- Payload framing, workers, queues, stream opens, records, tombstones, permits, RSS, and file descriptors remain bounded under C09-C13.
- All static/dependency checks and C01-C14 pass with schema-valid, scrubbed evidence.
- ADR 0001 is accepted from observed results. Until then, Plan 03 and all production identity/authentication/registry/ticket/ingress/proxy work remain blocked.

## 7. Architecture Gate Outcome

Plan 02b is complete only when §6 is satisfied and ADR 0001 is no longer `Deferred`.

If exact targeting, bounded fallback, supported-platform behavior, or resource cleanup still fails after the scoped custom handler work, record the reproducible failure and reject the foundation. Evaluate a libp2p version change only as a separate, narrowly justified correction followed by the full matrix; do not proceed to Plan 03 on intended behavior or unit-test-only evidence.
