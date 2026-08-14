# Plan: Connectivity Gate Remediation and Closure

- **Document status:** implementation-ready corrective Phase 0 plan
- **Date:** 2026-08-14
- **Reviewed baseline:** commit `9c8f128` on `feat/connectivity-spike-and-rust-libp2p-design`
- **Parent documents:** [`00-product-analysis.md`](00-product-analysis.md) and [`01-connectivity-spike-and-libp2p-design.md`](01-connectivity-spike-and-libp2p-design.md)
- **Dependency baseline:** Rust 1.96.0, `libp2p = 0.56.0`, and the committed `Cargo.lock`
- **Gate:** identity, authentication, registry, ticket, ingress, and production proxy work remains blocked until §7 passes and ADR 0001 is accepted

`plan/00-product-analysis.md` expected Plan 02 to cover identity, authentication, and tickets. The reviewed source does not satisfy the mandatory Phase 0 connectivity gate, and the committed evidence and ADR both explicitly mark that gate incomplete. This corrective plan therefore occupies number 02. Create the identity/authentication/ticket plan under the next available number only after this plan completes; do not implement both scopes together.

## 1. Goal and Scope

Complete the live rust-libp2p connectivity spike promised by Plan 01, correct the state-machine defects found during review, run the mandatory connectivity matrix, and make an evidence-based accept/reject decision for the networking foundation.

### 1.1 In scope

- Replace the current constants-only `builder.rs` with working exchange and peer swarm builders using the exact Plan 01 protocol set.
- Implement `/p2x/spike/1` as a bounded custom `NetworkBehaviour`/`ConnectionHandler` that opens a substream on one specified `ConnectionId`.
- Correct connection, reservation, and path-attempt state so duplicate, reordered, late, stale-generation, timeout, cancellation, and close events cannot produce a false path or readiness decision.
- Turn the three lifecycle binaries into the lab exchange, server, and client while keeping them as the only executable packages.
- Implement bounded nonce, half-close, and slow-reader probes without buffering a whole payload.
- Replace the placeholder local and Linux-namespace scripts with repeatable C01–C13 orchestration, complete the two-host C14 runbook, and run C14 on two real networks.
- Update the existing Plan 01 evidence document and ADR only from captured results.

### 1.2 Out of scope

- Persistent production identities, exchange identity pinning, fixed-token enrollment, tenant/role authorization, ticket signing, registry protocols, and relay admission by authenticated identity.
- `/p2x/proxy/1`, private-upstream dialing, fixed TCP ingress, HTTP Host routing, TLS SNI parsing, and production health/metrics endpoints.
- Active-stream migration, AutoNAT, rendezvous, UPnP, custom STUN/TURN, or a libp2p version change made only to avoid implementing the required exact-connection handler.
- Treating a passing same-host test as a substitute for Linux namespace and two-host evidence.

## 2. Review Findings

The current workspace compiles and the five existing unit tests pass, but those checks exercise only constants and small pure structures. No live libp2p swarm is constructed and no Plan 01 connectivity case has run.

| ID | Severity | Confirmed finding | Impact and required correction |
| --- | --- | --- | --- |
| R01 | Blocker | [`builder.rs`](../crates/p2x-net/src/builder.rs) defines constants only, while all three `main.rs` files generate an identity, print one line, and wait for Ctrl-C. | There is no TCP/QUIC transport, relay, Identify, Ping, DCUtR, reservation, dial, or swarm event loop. Implement the actual exchange and peer swarms before claiming Plan 01 complete. |
| R02 | Blocker | The planned `probe_stream/behaviour.rs`, `handler.rs`, and `upgrade.rs` do not exist. | Exact `ConnectionId` selection—the architecture gate—has not been implemented or tested. Add the custom behaviour and handler; opening by `PeerId` is not an acceptable substitute. |
| R03 | High | `PathAttempt::direct_ready` and `fallback` in [`path_selector.rs`](../crates/p2x-net/src/path_selector.rs) overwrite state without checking the current phase, direct deadline, setup deadline, or an earlier commitment. | A late direct event can change a relay-committed attempt, and repeated fallback can recommit it. Make commitment terminal for the current stream and reject stale or invalid transitions. |
| R04 | High | `ConnectionBook::mark_dcutr` in [`connection_book.rs`](../crates/p2x-net/src/connection_book.rs) drops DCUtR success received before `ConnectionEstablished`; `direct()` selects direct records even when `dcutr_confirmed` is false. | Event reordering can lose a valid direct path, while an unconfirmed path can be selected. Reconcile by `(PeerId, ConnectionId)`, bound pending successes, and expose only confirmed, open direct records to path selection. |
| R05 | High | `reservation::transition` in [`reservation.rs`](../crates/p2x-net/src/reservation.rs) ignores `renewal`, moves `Ready` back to `ReservationAccepted` on renewal, moves `Ready` back to `RelayAddressConfirmed` on a repeated address event, and carries no listener/generation identity. | Readiness can flap on healthy renewal and stale loss events can degrade a newer reservation. Track acceptance and address confirmation as idempotent facts scoped to one generation; only matching loss events may degrade it. |
| R06 | High | [`probe.rs`](../crates/p2x-net/src/probe.rs) only deserializes an already-buffered JSON slice. There is no bounded length-prefix reader, acknowledgement, worker/queue limit, exact-path observation, half-close implementation, slow reader, or fixed-buffer copy. | The current code proves neither framing safety nor backpressure/resource bounds. Implement the complete test protocol and enforce all Plan 01 limits before allocation and task creation. |
| R07 | High | [`local.sh`](../tests/connectivity/local.sh) prints that it is disabled and exits successfully; `netns.sh` is a fixed failure; the two-host document has no runnable procedure. | Automation can mistake the disabled local harness for success, and C01–C14 have no evidence. Disabled/unsupported cases must fail clearly; implemented cases must assert structured path evidence and preserve failure artifacts. |
| R08 | Medium | `--identity-seed` is accepted but ignored by every binary. `--unsafe-lab-public-relay` is also exposed by client and server even though only exchange relay binding needs it. | Runs are not deterministic as the CLI implies, and the safety boundary is unclear. Make the seed deterministic and visibly lab-only, remove the relay flag from peers, and enforce loopback binding unless exchange receives the unsafe flag. |
| R09 | Medium | The protocol-surface test checks a one-element constant array, not the protocols exposed by constructed behaviours. | It cannot detect an accidental behaviour/feature such as rendezvous. Test the real behaviour protocol set and the exact Cargo feature contract. |
| R10 | Medium | [`01-connectivity-spike-results.md`](evidence/01-connectivity-spike-results.md) and ADR 0001 correctly say the gate is incomplete, but the evidence does not enumerate resolved libp2p component versions or contain any raw-run summary. `cargo deny check` also cannot run in the current environment because the subcommand is not installed. | Preserve the honest incomplete status until all evidence exists. Provision a pinned compatible `cargo-deny` in the verification environment and record exact resolved versions and case results rather than a generic lockfile reference. |

## 3. Required Design and Invariants

### 3.1 Swarm construction and ownership

Implement the following in [`crates/p2x-net/src/builder.rs`](../crates/p2x-net/src/builder.rs):

- `ExchangeBehaviour { relay, identify, ping }`, `PeerBehaviour { relay_client, dcutr, identify, ping, probe_stream }`, and small derived `ExchangeEvent`/`PeerEvent` enums.
- `build_exchange_swarm(keypair, config) -> Result<Swarm<ExchangeBehaviour>, BuildError>` and `build_peer_swarm(keypair, config) -> Result<Swarm<PeerBehaviour>, BuildError>` using the builder order and feature set fixed by Plan 01 §4.
- Validated config structs for listener addresses and the explicit Plan 01 values: 256 Yamux/QUIC streams, 64 inbound negotiations, 5-second probe negotiation, 120-second idle timeout, Ping 15/5 seconds, 1.5-second direct preference, and one 20-second absolute setup deadline.
- Exchange `default-lab` and `limit-test` relay profiles. Non-loopback listeners are rejected unless the exchange process received `--unsafe-lab-public-relay`.

Each binary owns and polls exactly one `Swarm` from one task. Worker results and CLI commands return through bounded channels; workers never poll or mutate the swarm directly. Start TCP and QUIC listeners before exchange dialing. Derive path truth only from swarm, relay-client, and DCUtR events.

### 3.2 Exact-connection probe opener

Add:

```text
crates/p2x-net/src/probe_stream/
  mod.rs
  behaviour.rs
  handler.rs
  upgrade.rs
```

Implement these contracts:

- `RequestId` is a monotonic local newtype. `OpenProbe` contains `request_id`, `peer_id`, and `connection_id`.
- `ProbeStreamBehaviour::open_on` first verifies that the exact `(PeerId, ConnectionId)` is still known, enforces 128 global and 64-per-peer pending-open limits, then emits `ToSwarm::NotifyHandler { handler: NotifyHandler::One(connection_id), ... }`.
- The handler emits `OutboundSubstreamRequest` with the `RequestId` as `OutboundOpenInfo`; it negotiates only `/p2x/spike/1` with a 5-second timeout. Multiple opens may complete out of order.
- Behaviour events carry the original request, peer, and connection IDs for `OutboundOpened`, `OutboundFailed`, and `InboundOpened`. A mismatched event is a terminal internal/protocol error.
- Keep behaviour/handler queues explicitly bounded. A full queue fails immediately as `limit.command_queue_full`; never wait while holding a permit.
- Track an explicit deadline for every pending open. `ConnectionClosed`, timeout, cancellation, negotiation failure, and successful delivery each remove the pending entry and release all permits exactly once. Handle the documented `NotifyHandler::One` close race without hanging.
- Do not close the relay merely because direct becomes available. C05 requires both connections to coexist and independently carry an observed probe.

### 3.3 Connection inventory correction

Refactor [`connection_book.rs`](../crates/p2x-net/src/connection_book.rs) around event-specific methods rather than unrestricted `insert`/`mark_dcutr` mutation:

- Store `(PeerId, ConnectionId)`, monotonic sequence, `PathKind`, endpoint role, establishment time, DCUtR confirmation, last successful Ping time, and closing state.
- Classify relay versus direct from `ConnectedPoint::is_relayed()`. For direct addresses, classify QUIC before TCP from the actual endpoint multiaddress; for relay records, extract and validate the exchange `PeerId` from the circuit address.
- `on_dcutr_succeeded(peer_id, connection_id, now)` marks an existing direct record or stores a bounded pending success until its matching `ConnectionEstablished` arrives. Pending entries use the same setup lifetime, are capped at 128, and are removed on matching close, attempt cancellation, or expiry.
- `on_connection_established` consumes a pending DCUtR success regardless of event order. A duplicate event is idempotent and must not reset confirmation or sequence.
- `on_connection_closed` removes only the exact peer/connection record and any related pending open/success. A late DCUtR event for a tombstoned or expired connection is ignored.
- `select_direct(peer_id)` returns only open, DCUtR-confirmed records, preferring QUIC over TCP and then the oldest sequence. Exchange control loss does not remove unrelated direct records.

Unit tests must cover both DCUtR/established orderings, duplicate establish, stale success after close, incorrect peer, unconfirmed exclusion, QUIC preference, and deterministic oldest selection.

### 3.4 Path-attempt correction

Replace the mutable phase-plus-optional-fields model in [`path_selector.rs`](../crates/p2x-net/src/path_selector.rs) with a transition API whose state variants contain their required data. At minimum distinguish:

```text
Absent
RelayDialing
DirectWaiting { relay_id, direct_deadline }
Committed(PathDecision)
StreamOpening { decision, request_id, relay_fallback_used }
Streaming(PathDecision)
Failed(PathFailure)
```

Every event carries the owning monotonic `AttemptId`; events for another or terminal attempt are ignored. Every transition accepts injected monotonic `now` and returns domain actions instead of sleeping or opening sockets.

Required behavior:

1. Create one `setup_deadline = started_at + 20 seconds` and never extend it.
2. Commit a healthy pooled direct connection immediately; otherwise make relay ready before starting the 1.5-second direct-preference timer.
3. Commit direct only when a matching confirmed direct record arrives before the direct and setup deadlines.
4. Commit relay on explicit DCUtR failure or direct deadline if the relay is still open.
5. Once committed, a late direct success is retained in `ConnectionBook` for a future attempt but cannot alter the current decision.
6. If exact-connection negotiation fails before any probe payload is accepted, permit one fallback from direct to the still-open relay inside the original setup deadline. Never replay after payload commitment.
7. Setup expiry, cancellation, selected-connection close, or relay loss without an eligible fallback becomes one terminal failure and releases all resources exactly once.

Add table-driven tests for every rule above, repeated terminal events, boundary timestamps, stale `AttemptId`s, and both selected-connection close races.

### 3.5 Reservation correction

Replace the value-only transition in [`reservation.rs`](../crates/p2x-net/src/reservation.rs) with a context that owns:

- current generation, exchange `PeerId` and connection ID, relay listener ID, canonical circuit address, acceptance/address-confirmed flags, last acceptance time, renewal count, and retry attempt;
- events carrying the generation and relevant connection/listener/address identity;
- a derived `phase()` and `is_ready()` rather than using one enum value as all state.

Acceptance and address confirmation commute, repeat idempotently, and make the same generation ready only when both are present. `renewal: true` increments the renewal count and keeps an already ready generation ready. Only a matching exchange connection loss, expired address, or listener close degrades the generation. Retry timers carry the generation so a stale timer cannot replace a newer healthy listener. Retry delay begins at 250 ms, doubles to 10 seconds, applies 20% injected jitter, and resets only after confirmed readiness.

### 3.6 Bounded probe protocol

Extend [`probe.rs`](../crates/p2x-net/src/probe.rs) with a spike-only codec and streaming helpers:

- Use a 4-byte big-endian length prefix followed by at most 4096 bytes of JSON. Reject an oversized declared length before allocating or reading its body.
- Replace free-form `mode: String` with a closed `ProbeMode` enum for `nonce_echo`, `half_close`, and `slow_reader`. Validate mode-specific lengths and delays against test-profile caps.
- Define a bounded acknowledgement containing request/nonce, server-observed `PathKind`, server-local connection identifier/hash, byte counts, streaming hashes, half-close result, and a stable terminal code. The client compares requested and independently observed path classes; local connection IDs on opposite peers are recorded separately, not compared for equality.
- Use fixed 32 KiB copy buffers and incremental deterministic pattern generation/hash verification. A 256 MiB test must not allocate a 256 MiB buffer.
- Limit inbound workers to 128 globally and 64 per remote peer. Reject excess streams before reading a payload and keep control/swarm polling responsive during a slow reader.

### 3.7 Lab binaries and orchestration

Implement component-specific CLIs and event loops:

- `p2x-exchange`: identity seed, TCP/QUIC listen addresses, relay profile, unsafe public-lab acknowledgement, structured result path, and graceful cancellation.
- `p2x-server`: identity seed, complete exchange address/peer ID, local TCP/QUIC listen addresses, circuit-listener lifecycle, probe worker limits, and structured readiness containing the canonical circuit address.
- `p2x-client`: identity seed, exchange/server peer IDs and circuit address, requested/forced path, probe mode/size/count/concurrency, deadline, and structured result path.

`--identity-seed` must deterministically derive a lab-only Ed25519 identity and never be the production persistence API. Do not write seeds or private key material into logs or committed evidence. Serialize result lines with `serde_json`; do not build JSON manually.

Replace the fixtures as follows:

- `local.sh` builds once, allocates collision-safe loopback ports, starts all processes in one process group, waits for structured readiness, runs requested cases, and reliably cleans only its own run. A disabled or unsupported case exits non-zero.
- `netns.sh` validates Linux, privileges, tools, and its run ID before mutation; creates namespaced exchange/client/server networks and explicit firewall/traffic-control rules; supports the C02–C13 forced-path and fault cases; and tears down only names bearing its validated run ID.
- Both scripts write raw logs and one JSON summary per case below `target/p2x-spike/<run-id>/`, print artifact paths on failure, and assert both client-selected and server-observed paths.
- `two-host.md` gives exact exchange/server/client commands, required TCP/UDP firewall rules, environment capture, JSON assertions, redaction, and teardown for C14 on native hosts on separate networks.

## 4. Implementation Order

### 4.1 Lock the defects with tests

1. Add failing table tests for R03–R05 before refactoring their state.
2. Add codec tests for oversized declared lengths, truncated frames, invalid modes, and bounded acknowledgements.
3. Add compile-time/unit assertions for the actual swarm behaviour protocol surface and configured limits.

### 4.2 Correct pure state and protocol code

1. Refactor `ConnectionBook`, `PathAttempt`, and reservation context to the contracts in §§3.3–3.5.
2. Implement the bounded probe codec and streaming pattern/hash helpers.
3. Keep these modules independent of timers and sockets; inject time, generation, randomness/jitter, and events in tests.

### 4.3 Implement the networking core

1. Add the exact-connection `probe_stream` upgrade, handler, and behaviour.
2. Build exchange and peer swarms with the fixed behaviours and settings.
3. Map libp2p events into the corrected domain state and fail pending exact-connection opens on close/timeout.
4. Add same-process integration tests that maintain direct and relayed connections simultaneously and target each connection explicitly.

### 4.4 Wire the three lab processes

1. Implement exchange relay event loop and both relay profiles.
2. Implement server listen/dial/reservation/renewal/recovery and bounded inbound probe workers.
3. Implement client relay-first dialing, DCUtR observation, path commitment, exact open, one pre-payload fallback, and probe result reporting.
4. Add cancellation supervisors and verify no child task remains after normal or interrupted shutdown.

### 4.5 Implement and run the lab

1. Implement `local.sh`, then pass same-host baseline, coexistence, renewal, interruption, concurrency, and slow-reader cases.
2. Implement `netns.sh` on Linux and pass every controlled TCP/QUIC/block/loss/latency/limit case.
3. Run C14 on two real machines on separate networks; record relay success and the observed direct result without requiring direct success in an unsupported NAT topology.
4. Fix code or harness defects and rerun every affected case. A libp2p dependency change requires rerunning all C01–C14 cases and updating every baseline reference.

### 4.6 Freeze evidence and decision

1. Update [`plan/evidence/01-connectivity-spike-results.md`](evidence/01-connectivity-spike-results.md) from scrubbed JSON summaries, including exact resolved component versions from `Cargo.lock`, commands, topology, path observations, durations, resource baselines/peaks, rerun counts, and failures.
2. Keep [`docs/adr/0001-rust-libp2p-connectivity.md`](../docs/adr/0001-rust-libp2p-connectivity.md) `Deferred` until all mandatory evidence exists.
3. After all acceptance criteria pass, set the ADR to `Accepted` or `Accepted with required custom handler`; otherwise record `Rejected` with the failing invariant and stop before product protocols.

## 5. Verification

### 5.1 Static and deterministic checks

Run from the repository root:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo deny check
```

The verification environment must provision and pin a `cargo-deny` release compatible with Rust 1.96.0; absence of the tool is not a passing/skipped security check. `Cargo.lock` remains committed and the worktree must be clean after tests except ignored `target/p2x-spike/` artifacts.

### 5.2 Mandatory connectivity cases

Implement script selectors with these stable case IDs and preserve the Plan 01 assertions:

| Command/case | Pass condition |
| --- | --- |
| `tests/connectivity/local.sh --case C01` | Relay becomes ready, DCUtR produces a direct connection, and exact-path nonce probe succeeds. |
| `netns.sh --case C02` / `C03` | Forced direct QUIC / direct TCP is independently observed by the server. |
| `netns.sh --case C04` | With peer-to-peer traffic blocked, TCP relay succeeds within the one 20-second setup budget. |
| `local.sh --case C05` | Direct and relay coexist; explicit opens on both IDs are observed on the requested path. |
| `local.sh --case C06` | Suppressed terminal DCUtR result commits relay at the 1.5-second policy deadline within documented scheduler tolerance. |
| `local.sh --case C07` / `C08` | Exchange loss preserves an active direct half-close transfer; selected P2P connection loss resets only that stream and a later request recovers. |
| `local.sh --case C09` | Low relay limits deny excess work with stable classification without starving existing work. |
| `local.sh --case C10 --streams 64` and `--streams 128` | No wrong-connection result, queue overflow is controlled, unrelated probes progress, and resources return to baseline. |
| `local.sh --case C11 --bytes 268435456 --path direct` and `--path relay` | Streaming hashes and half-close match; RSS does not scale with payload; nonce probes remain responsive. |
| `local.sh --case C12` | At least two reservation renewals occur and the circuit remains dialable throughout. |
| `local.sh --case C13 --iterations 100` | No leaked tasks, records, listeners, permits, or monotonically growing RSS/FD count. |
| C14 from `two-host.md` | Relay succeeds on separate real networks; direct outcome and environment are recorded honestly. |

Run relevant local cases once over exchange TCP and once over exchange QUIC. Linux namespace cases require Linux with `CAP_NET_ADMIN`; C14 requires two native hosts. Platform requirements do not permit omitting either class from the committed gate evidence.

### 5.3 Evidence integrity

Each case summary must include all Plan 01 §8.3 fields, client-selected and server-observed path, both peers' local connection ID hashes, monotonic timing, terminal code, and `passed`. The harness must fail when a field is missing, when only the client's preferred path is known, when setup exceeds 20 seconds, or when the component exits without a terminal result. Committed evidence must omit private keys, seeds, payloads, credentials, and full reusable lab identities.

## 6. Acceptance Criteria

- R01–R10 are closed by code, tests, or reproducible verification-environment setup.
- The workspace still produces exactly `p2x-exchange`, `p2x-client`, and `p2x-server` as binaries.
- Exact `ConnectionId` selection is proven while direct and relay coexist; neither closing relay nor opening by `PeerId` is used to manufacture success.
- Path commitment is immutable for a current stream, all work shares one 20-second setup deadline, and late/stale events cannot complete a newer or terminal attempt.
- Reservation readiness survives healthy renewal and ignores stale-generation loss/retry events.
- Queues, pending opens, workers, copy buffers, relay limits, concurrency, cancellation, and slow readers remain within configured bounds.
- C01–C14 and all static checks pass with scrubbed evidence; ADR 0001 records the observed outcome.
- No identity/authentication, registry, ticket, ingress, or production proxy implementation begins before ADR 0001 is accepted.

## 7. Architecture Gate Outcome

This plan is complete only when §6 passes and ADR 0001 is no longer `Deferred`.

If exact connection targeting cannot be made reliable with the public `libp2p` 0.56.0 APIs and the scoped custom behaviour/handler, stop and document the failing race or invariant. Evaluate a narrowly scoped libp2p upgrade only with a full C01–C14 rerun. Do not continue into identity/authentication design on an unproven path-selection foundation.
