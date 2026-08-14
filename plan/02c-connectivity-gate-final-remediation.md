# Fix Plan: Finish the Connectivity Gate from Executable Evidence

- **Document status:** implementation-ready corrective follow-up to Plans 02, 02a, and 02b
- **Date:** 2026-08-14
- **Reviewed baseline:** commit `f748d050414737f45ce35595e4f9552f0eeb0364`
- **Parent documents:** [`00-product-analysis.md`](00-product-analysis.md), [`01-connectivity-spike-and-libp2p-design.md`](01-connectivity-spike-and-libp2p-design.md), and Plans [`02`](02-connectivity-gate-remediation.md), [`02a`](02a-connectivity-gate-completion.md), and [`02b`](02b-connectivity-gate-closure.md)
- **Decision:** do not create Plan 03 yet. ADR 0001 is still `Deferred`, C01-C14 have not passed, and the current binaries cannot execute the required connectivity lifecycle.

## 1. Goal and Scope

Close the remaining gap between the implemented pure-state/libp2p scaffolding and the evidence-backed connectivity gate. Preserve the Rust 1.96.0, `libp2p = 0.56.0`, three-binary, and `/p2x/spike/1` baselines. Correct the confirmed state and resource-lifecycle defects, finish the three lab processes and bounded probe protocol, execute C01-C14, and update the evidence and ADR only from validated artifacts.

Production identity persistence, enrollment, authorization, registry, tickets, ingress routing, upstream dialing, and `/p2x/proxy/1` remain out of scope and blocked until this plan accepts the connectivity foundation.

## 2. Review Result

### 2.1 Verification performed

The following were run from the repository root at the reviewed commit:

```text
cargo fmt --all -- --check                                      passed
cargo clippy --workspace --all-targets --all-features -- -D warnings
                                                                  passed
cargo test --workspace --all-targets                             passed: 17 tests
cargo deny check                                                 failed: cargo-deny is not installed
./tests/connectivity/local.sh --case C01                         failed: unsupported, exit 2
```

There are no application or integration tests. All 17 tests are small unit tests in `p2x-net`; none starts an exchange/server/client lifecycle, creates a relay reservation, performs DCUtR, opens a probe on an exact live `ConnectionId`, transfers payload, or validates cleanup.

### 2.2 Confirmed findings

| ID | Severity | Confirmed finding | Required outcome |
| --- | --- | --- | --- |
| 02C-01 | Blocker | The three `main.rs` files only listen or dial once and print hand-built JSON. The server has no exchange address/identity, reservation, circuit listener, or probe workers. The client can dial only the exchange, never the server circuit address, never drives `ConnectionBook`/`PathAttempt`, and never emits a finite terminal result. | Implement the complete exchange, server, and client lab lifecycles in §3.5. |
| 02C-02 | Blocker | `local.sh` and `netns.sh` are fixed unsupported writers. The committed evidence explicitly says C01-C14 did not run, and C14's commands do not match a functional server/client CLI. | Replace the stubs, execute the full matrix, and decide the ADR from artifacts as specified in §§3.6-3.7. |
| 02C-03 | P0 | `probe.rs` provides synchronous header helpers only. It accepts unknown JSON fields, has no request ID or mode parameters in `ProbeHeader`, uses a free-form path string in `ProbeAck`, has no async payload/half-close/slow-reader implementation or worker admission, and caps transfers at 16 MiB even though C11 requires 256 MiB. | Implement the bounded async protocol and workers in §3.4. |
| 02C-04 | P0 | `ProbeStreamBehaviour` removes a pending request before its terminal event is delivered, leaves stale commands behind on timeout/close, and puts outbound and inbound events in an unbounded queue. The handler can silently drop negotiated streams or failures when its event queue is full, and its queue-full failure path can itself grow without a bound. No test exercises this behaviour or handler. | Implement a bounded, exactly-once open lifecycle whose permit is retained through terminal delivery, with race tests, as specified in §3.3. |
| 02C-05 | P0 | `PathAttempt` has no start transition that emits `DialRelay`; `RelayDialing`, `CancelOpen`, and `CloseStream` are never produced. Exact-open results carry no request/connection identity, relay fallback reuses the failed request ID, `ExactOpenSucceeded` enters `Streaming` before payload acceptance, repeated terminal events emit repeated `Finish` actions, and `RelayLost` incorrectly fails a direct stream while doing nothing to a relay path that is still waiting. | Replace the transition contract and add complete table tests in §3.2. |
| 02C-06 | P0 | `ReservationContext` accepts most events without exchange connection/listener/address identity. Starting the same generation resets readiness, a new generation retains old acceptance timestamps and renewal count, loss does not invalidate its corresponding readiness fact, duplicate losses repeatedly advance retry, address confirmation alone clears degradation/retry, recovery ordering is not commutative, and no jittered generation-scoped retry action exists. | Make reservation truth generation- and identity-scoped as specified in §3.2. |
| 02C-07 | P0 | `RelayProfile::DefaultLab` uses upstream defaults (128 KiB circuit byte cap, two-minute circuit duration, and only 16 circuits), while `LimitTest` changes only `max_circuits`. A 256 MiB relay C11 run therefore cannot pass. The required relay-client Yamux and QUIC limits, inbound negotiation limit, DNS transport, Identify push-update, and configured QUIC listeners are not applied. | Apply and test the complete network and relay profiles in §3.1. |
| 02C-08 | P1 | `ConnectionBook` does not know or validate the configured exchange peer. A relayed endpoint without an exchange identity is classified as `UnknownDirect`; tied expiry eviction is nondeterministic, and evicting a live close tombstone permits a late DCUtR/establish sequence to make a closed ID selectable. The existing cap test exercises only pending successes, reuses IDs, and never covers high-churn closes. | Use a fail-closed bounded lifecycle ledger, exact relay validation, periodic sweeping, and the tests in §3.2. |
| 02C-09 | P1 | `SwarmConfig` mixes exchange and peer concerns. Its listener fields are validated but not consumed by the builders; binaries can call `listen_on` with other values. `MAX_NEGOTIATIONS` and the protocol-surface assertion do not configure or inspect a live swarm. | Split validated configs, make builders apply them, and test effective settings in §3.1. |
| 02C-10 | P1 | Required Plan 02b tests are missing: exact-open queue/race/permit tables, complete path and reservation transition tables, async codec/worker tests, direct-plus-relay coexistence integration, and all process/harness tests. | Add tests before lifecycle wiring and require them in §4. |
| 02C-11 | P2 | Lifecycle output still uses formatted strings with no schema version, terminal cardinality, or artifact schema. `cargo-deny 0.20.2` is not provisioned, the evidence names old verification commits, and ADR 0001 still says corrective "Plans 02/03" are blocked rather than only Plan 03/product work. | Add typed output, reproducible dependency checking, generated evidence, and correct gate wording in §3.7. |

## 3. Required Remediation

### 3.1 Apply authoritative network configuration

Refactor [`builder.rs`](../crates/p2x-net/src/builder.rs) around separate `ExchangeSwarmConfig` and `PeerSwarmConfig` types. Constructors validate complete TCP and QUIC listener multiaddresses, and `start_exchange_listeners` / `start_peer_listeners` (or equivalent builder methods) call `listen_on` using those same stored values. Do not validate one address and let a binary supply a different one later.

Apply these settings to the actual transports and behaviours:

- Tokio plus DNS, TCP `nodelay`/Noise/Yamux, explicit QUIC, and relay-client Noise/Yamux for peers.
- 256 Yamux streams on both ordinary TCP and relay-client connections; 256 QUIC bidirectional streams; 64 maximum negotiating inbound streams; five-second `/p2x/spike/1` negotiation/open timeout; 120-second idle timeout.
- Ping interval/timeout of 15/5 seconds and Identify `with_push_listen_addr_updates(true)`.
- Exchange TCP and QUIC listeners must both reject non-loopback addresses unless the exchange-only unsafe lab acknowledgement is set. Peer listeners remain explicit lab configuration and must be included in structured readiness.

Build `relay::Config` without inheriting unsuitable upstream defaults:

| Field | `DefaultLab` | `LimitTest` |
| --- | ---: | ---: |
| Global reservations | 64 | 2 |
| Reservations per peer | 2 | 1 |
| Reservation duration | 60 seconds | 60 seconds |
| Global circuits | 128 | 2 |
| Circuits per source peer | 4 | 1 |
| Maximum circuit duration | 60 minutes | 5 minutes |
| Maximum circuit bytes | 1 GiB | 16 MiB |

Use explicit lab rate limiters that permit C12 renewal and C13's 100 sequential circuits under `DefaultLab`; the low profile must fail at the table boundaries rather than through an unrelated byte or duration cap. Unit-test every effective field, both listener safety paths, both listener startup paths, and the actual Cargo/behaviour protocol surface. Remove `supported_protocols()` if it remains only a constant assertion.

### 3.2 Correct connection, reservation, and path truth

#### Connection inventory

Change `ConnectionBook::new` to require the expected exchange `PeerId`. Make `on_connection_established` return a typed result and reject a relayed `ConnectedPoint` unless the address has the expected exchange identity before `/p2p-circuit`. Store the endpoint role/address and select only open, non-closing, DCUtR-confirmed direct records; keep QUIC-before-TCP and oldest-sequence ordering.

Replace independent evicting maps with one `MAX_CONNECTION_LIFECYCLES = 512` ledger covering `PendingDcutr`, `Active(ConnectionRecord)`, and `Retired { expires_at }`. A close changes an existing active slot to retired rather than allocating a new slot. On capacity exhaustion, reject an untracked establish/DCUtR event and have the owner close the connection; never evict an unexpired retired entry merely to admit an event that could resurrect its ID. `sweep(now)` is the only time-based removal path and is driven on a peer-loop interval even without network events.

Tests must cover both DCUtR/establish orders, invalid/wrong relay peer, relayed address without exchange identity, duplicate establishment, close-before-late-success, capacity exhaustion, deterministic expiry, more than 128 connect-close iterations with periodic sweep, and proof that no retired ID becomes selectable.

#### Reservation lifecycle

Use `libp2p::swarm::ListenerId`, not `u64`, and include generation, expected exchange peer/connection, listener ID, and canonical circuit address in every applicable event. A strictly newer `GenerationStarted` clears acceptance, address confirmation, listener, canonical address, last acceptance, renewal count, retry attempt, and retry deadline. Replaying the exact same start is idempotent; reusing a generation with different identities is a typed error/no-op.

Loss invalidates its corresponding facts: exchange loss invalidates all reservation/address truth, listener close invalidates acceptance and that listener's address, and address expiry invalidates only the matching address. A matching renewal updates `last_acceptance` and increments `renewal_count` without flapping a ready generation. Acceptance and address confirmation commute during both initial setup and recovery. Reset retry state only when both current-generation facts are valid again.

Return explicit actions for dial, create circuit listener, retry, and readiness/degradation publication. Retry events carry generation and attempt. Schedule the first matching loss at 250 ms, double to 10 seconds, and apply deterministic injected jitter within +/-20%; duplicate/stale loss or timer events must not reschedule a newer attempt.

#### Path attempt

Keep one `apply(PathEvent) -> Vec<PathAction>` entry point; remove `open_committed` as a second transition API. Add an explicit begin event that either commits a currently healthy pooled direct connection or enters `RelayDialing` and returns `DialRelay`. Preserve the immutable 20-second setup deadline and start the 1.5-second direct window only after relay readiness.

Correlate every exact-open event with `RequestId` and selected `ConnectionId`. The owner executes `OpenExact`, calls `ProbeStreamBehaviour::open_on`, then feeds the returned request ID into `ExactOpenQueued`. Ignore any open result whose attempt/request/connection tuple does not match the current state. A direct-open failure may request one new relay open with a new request ID; late completion of the failed direct request cannot complete the relay open.

Represent an opened-but-no-payload stream separately from `Streaming` (a `StreamReady` state or an equivalent data-bearing flag). Only `PayloadAccepted` enters `Streaming`. Cancellation/setup expiry while an open is queued returns `CancelOpen`; cancellation before payload on an opened stream returns `CloseStream`; connection loss after payload returns one terminal failure and never replays bytes. Relay loss affects a relay-selected/waiting attempt but does not terminate a direct-selected stream. Once `Failed`, every event is a no-op so `Finish` and resource release occur exactly once.

Table-test begin with/without pooled direct, relay readiness, direct before/at/after deadline, silent/explicit DCUtR failure, early timer, setup expiry in every pre-streaming state, open correlation, one fallback with a new request ID, late old result, payload commitment, selected versus unselected close, direct stream during relay loss, cancellation cleanup, stale attempt ID, and repeated terminal events.

### 3.3 Make exact-connection opening bounded and exactly once

Refactor [`probe_stream/behaviour.rs`](../crates/p2x-net/src/probe_stream/behaviour.rs) and [`handler.rs`](../crates/p2x-net/src/probe_stream/handler.rs) around a `PendingOpen` that owns the full `OpenProbe`, created/deadline times, phase, and permit until its terminal output is polled by the swarm owner.

- Admit at most 128 opens globally and 64 per peer. Count queued commands, handler/in-flight work, and terminal outputs against the same permit; decrement only after `OutboundOpened`/`OutboundFailed` delivery or explicit shutdown discard.
- Use separate bounded outbound-terminal and inbound-open queues so inbound traffic cannot consume outbound completion capacity. Outbound capacity equals the admitted pending-open cap; inbound capacity equals the worker admission cap. Prioritize outbound terminal delivery.
- On close, timeout, or cancel, remove every matching not-yet-notified command and enqueue one failure. A later handler event for that request is ignored and any returned stream is dropped/reset.
- Add known connections only from `FromSwarm::ConnectionEstablished`; remove them on exact close. Drive `expire(now)` from the owner timer.
- Keep handler command and outbound-completion queues at 64. Separate inbound delivery from outbound completion, never silently discard an outbound success/failure, and classify/reset an excess inbound stream as `limit.inbound_queue_full` before application reads.
- Expose injected time/test constructors and counters for known connections, commands, pending opens, terminal events, and inbound events.

Add unit tests for unknown connection, request-ID exhaustion, global/per-peer limits, command/event/handler capacity, mismatch, cancel before/after notify, close before notify/during negotiation/after success, timeout, success-versus-late-failure ordering, inbound starvation resistance, shutdown drain, and exactly-once permit release. Add an integration test under `crates/p2x-net/tests/` that holds direct and relayed connections to one peer concurrently and proves receiver-observed exact opens on both IDs without closing the losing path.

### 3.4 Implement the bounded async probe protocol and workers

Extend [`probe.rs`](../crates/p2x-net/src/probe.rs) and add a focused worker module such as `probe_worker.rs`. Add only the Tokio/futures I/O and synchronization features needed by this implementation.

- Add `#[serde(deny_unknown_fields)]` to bounded wire structs. `ProbeHeader` contains schema version, request ID, nonce, closed `ProbeMode`, transfer length, and bounded slow-reader delay/chunk parameters. Support zero through 256 MiB so C11 is representable; reject mode-specific invalid combinations before payload reads.
- Make `ProbeAck.path` a closed observed-path value, not `String`, and include schema version, request/nonce, receiver-local connection-ID hash, directional byte counts/hashes, half-close result, and a stable terminal code.
- Implement async four-byte length-prefixed read/write helpers. Reject a declaration over 4096 bytes before allocation; classify oversized, malformed/unknown/trailing, truncated, timeout, and I/O failures distinctly.
- Generate, stream, and hash deterministic payload in reusable 32 KiB buffers. Yield through async I/O; never build a payload-sized `Vec` or run `pattern_hash(256 MiB)` on the swarm task.
- Implement `nonce_echo`, bidirectional `half_close` with write-half shutdown and EOF verification, and delayed-chunk `slow_reader` without holding the swarm loop.
- Admit inbound workers before reading the header with 128 global and 64 per-peer permits. Send results over a bounded channel and release permits once on rejection, success, error, timeout, cancellation, and shutdown.

Test exact/truncated/oversized frames, unknown and trailing fields, every mode boundary, all terminal codes, short reads/writes, zero and 256 MiB streaming with fixed buffer accounting, both half-closes, concurrent slow reader plus nonce responsiveness, global/per-peer rejection, cancellation, shutdown, and worker-result backpressure.

### 3.5 Complete the three process lifecycles and typed artifacts

Add shared versioned `Serialize` structs in a small `p2x-net` lifecycle/artifact module. Write NDJSON with `serde_json::to_writer`/`to_string` to stdout and an optional per-process artifact path. Every event includes schema version, component, run ID, monotonic offset, and event kind. Finite clients emit exactly one `TerminalResult`; graceful shutdown emits final resource counters after admissions close and workers drain/cancel.

Keep exactly the existing three binary packages:

1. `p2x-exchange` starts validated TCP and QUIC listeners, applies the selected relay profile, reports both usable addresses and relay events, and drains on cancellation.
2. `p2x-server` validates one complete exchange multiaddress and expected exchange peer, starts TCP/QUIC peer listeners, dials exactly one exchange control connection, creates `<exchange-address>/p2p-circuit`, drives `ReservationContext` across renewal/loss/retry generations, publishes readiness only with the canonical circuit address, and dispatches inbound streams to bounded probe workers.
3. `p2x-client` validates exchange/server identities and the complete server circuit address, starts local peer listeners, establishes relay first, drives DCUtR plus `ConnectionBook` and `PathAttempt`, opens the chosen exact connection, executes requested probe count/size/concurrency, and exits finite mode with one result on every success or failure path.

One task owns and polls each swarm. Workers use bounded command/result channels and never own the swarm. Map connection close into the connection book, exact opener, reservation state, and current attempt in the same owner turn before processing later events. Add periodic expiry/retry/resource sampling timers and graceful cancellation that leaves zero pending opens and worker permits.

### 3.6 Replace the harness and execute the stable matrix

Replace both stub scripts while preserving Plan 01 §8.2 and Plan 02 §5.2 case meanings. A small `tests/connectivity/common.sh` may hold run-ID validation, collision-safe port allocation, process ownership, NDJSON validation, resource sampling, and scoped cleanup shared by both entry points.

- `local.sh` supports C01 and C05-C13, builds once, starts the three processes, waits for schema-valid readiness, runs exchange-TCP and exchange-QUIC variants where applicable, validates exactly one client terminal record and matching server-observed path, and kills only children belonging to its run.
- `netns.sh` supports C02-C13 on Linux after validating root/CAP_NET_ADMIN, `ip`, `iptables`/`nft`, `tc`, `jq`, and a strict run ID. Create exchange/server/client namespaces and run-scoped interfaces/rules for QUIC-only, TCP-only, all-direct-blocked, latency/loss, exchange interruption, selected-connection interruption, limits, concurrency, renewal, and churn. Teardown resolves and removes only run-derived names.
- C10 runs 64 then 128 mixed probes. C11 transfers exactly 268435456 bytes over direct and relay while a nonce probe remains responsive. C12 observes at least two renewals. C13 performs 100 connect-close iterations.
- Capture raw per-process logs plus one validated case summary under `target/p2x-spike/<run-id>/`. Missing/duplicate terminal output, path disagreement, setup over 20 seconds, hash/half-close mismatch, unsupported status, or non-zero final logical resources fails the case.
- Sample RSS, file descriptors, worker/task counts, connection-ledger entries, pending opens, queue depths, listeners, and permits for C09-C13. Record baseline/peak/final values and fail unexplained monotonic growth.
- Update `two-host.md` to the implemented CLIs and execute C14 on two native hosts on separate networks. Relay success is mandatory; direct success is recorded but not required.

### 3.7 Produce evidence and close the decision

1. Provision exactly `cargo-deny 0.20.2` in the verification environment and record a reproducible install/version/check command compatible with Rust 1.96.0.
2. Run static/dependency checks, unit/integration tests, native macOS local coverage, the privileged Linux namespace matrix, and C14. A platform being unavailable is an incomplete gate, not a skip/pass.
3. Generate [`evidence/01-connectivity-spike-results.md`](evidence/01-connectivity-spike-results.md) from scrubbed validated summaries. Record git revision/dirty state, exact component versions, commands, environment/topology, client and server path observations, timings, payload/hash/half-close results, resource baseline/peak/final values, rerun count, and all failures.
4. Correct ADR 0001's gate wording to allow the corrective 02-series work. Set it to `Accepted` or `Accepted with required custom handler` only if every mandatory invariant passes; otherwise set it to `Rejected` with the reproducible failed invariant.
5. Create Plan 03 for identity, authentication, and connection tickets only after the accepted ADR and complete evidence are committed.

## 4. Implementation Order

1. Add the missing failing pure-state, exact-open, codec, and worker unit tests; correct `ConnectionBook`, `ReservationContext`, and `PathAttempt`.
2. Apply the authoritative builder/relay configuration and add effective-configuration tests.
3. Complete the exact-connection handler/behaviour and direct-plus-relay coexistence integration test.
4. Implement the async probe codec, worker admission, payload modes, typed lifecycle records, and resource counters.
5. Wire exchange, then server reservation/recovery, then finite client path/probe execution; add same-host process integration coverage.
6. Implement `local.sh`, pass C01/C05-C13 over required exchange transports, then implement and run the Linux namespace C02-C13 variants.
7. Run C14 and all dependency/resource checks, fix failures, and rerun every case affected by networking, protocol, timing, or cleanup changes.
8. Generate the scrubbed evidence and update ADR 0001. Start Plan 03 only if the ADR is accepted.

## 5. Verification

Run from the repository root with the committed toolchain and lockfile:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo deny --version                         # exactly 0.20.2
cargo deny check
```

Run every stable C01-C14 case and the transport/path variants described in §3.6. Preserve raw failure artifacts during development; commit only scrubbed summaries. The worktree must be clean after verification except ignored `target/p2x-spike/` output.

Any change to Rust/libp2p versions, transport composition, relay limits, exact-open lifecycle, probe framing, or path timing invalidates prior connectivity artifacts and requires a complete affected matrix rerun. A Rust/libp2p version change requires the full C01-C14 rerun.

## 6. Definition of Done

- Findings 02C-01 through 02C-11 are closed by code, tests, and observed artifacts.
- Direct and relay connections coexist to the same peer, and receiver-observed results prove both exact `ConnectionId` opens without closing the other path.
- Every attempt has one setup deadline, immutable payload path, at most one pre-payload relay fallback with a distinct request ID, one terminal result, and exactly-once cleanup.
- Reservation readiness is generation/identity scoped, survives valid renewal, recovers in either event order, and ignores stale/duplicate loss and retry events.
- The 256 MiB direct and relay cases use fixed-size buffers; all queues, ledgers, workers, permits, relay resources, RSS, and file descriptors meet the C09-C13 bounds and return to baseline.
- Static checks, `cargo deny check`, C01-C14, native supported-platform coverage, and privileged namespace coverage pass with schema-valid evidence.
- ADR 0001 is no longer `Deferred`. Until it is accepted, Plan 03 and all product identity/authentication/registry/ticket/ingress/proxy work remain blocked.

## 7. Gate Outcome

The reviewed implementation does not satisfy Plans 02-02b. This 02c follow-up is complete only when §6 passes and ADR 0001 records an evidence-backed acceptance or rejection.

If exact targeting, bounded relay fallback, 256 MiB relay streaming, supported-platform behavior, or resource cleanup cannot pass on `libp2p 0.56.0`, preserve the failing artifacts and reject the foundation. A dependency upgrade is a separate corrective decision followed by the full gate; it is not permission to proceed to Plan 03 on unit-test-only evidence.
