# Fix Plan: Close the Connectivity Gate with Truthful Executable Evidence

- **Document status:** implementation-ready corrective follow-up to Plans 02, 02a, 02b, and 02c
- **Date:** 2026-08-15
- **Reviewed baseline:** commit `296992529a6ccce7e10b3f216f466fa40567c5ed` on `feat/02-connectivity-gate-remediation`
- **Parent documents:** [`00-product-analysis.md`](00-product-analysis.md), [`01-connectivity-spike-and-libp2p-design.md`](01-connectivity-spike-and-libp2p-design.md), and Plans [`02`](02-connectivity-gate-remediation.md), [`02a`](02a-connectivity-gate-completion.md), [`02b`](02b-connectivity-gate-closure.md), and [`02c`](02c-connectivity-gate-final-remediation.md)
- **Decision:** do not create Plan 03. The reviewed implementation can complete one same-host relayed nonce smoke, but it does not exercise the required DCUtR/path state, the canonical C01 entry point is still unsupported, dependency policy fails, C02-C14 are not proved, and ADR 0001 remains `Deferred`.

## 1. Goal and Scope

Finish the Phase 0 connectivity proof without treating generic relay traffic or case-name aliases as architecture evidence. Integrate the implemented state modules into the live processes, correct their remaining lifecycle defects, make the exact-open and probe paths bounded under real concurrency, execute the stable C01-C14 matrix, and make ADR 0001 an evidence-backed accept/reject decision.

This remains corrective Plan 02 work. Persistent production identities, enrollment/authentication, registry protocols, signed tickets, ingress, private-upstream dialing, and `/p2x/proxy/1` remain out of scope. Preserve Rust 1.96.0 and `libp2p = 0.56.0` unless resolving the dependency-security gate requires a narrowly justified change; any such baseline change requires the full C01-C14 rerun before the ADR decision.

## 2. Review Result

### 2.1 Verification performed

| Check | Result at the reviewed baseline |
| --- | --- |
| `cargo fmt --all -- --check` | Passed. |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Passed. |
| `cargo test --workspace --all-targets` | Passed 26 `p2x-net` unit tests. All three app crates have zero tests; there is no Rust integration test that starts live peers or holds direct and relay connections concurrently. |
| `cargo deny --version` | Passed with exactly `cargo-deny 0.20.2`. |
| `cargo deny check` | Failed. `Zlib` is not allowed, the four unpublished workspace packages are classified as unlicensed, `hickory-proto 0.25.2` is reported under RUSTSEC-2026-0118 and RUSTSEC-2026-0119, and `paste 1.0.15` is reported under RUSTSEC-2024-0436. |
| `./tests/connectivity/local.sh --case C01` | Exited 2 with `terminal_code: unsupported`; it starts no P2X process. |
| `./tests/local/run.sh C01` | Passed only the separately named `C01-smoke` after loopback sockets were permitted. The artifact shows a relayed zero-byte nonce probe; the server's attempted direct connection was refused because the client advertised no listen address. This is useful smoke coverage but does not meet C01's DCUtR/direct assertion. |
| Namespace and two-host gates | `tests/linux/C02-netns/run.sh` explicitly returns `not_implemented`; the Linux dispatcher wires only C02; the C14 scripts do not start a server or supply a server circuit address to the client. |
| Evidence and ADR | [`01-connectivity-spike-results.md`](evidence/01-connectivity-spike-results.md) still says C01-C14 are not passed and incorrectly says `cargo-deny` is absent. ADR 0001 remains `Deferred` and still says corrective “Plans 02/03” are blocked. |

### 2.2 Confirmed findings

| ID | Severity | Confirmed finding | Required outcome |
| --- | --- | --- | --- |
| 02D-01 | Blocker | The canonical `tests/connectivity/local.sh` and `netns.sh` are unsupported-result stubs. The alternate `tests/local/` cases C06-C09 all run the same ordinary relay probe without their named deadline, DCUtR, interruption, or limit conditions; C10 runs eight sequential probes rather than 64 and 128 concurrent probes; C11 has no concurrent nonce/resource assertion; C12 and C13 do not pass their lifecycle requirements. | Establish one canonical harness, implement each case's actual setup/fault/assertions, and reject aliases that do not prove the named invariant. |
| 02D-02 | Blocker | The live apps do not use `ConnectionBook`, `ReservationContext`, or `PathAttempt`. The client opens on the first server connection, does not listen on TCP/QUIC, does not process DCUtR, and uses `--path` only in log text. The server manually requests one relay listener and awaits the whole probe on the swarm task. The exchange listens only on TCP. | Wire the three state machines and both transports into one bounded owner loop per process, with worker tasks outside the swarm loop and finite terminal behavior. |
| 02D-03 | P0 | `builder.rs` still has one mixed `SwarmConfig`; its listener fields are validated but not consumed by either builder. DNS wrapping, explicit QUIC configuration, the 64 inbound-negotiation limit, Identify pushed-listen updates, configured QUIC listeners, and explicit relay rate limiters are absent. `supported_protocols()` still tests a standalone constant. | Make configuration authoritative and test constructed transport/behaviour settings and both listener startup paths. |
| 02D-04 | P0 | `ProbeStreamBehaviour` removes a request and releases its capacity before the terminal output is polled. Its terminal/inbound events share an unbounded queue; timeout and close leave stale commands; handler queues can silently discard negotiated outbound success/failure, while the handler queue-full failure path can itself exceed its event bound. | Retain one permit through terminal delivery, separate bounded outbound/inbound queues, remove stale commands on every terminal path, and make outbound completion exactly once and non-droppable. |
| 02D-05 | P0 | `ConnectionBook` still uses independent record/pending/tombstone maps rather than one lifecycle cap, accepts an optional expected exchange, evicts unexpired tombstones, and can admit an unvalidated relayed endpoint as `UnknownDirect`. `ReservationContext` resets an equal generation, does not invalidate facts on loss, increments retry on duplicate loss, has one-sided jitter, and returns no recovery actions. `PathAttempt` retains the second `open_committed` transition API and cannot return `CancelOpen`/`CloseStream` cleanup on timeout or cancellation. | Implement the fail-closed lifecycle and event/action contracts in §3.3 and cover every boundary/reordering with tables. |
| 02D-06 | P0 | The probe implementation is one-way: server acknowledgements always report zero bytes read/hash, half-close success is inferred from mode rather than observed EOF, and “slow reader” delays server writes rather than exerting read-side backpressure. Payload I/O lacks one operation deadline, and the live server blocks swarm polling while transferring up to 256 MiB. | Implement verified bidirectional phases, real half-close/EOF checks, a true slow-reader worker, bounded result channels, and responsiveness tests. |
| 02D-07 | P0 | Lifecycle records put operational data into free-form `detail` strings. Terminal output omits selected/observed path, request/connection hashes, timings, payload results, and final resource counters. Early client failures return `Err` without the mandatory terminal record, and no app accepts an artifact output path. | Add typed versioned records and a terminal guard so every finite client path emits exactly one complete result. |
| 02D-08 | P1 | Test coverage does not exercise the exact-open queues/races, handler overflow, full state tables, bidirectional protocol, worker admission/cancellation, direct-plus-relay coexistence, process cleanup, or any case harness. Existing local summaries can report named cases as passed without applying their required fault. | Add focused unit, same-process integration, and process-harness tests before accepting case summaries. |
| 02D-09 | P1 | Dependency and evidence state is stale and failing: `cargo-deny` is now present but policy/advisory checks fail; evidence names old commits and no observed matrix; ADR gate wording blocks the corrective work itself. | Resolve or explicitly adjudicate each dependency finding, regenerate evidence only from validated summaries, and update the ADR wording and decision. |

## 3. Required Remediation

### 3.1 Make swarm construction authoritative

Replace `SwarmConfig` in [`crates/p2x-net/src/builder.rs`](../crates/p2x-net/src/builder.rs) with separate `ExchangeSwarmConfig` and `PeerSwarmConfig` values. Their constructors validate complete TCP and QUIC listen multiaddresses; builder/startup functions must call `listen_on` from those stored values and return the resulting `ListenerId`s. App code must not accept or start a different unchecked listener afterward.

Apply the existing constants to real libp2p configuration:

- use `with_quic_config` to set `max_concurrent_stream_limit = 256` explicitly;
- wrap transports with `with_dns()` and handle its build error;
- set `with_max_negotiating_inbound_streams(64)` and the 120-second idle timeout on the swarm config;
- configure both ordinary and relay-client Yamux for 256 streams;
- enable `identify::Config::with_push_listen_addr_updates(true)` and keep Ping at 15/5 seconds;
- start configured TCP and QUIC listeners for exchange, server, and client before any exchange/server dial;
- reject either non-loopback exchange listener unless the exchange-only unsafe lab acknowledgement is present.

Construct both relay profiles from explicit fields and rate limiters rather than inheriting upstream limiter defaults. Preserve Plan 02c's reservation/circuit/duration/byte table. The `DefaultLab` rate limiters must allow two renewals and 100 sequential churn circuits; `LimitTest` must reject at the intended reservation/circuit-count boundary.

Delete `supported_protocols()` if it remains disconnected from constructed behaviour. Tests must inspect effective config helpers and observed Identify protocol sets from a live same-process swarm, proving that `/p2x/spike/1`, relay, DCUtR, Identify, and Ping are present while AutoNAT, rendezvous, request-response, WebSocket, and UPnP are absent.

### 3.2 Make exact-connection opening bounded through delivery

Refactor [`probe_stream/behaviour.rs`](../crates/p2x-net/src/probe_stream/behaviour.rs) around:

```text
PendingOpen { request, created_at, deadline, phase, terminal }
phase = Queued | Notified | TerminalQueued
```

- Keep the request in the admitted set through `TerminalQueued`; release its global/per-peer permit only when `poll` returns that terminal `GenerateEvent`, or when shutdown explicitly discards it.
- Store at most 128 admitted outbound requests and 64 per peer. Derive counter values from the admitted records or update one checked accounting object; do not repeatedly scan or maintain independently drifting counters.
- Keep a bounded outbound terminal queue sized to the global admitted cap and a separate bounded inbound queue sized to inbound admission. Always poll outbound terminal delivery first.
- On close, expiry, cancellation, mismatch, or shutdown, remove matching commands that have not been delivered to a handler, transition each request once to `TerminalQueued`, and ignore/drop any later returned stream.
- Allocate `RequestId` with checked monotonic increment and provide injected-time test constructors plus counters for admitted, queued, in-flight, terminal, inbound, and known-connection state.

In [`handler.rs`](../crates/p2x-net/src/probe_stream/handler.rs), separate bounded outbound completions from inbound streams. A negotiated outbound success/failure must never be silently dropped. Keep the 64-command/64-outbound-completion bounds; when inbound capacity is full, reset/drop the stream and report one bounded rejection without consuming outbound completion capacity. Queue-full rejection must use reserved outbound capacity and cannot append to an already full queue.

Add unit tests for unknown connection, checked request-ID exhaustion, global/per-peer admission, every queue boundary, mismatch, timeout/cancel/close before and after notification, success versus late failure, inbound starvation, shutdown drain, stale-command removal, and exactly-once permit release. Add `crates/p2x-net/tests/exact_connection.rs` (or the repository's chosen integration-test name) that holds direct and relay connections to one peer concurrently and proves receiver-observed opens on each exact ID without closing the other.

### 3.3 Correct connection, reservation, and path truth

#### Connection lifecycle

Replace the three maps in [`connection_book.rs`](../crates/p2x-net/src/connection_book.rs) with one `MAX_CONNECTION_LIFECYCLES = 512` ledger keyed by `(PeerId, ConnectionId)` and containing `PendingDcutr`, `Active(ConnectionRecord)`, or `Retired { expires_at }`.

- Require the expected exchange `PeerId` in `ConnectionBook::new`; remove the optional/default production path.
- Validate a relayed endpoint only when the authoritative `ConnectedPoint` address contains the expected exchange identity before `/p2p-circuit`; otherwise return a typed rejection and have the owner close it.
- On total ledger capacity, reject an untracked establish/DCUtR event. Never evict an unexpired retired ID or pending event to admit a new one.
- Close converts an existing slot to `Retired`; `sweep(now)` is the only expiry/removal path and runs from a peer-loop interval even without network events.
- Keep direct selection restricted to open, confirmed direct records with QUIC-before-TCP and oldest-sequence ordering.

Tests must cover both event orders, malformed/wrong relay identity, duplicate establish, late success after close, total capacity, deterministic sweep, sequence overflow handling, and more than 512 connect-close attempts without resurrection or unbounded state.

#### Reservation lifecycle

Make every applicable [`ReservationEvent`](../crates/p2x-net/src/reservation.rs) carry generation, expected exchange peer/connection, `ListenerId`, and canonical address identity. Replaying the identical `GenerationStarted` is a no-op; an equal generation with different identities is a typed error; only a strictly newer generation clears all facts and counters.

Matching exchange loss invalidates exchange, acceptance, listener, and address truth. Matching listener loss invalidates its acceptance/address facts. Matching address loss invalidates only that address. Duplicate/stale loss cannot increment retry or replace a scheduled deadline. Return explicit `DialExchange`, `CreateCircuitListener`, `ScheduleRetry`, `PublishReady`, and `PublishDegraded` actions. Apply deterministic injected jitter in the full -20% to +20% range, cap exponential backoff at 10 seconds, and reset retry only when matching acceptance plus address confirmation restores readiness.

#### Path attempt

Remove `open_committed`; keep one `apply(PathEvent) -> Vec<PathAction>` transition surface. `Begin` either selects a healthy pooled direct record or emits `DialRelay`. Relay readiness begins the 1.5-second direct window; it must not emit a duplicate relay dial.

`OpenExact` does not invent a request ID. The owner calls `ProbeStreamBehaviour::open_on`, then returns `ExactOpenQueued { request_id, connection_id }` to the attempt. Every success/failure must match attempt, request, and connection. Direct failure may generate one new relay open whose request ID comes from the behaviour. Setup expiry/cancellation while queued emits `CancelOpen`; expiry/cancellation in `StreamReady` emits `CloseStream`; both then emit one `Finish`. Selected/unselected close events carry the actual connection ID. Payload acceptance alone enters `Streaming`, after which no fallback/replay is allowed.

Expand table tests to every state, boundary timestamp, stale attempt/request/connection, explicit and silent DCUtR failure, relay loss, one fallback, cleanup action, and repeated terminal input.

### 3.4 Finish the bidirectional probe and worker contract

Keep the 4096-byte header cap, 256 MiB transfer cap, closed modes, and reusable 32 KiB buffers in [`probe.rs`](../crates/p2x-net/src/probe.rs) and [`probe_worker.rs`](../crates/p2x-net/src/probe_worker.rs), but make the wire phases observable rather than inferred:

1. `nonce_echo`: client writes a bounded header; server returns the correlated ack with no payload.
2. `half_close`: client streams the declared deterministic payload and shuts down its write half; server reads exactly the declared bytes and then verifies EOF. Server streams its declared response, writes the ack, and shuts down its write half; client verifies payload/hash, ack, and EOF.
3. `slow_reader`: client writes the declared payload while the server intentionally reads bounded chunks at the configured delay. A separate nonce stream must finish within its own deadline while backpressure is active.

Populate both directional byte/hash fields from observed I/O. Set half-close success only after EOF checks. Give frame, payload, ack, and total worker operations injected deadlines and distinct stable terminal codes for oversize, schema/mode validation, truncation, timeout, I/O, hash mismatch, EOF mismatch, and admission rejection.

Admit inbound work before reading a header with 128 global and 64-per-peer permits. The swarm owner moves each admitted stream into a spawned worker and continues polling; workers return typed results through a bounded channel. Release permits exactly once on success, rejection, timeout, cancellation, worker panic/join failure, and shutdown. Never await a payload copy inside the swarm event arm.

Test short I/O, unknown/trailing fields, all mode boundaries, zero and 256 MiB constant-buffer transfers, both half-closes, wrong pattern/hash, concurrent slow reader plus nonce, admission limits, result-channel backpressure, cancellation, and shutdown.

### 3.5 Integrate the three finite lab lifecycles

Keep exactly the existing binaries and make one task own each swarm.

1. `p2x-exchange` accepts validated TCP/QUIC listeners, `RelayProfile`, unsafe public acknowledgement, run ID, and optional artifact path. It emits typed listener/readiness/relay/resource records and drains on cancellation.
2. `p2x-server` accepts one complete exchange address plus expected peer, validated TCP/QUIC listeners, and worker limits. It drives `ReservationContext` through generation, renewal, loss, and retry; advertises ready only when matching acceptance and canonical circuit address are both present; and dispatches inbound probes to bounded workers.
3. `p2x-client` accepts exchange/server identities and circuit address, validated local TCP/QUIC listeners, requested/forced path, mode/size/count/concurrency, and one setup deadline. It establishes relay first, consumes swarm/DCUtR events into `ConnectionBook` and `PathAttempt`, opens only the selected exact connection, verifies the server-observed path/ack, and exits finite mode with one result.

Map each `ConnectionClosed` into connection ledger, exact opener, reservation context, and active attempt in the same owner turn. Drive exact-open expiry, ledger sweep, reservation retry, path deadlines, and resource sampling with intervals. On shutdown, close admission, cancel/drain bounded workers, fail pending opens, and emit final zero logical-resource counts.

Replace free-form lifecycle `detail` with a tagged `LifecycleRecord` enum in [`lifecycle.rs`](../crates/p2x-net/src/lifecycle.rs). Define typed records for readiness, connection/path observations, reservation/renewal, probe completion, resources, and `TerminalResult`. The terminal record includes schema/component/run/case IDs, result/code, setup duration, selected and receiver-observed path, local connection hashes, byte/hash/half-close fields, and final resource counts. Implement finite client execution as `run(...) -> TerminalResult` so `main` serializes exactly one terminal result even for validation, dial, timeout, cancellation, and probe errors. Mirror NDJSON to the optional artifact path with the same serializer.

### 3.6 Replace false-positive harnesses with the stable matrix

Make [`tests/connectivity/local.sh`](../tests/connectivity/local.sh) and [`netns.sh`](../tests/connectivity/netns.sh) the canonical entry points. They may delegate to per-case directories, but `tests/local/run.sh` and `tests/linux/run.sh` must not define a second, weaker meaning for a case. Add `tests/connectivity/common.sh` for strict run IDs, TCP/UDP port allocation, owned process groups, readiness parsing, resource sampling, schema validation, and run-scoped cleanup.

- C01 must prove relay reservation, a DCUtR-confirmed direct connection, and receiver-observed exact direct probing; the current relay nonce smoke remains a separate non-gate smoke.
- C05 must keep direct and relay connections open together and open one receiver-observed probe on each exact ID.
- C06-C09 must apply their named missing-DCUtR, interruption, and low-relay-limit conditions; a generic relay nonce cannot pass them.
- C10 must run 64 and 128 genuinely concurrent mixed probes, not eight sequential opens.
- C11 must run exactly 268435456 bytes over direct and relay with verified bidirectional hashes/half-close, a responsive concurrent nonce, and RSS/buffer assertions.
- C12 must observe at least two renewals while the circuit stays dialable; C13 must complete 100 connect-close iterations and return records, opens, workers, permits, tasks, RSS, and file descriptors to baseline.
- `netns.sh` must implement C02-C13 with three namespaces, scoped firewall/traffic-control rules, transport/path assertions, and safe teardown; a namespace-creation smoke is not a case pass.
- C14 scripts must start exchange and server, extract the canonical circuit address, run the client from a separate real network, validate relay success plus both path observations, capture environment/firewall/cleanup, and report the topology-dependent direct result honestly.

Every gate case writes raw per-process NDJSON, environment/topology, resource samples, cleanup status, and one schema-validated summary below `target/p2x-spike/<run-id>/`. Missing/duplicate terminal records, path disagreement, setup over 20 seconds, absent fault application, wrong counts/hashes/EOF, unsupported status, or non-zero final logical resources fail the case.

### 3.7 Resolve dependency policy and close evidence

Keep `cargo-deny 0.20.2` pinned and correct [`deny.toml`](../deny.toml) deliberately:

- allow the OSI-approved `Zlib` dependency license;
- while the repository license remains intentionally undecided, configure cargo-deny to ignore unpublished private workspace packages rather than assigning a guessed license; remove that exception when the repository license is selected. Do not assume AGPL unless later approved third-party source use requires it;
- use `cargo tree -e features -i hickory-proto` to document whether each hickory advisory is reachable under the committed features, then resolve it through the smallest compatible dependency change or a narrowly scoped, owner-reviewed ignore with reachability rationale and removal condition;
- resolve the `paste` unmaintained advisory through an available upstream dependency update, or document a narrowly scoped temporary ignore and tracked removal condition; do not add a blanket advisory ignore.

If resolving hickory changes `libp2p`, any libp2p component, the DNS transport, or Rust, freeze the new versions before live testing and rerun all C01-C14 cases.

After every check and case passes, generate [`plan/evidence/01-connectivity-spike-results.md`](evidence/01-connectivity-spike-results.md) from scrubbed validated summaries. Record the reviewed commit and dirty state, exact resolved component versions, commands, environment/topology, client/server path observations, timings, bytes/hashes/EOF, resource baseline/peak/final values, rerun count, and failures. Remove stale statements that `cargo-deny` is absent.

Correct ADR 0001's gate wording so corrective Plan 02 work is allowed while product Plan 03 remains blocked. Set the ADR to `Accepted` or `Accepted with required custom handler` only when §6 passes. If exact selection, fallback, supported-platform behavior, security policy, or resource cleanup fails, set it to `Rejected` with the reproducible invariant and do not create Plan 03.

## 4. Implementation Order

1. Add failing unit tables for connection/reservation/path transitions, exact-open accounting/queues, bidirectional probe phases, worker admission, and terminal cardinality.
2. Correct the exact-open lifecycle and the three pure state modules; add the direct-plus-relay exact-connection integration test.
3. Make exchange/peer configuration authoritative and apply DNS, QUIC/Yamux, negotiation, Identify, listener, and relay-rate settings.
4. Finish the probe protocol, move payload work off the swarm task, and add bounded worker/result channels.
5. Replace lifecycle strings with typed records and integrate exchange, server reservation/recovery, and client DCUtR/path/open/probe state.
6. Consolidate the local harness; pass C01 and C05-C13 on required TCP/QUIC variants without aliases or weakened assertions.
7. Implement and pass Linux namespace C02-C13, then execute C14 on two native hosts on separate networks.
8. Resolve `cargo deny check`, rerun every case invalidated by dependency/network changes, generate evidence, and decide ADR 0001.
9. Create Plan 03 for Phase 1 identity/authentication/bounded protocols only after an accepted ADR and committed complete evidence.

## 5. Verification

Run from the repository root with the committed toolchain and lockfile:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo deny --version                         # exactly 0.20.2
cargo deny check
```

Run canonical commands only:

```text
./tests/connectivity/local.sh --case C01
./tests/connectivity/local.sh --case C05
./tests/connectivity/local.sh --case C06
./tests/connectivity/local.sh --case C07
./tests/connectivity/local.sh --case C08
./tests/connectivity/local.sh --case C09
./tests/connectivity/local.sh --case C10 --streams 64
./tests/connectivity/local.sh --case C10 --streams 128
./tests/connectivity/local.sh --case C11 --bytes 268435456 --path direct
./tests/connectivity/local.sh --case C11 --bytes 268435456 --path relay
./tests/connectivity/local.sh --case C12
./tests/connectivity/local.sh --case C13 --iterations 100
./tests/connectivity/netns.sh --case C02  # repeat through C13 with required variants
```

Run applicable local cases once through exchange TCP and once through exchange QUIC. Run the namespace matrix on Linux with the required privileges, native macOS coverage, and C14 on separate real networks. Preserve raw failure artifacts during development; commit only scrubbed validated summaries. The worktree must remain clean except ignored `target/p2x-spike/` outputs.

## 6. Definition of Done

- Findings 02D-01 through 02D-09 are closed by code, automated tests, and observed artifacts.
- Configuration accepted by each binary is the configuration applied to its real transports, behaviours, relay service, and listeners.
- Direct and relay coexist for one peer and receiver observations prove exact opens on both IDs without closing the other connection.
- Every open and attempt has one immutable setup budget, at most one pre-payload fallback with a fresh behaviour-issued request ID, one terminal output, and exactly-once cleanup.
- Reservation readiness/recovery is identity- and generation-scoped, survives renewal, and ignores duplicate/stale loss and retry events.
- Half-close, slow-reader, 256 MiB, concurrency, interruption, renewal, and churn tests prove bounded buffers, queues, workers, records, permits, tasks, RSS, and file descriptors.
- Static checks and `cargo deny check` pass; C01-C14 pass with schema-valid evidence on all required environments.
- ADR 0001 records the evidence-backed accept/reject outcome. Plan 03 and product implementation remain absent unless that outcome is accepted.

## 7. Gate Outcome

Plans 02-02c are not complete at the reviewed baseline. The passing unit tests and relayed nonce smoke demonstrate useful components, but they do not prove the product-analysis architecture spikes in §23.1 or the Phase 0 exit in §24.

Plan 02d is complete only when §6 is satisfied and ADR 0001 is no longer `Deferred`. If the foundation is rejected, preserve the failing artifacts and plan the architecture change separately; do not reinterpret a smoke pass, an ignored case, or a unit-only invariant as permission to begin Plan 03.
