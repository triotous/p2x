# Remediation Plan: Close Plan 06 Raw TCP Tunnel Gaps

- **Document status:** implementation-ready
- **Scope:** corrective follow-up to [`06-raw-tcp-proxy-tunnel.md`](06-raw-tcp-proxy-tunnel.md)
- **Baseline reviewed:** `feat/06-raw-tcp-proxy-tunnel` at `7675325`
- **Required outcome:** keep the implemented direct/relay raw TCP path, but make every local ingress failure nonfatal to the client daemon, make pre-Accept server work deadline- and shutdown-bounded, enforce every configured stream limit exactly, emit complete terminal evidence, and replace representative tunnel tests with the executable coverage required by Plan 06

## 1. Review Result and Scope

The Plan 06 implementation establishes the core product path: the client binds loopback listeners before exchange dialing, resolves a TCP selector, opens the selected direct or relayed `/p2x/proxy/1` stream, the server verifies and consumes a one-use ticket, connects an immutable IP-literal upstream, emits `Accepted`, and proxies opaque bytes with fixed buffers and half-close propagation. The canonical runner currently completes all 14 named tunnel cases.

Plan 06 is not complete, however. Several product-mode error branches still terminate the whole client process, server dial work does not use the remaining handshake deadline or shutdown cancellation, one client limit can be silently widened, and the executable suite does not prove the full limit, shutdown, lifecycle, privacy, and same-process owner requirements it reports as complete.

This plan fixes only the reviewed Phase 4 closure gaps. It does not add HTTP/SNI routing, DNS upstreams, load balancing, stream migration, dynamic configuration reload, or final deployment packaging.

### 1.1 Verification completed during review

| Check | Review result |
| --- | --- |
| `cargo fmt --all -- --check` | passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-targets --all-features` | passed outside the restricted socket sandbox, including TCP/QUIC network tests |
| Initial parallel test run | exposed one intermittent client-config test failure; the isolated test and full rerun passed, so test-file isolation must be made deterministic |
| `cargo deny check` | passed; duplicate dependency versions remain warnings |
| `cargo tree -e features` | passed |
| `./tests/tunnel/local.sh --case all` | all 14 named cases passed |
| `./tests/auth/local.sh --case all` | passed |
| `./tests/registry/local.sh --case all` | passed |
| `./tests/connectivity/local.sh --case all` | C01 and C05-C13 passed, including 64/128 concurrency |
| `./tests/resolution/local.sh --case all` | failed: `concurrent-opens` sampled `[0, 62]` instead of the asserted 64-owner peak; the case passed when rerun alone, confirming timing-dependent evidence |
| Plan 06 owner-executed platform phase | not rerun; Linux namespace/firewall, two-host, native platform/container, and soak gates remain explicitly incomplete as allowed by Plan 06 §5.5 |

### 1.2 Confirmed implementation and evidence gaps

| Priority | Confirmed current behavior | Required correction |
| --- | --- | --- |
| P0 | Product ingress shares route-owner branches with finite diagnostics. Resolve timeout, path timeout, connection loss, and several capacity/rejection branches emit a process `terminal` and return from `main`; `ConnectionManager::begin_path...` errors also escape through `?`. One failed local connection can therefore stop every listener and unrelated active tunnel. | Centralize product-ingress completion so every setup failure rejects and cleans only its `IngressId`/`OpenId`; keep process terminals only for finite diagnostics, fatal configuration/invariant corruption, and shutdown. |
| P0 | `run_worker` receives `now` at inbound-open time, can wait five seconds plus a test hold, and verifies the ticket using that stale time. Its owner wait, test hold, upstream dial, and Accepted write are not one absolute cancellable operation. | Give the worker one five-second handshake deadline, recompute time after delay, recheck time in the owner, clip dial timeout to the deadline, and select every pre-Accept wait against shutdown. |
| P0 | `upstream::timeout_for` is tested but unused. Production always gives `TcpStream::connect` the full configured timeout, while deterministic dial holds sleep outside both the timeout and shutdown signal. | Make the production connector accept the remaining worker budget and cancellation; make fault holds use the same path and never outlive shutdown or the deadline. |
| P1 | Before Accepted, local EOF only sets `local_eof = true`; it does not notify the main loop or cancel route work, so an abandoned caller can continue through ticket consumption and upstream dial until setup timeout. | Emit one pre-Accept close/cancel event immediately on EOF or read error and release the exact route, proxy, connection-manager, and ingress owners. |
| P1 | `ConnectionManager::admit` compares active-plus-pending against `max_streams_per_server.max(max_pending_per_server)`. A valid configuration with a lower stream limit is silently widened to the pending limit. | Enforce `max_streams_per_server` literally; validate configuration relationships explicitly if a lower pending limit is required, and prove asymmetric configurations. |
| P1 | `StreamAdmission::reserve` uses `HashMap::insert` before checking for an existing stream ID. A collision returns an error after replacing the live entry. | Use `HashMap::entry`; reject an occupied stream ID without changing the existing owner or counters. Add a deterministic collision test. |
| P1 | `TunnelTerminal` has no component side, selected path, or pump terminal class. The client always emits `code: None`; the server maps only idle timeout. Cancellation and local/remote I/O failures are indistinguishable from a clean completion. | Add closed lifecycle enums/fields for side, path, and terminal class; map every `PumpResult::terminal` on both components and preserve request/stream/connection correlation. |
| P1 | `apps/p2x-server/tests/owner_pipeline.rs` still stops at ticket authorization/replay. It does not exercise `StreamAdmission`, immutable `LocalUpstream`, TCP connect, Accepted, bytes, or terminal cleanup. Server worker release paths and several pump invariants also have no direct tests. | Extend the same-process owner pipeline through the actual upstream and add deterministic tests for every decision, dial, Accepted-write, pump, cancellation, and release path. |
| P1 | `stream-limits` proves only a per-service limit of one. `shutdown-cancellation` stops the client before the server and therefore does not prove independent setup/active cancellation on both sides. Idle, terminal-correlation, timing-stage, baseline resource, and privacy claims are also incomplete. | Split these into explicit subcases and assert every Plan 06 §5.2-§5.4 owner and terminal condition from events and endpoint observations. |
| P1 | The tunnel privacy scan omits the payload sentinel, selector/metadata value, and upstream ID even though the summary reports privacy clean. The summary's `one_terminal_each` checks process terminals, not one tunnel terminal per accepted stream. | Scan all prohibited run-scoped markers and separately assert exactly one process terminal per process plus exactly one terminal per accepted stream per component. |
| P1 | Resolution `concurrent-opens` infers an exact owner peak from one-second periodic resource samples. The full suite observed 62 while the isolated case observed 64. | Replace timing-dependent sampling with an owner transition/high-water event or a deterministic hold/release barrier, then require the exact 64/128 evidence in every run. |
| P2 | [`docs/protocol/proxy-v1.md`](../docs/protocol/proxy-v1.md) still says the server requires Open-side write-half closure and rejects early application data, contradicting the implemented flush-without-close Phase 4 handshake. | Correct protocol and operations documentation only after the executable behavior is closed. |

## 2. Required Invariants

The remediation must preserve these already-correct Plan 06 properties:

- fixed ingress binds only unique, nonzero loopback `SocketAddr` values and resolves exactly one TCP route;
- the client accept timestamp remains the origin of the route setup deadline; no retry creates a new client deadline;
- the client sends no P2P application bytes before a correlated `Accepted`;
- the server obtains the actual upstream address only from immutable local configuration and never logs or transmits it;
- behavior, replay, stream, dial, service, client ingress, route, peer, and active-stream limits are acquired before the corresponding work and released exactly once;
- ticket consumption remains final after dial failure, Accepted-write failure, cancellation, connection loss, or shutdown;
- active direct streams survive exchange control loss; selected P2P path loss resets only affected streams and does not transparently replay them;
- the duplex pump uses one fixed buffer per direction, increments counters after successful writes, propagates half-close, and applies only the server idle timeout;
- product-mode setup failure is local to one ingress. Only invalid startup configuration, corrupted internal ownership, unrecoverable swarm failure, or operator shutdown may stop the daemon.

## 3. Required Design Corrections

### 3.1 Product-ingress failure isolation

Refactor `apps/p2x-client/src/main.rs` so all route completions enter one helper before any process-level decision. The helper should receive:

```text
OpenId
optional server PeerId
Result<(), PublicErrorCode>
completion source: resolve | path | proxy | connection | deadline | ingress
```

For `product_ingress == true`, it must:

1. remove the exact `OpenId -> IngressId` mapping and ignore a completion for an already removed generation;
2. remove only matching resolve/proxy wire mappings and cancel the corresponding behavior request where it still exists;
3. call `ResolverState::cancel` for the exact request and promote any newly ready waiter;
4. release the exact connection-manager waiter and pending count once; do not close a shared healthy connection merely because one setup failed;
5. remove and cancel the matching ingress token, send `IngressCommand::Reject`, and emit one `IngressRejected` with the stable public code;
6. continue the main loop without emitting a process `terminal`;
7. leave unrelated `active_ingress`, route opens, peer states, listeners, auth, and exchange reconnect state untouched.

For finite diagnostic modes, preserve the existing aggregate process-terminal behavior. Do not scatter `if product_ingress` branches at each call site; route maintenance timeouts, resolve responses/failures, path ticks, proxy failures, connection closure, and capacity errors must use the same helper.

Replace product-mode `?` propagation from expected capacity/path errors with `RouteAction::Complete` or the centralized completion helper. Reserve `io::Error` process exit for malformed internal ownership that cannot be attributed to one current ingress.

### 3.2 Exact client ingress and peer-stream ownership

Update `apps/p2x-client/src/ingress.rs`:

- replace the overloaded `Closed` event with an explicit pre-Accept terminal carrying `IngressId`, route ID/hash context, and whether the cause was EOF, local I/O, deadline, or shutdown;
- on `read == Ok(0)` before `StartTunnel`, send the terminal immediately and return; never retain the route until the deadline;
- use a local `terminal_delivered` guard so deadline, command closure, EOF, cancellation, and read error cannot report or release twice;
- when the shared pump returns an `io::Error`, preserve a stable local terminal class instead of synthesizing `Cancelled` with zero counters;
- keep the prebuffer allocation fixed and stop reading at capacity as today.

Update `apps/p2x-client/src/connection_manager.rs` and config validation:

- compare `pending + active` directly with `max_streams_per_server`;
- either require `max_pending_per_server <= max_streams_per_server` at configuration load or let the total-stream check be the stricter bound; do not silently compute a larger effective value;
- make pending-to-active promotion return `Result`/`bool` and require one pending owner before incrementing active;
- reject underflow/double release in tests instead of masking it with `saturating_sub`;
- add tests with `max_pending_per_server = 8` and `max_streams_per_server = 1`, one active plus a new pending attempt, and capacity reuse after terminal.

### 3.3 One cancellable server pre-Accept state machine

Refactor `apps/p2x-server/src/proxy_open.rs` around a single absolute worker deadline created when `run_worker` begins:

```text
worker_deadline = started_at + 5 seconds
read Open -> optional guarded hold -> verify current ticket time
-> enqueue candidate -> await owner decision -> dial clipped to remaining time
-> owner-confirm Dialing-to-Active promotion -> write Accepted
```

Every arrow must select against `shutdown.cancelled()` and return through one release path. A timeout at or before dial maps to `upstream.connect_timeout` when the upstream dial has begun; earlier handshake expiry remains the existing setup/protocol failure class. No test hook may sleep outside this state machine.

Change `apps/p2x-server/src/upstream.rs` to expose a production connector equivalent to:

```rust
connect(upstream, remaining, cancel) -> Result<TcpStream, ConnectError>
```

It must use `min(upstream.connect_timeout, remaining)`, select against cancellation, and retain redacted public errors. Remove or use the currently dead `timeout_for` and `redacted_io_error` seams.

Time verification must use a fresh wall-clock value after Open/hold work. The owner must also reject a candidate whose ticket is no longer within its signed time window at the owner transition, using the configured skew, so queue delay cannot authorize an expired ticket. Inject a clock into tests; do not depend on sleeps for boundary assertions.

Make dial promotion an acknowledged owner transition. The worker may write `Accepted` only after the owner changes the matching admission entry from `Dialing` to `Active`; a stale/missing promotion is a terminal release, not a best-effort ignored boolean.

During server shutdown, the drain loop must process release and promotion acknowledgements, release `StreamAdmission` entries, emit terminal records for cancelled accepted streams, and finish with behavior workers, proxy workers, dialing entries, active entries, and service entries at zero. A dial or hold must not survive the five-second shutdown window.

### 3.4 Collision-safe admission and exact release

Update `apps/p2x-server/src/stream_admission.rs`:

- use `HashMap::entry` so an occupied `stream_id` returns `protocol.malformed` without replacing the existing `Entry`;
- keep global, per-client, per-service, and dial preflight checks before mutation;
- make promotion/release results explicit errors in production ownership rather than ignored booleans;
- expose privacy-safe global/dialing/active counts and per-service counts for final evidence;
- test collision, duplicate promotion, duplicate release, decision-channel loss, dial failure, Accepted-write failure, connection reset, idle, cancellation, and shutdown.

Do not retry stream-ID allocation after ticket consumption unless the ticket ledger and admission owner perform that allocation atomically. The smallest safe correction is to reject the collision and retain the consumed ticket while preserving the prior live admission.

### 3.5 Duplex pump and lifecycle completeness

Extend `crates/p2x-net/src/lifecycle.rs` with closed, serialized values for:

- `component_side`: `client` or `server`;
- `selected_path`: `direct`, `relay`, or absent before selection;
- `terminal_class`: `complete`, `idle_timeout`, `cancelled`, `local_io`, or `remote_io`;
- setup duration on the Accepted/setup event, measured from local accept on the client;
- existing request, stream, and connection fingerprints plus directional byte/EOF fields.

Map every `p2x_proxy::Terminal` in client and server terminal emission. `code` remains a stable public code where one exists; terminal class must not be inferred from `code: null`. An accepted tunnel may report `accepted: true` and a non-success terminal class.

Add focused `p2x-proxy` tests for:

- EOF and response continuation in both half-close directions;
- idle deadline reset by successful writes in either direction;
- a blocked writer reaching idle timeout without unbounded buffering;
- local-read, local-write, remote-read, and remote-write failures with exact counters;
- cancellation while both directions are pending and while one writer is blocked;
- no detached task or retained socket after completion;
- bounded scheduler fairness during a hot stream, with a concurrent heartbeat task making progress.

If the fairness test exposes starvation, bound the amount of copy work performed in one `poll_pump` call and self-wake/yield after that budget. Do not add per-chunk channels or allocate a new buffer per read.

## 4. Ordered Implementation Plan

Each phase must end with a focused commit and its relevant tests passing. Do not postpone all tests to the final phase.

### 4.1 Phase A — Isolate product ingress failures

Files:

- `apps/p2x-client/src/main.rs`
- `apps/p2x-client/src/route_open.rs`
- `apps/p2x-client/src/ingress.rs`

Steps:

1. Introduce the centralized product-route completion helper and a closed completion-source enum.
2. Route maintenance timeout, resolve timeout/rejection, path completion, proxy rejection/failure, selected connection loss, local EOF/error, and client capacity rejection through it.
3. Preserve finite diagnostic exits behind an explicit mode branch.
4. Ensure cleanup removes only matching generations and promotes resolver waiters after cancellation.
5. Add a same-process state test and live cases where the first ingress fails at resolve, path, upstream, and client capacity stages while a later ingress succeeds in the same client process.

Phase gate: no expected per-ingress `PublicErrorCode` can reach a process `terminal` or return from product `main`.

### 4.2 Phase B — Fix client EOF and stream bounds

Files:

- `apps/p2x-client/src/config.rs`
- `apps/p2x-client/src/connection_manager.rs`
- `apps/p2x-client/src/ingress.rs`

Steps:

1. Emit an immediate, exactly-once pre-Accept terminal on EOF/error/deadline.
2. Enforce the literal active-plus-pending per-server limit and make promotion/release checked transitions.
3. Give config tests collision-free temporary paths using a process-wide atomic sequence or an owned temporary directory; do not rely on wall-clock nanoseconds alone.
4. Add exact boundary and capacity-reuse tests for ingress, route, pending-per-server, and active-plus-pending limits.

Phase gate: an abandoned local socket creates no ticket/upstream dial after its close event, and asymmetric configured limits reject at the documented owner without stopping listeners.

### 4.3 Phase C — Bound server verification, decision, dial, and shutdown

Files:

- `apps/p2x-server/src/proxy_open.rs`
- `apps/p2x-server/src/upstream.rs`
- `apps/p2x-server/src/main.rs`
- `apps/p2x-server/src/ticket_admission.rs`
- `apps/p2x-server/src/stream_admission.rs`

Steps:

1. Thread one worker deadline, cancellation token, and injected clock through Open read, guarded holds, verification, candidate enqueue, decision wait, dial, promotion, and Accepted write.
2. Clip the real connect timeout to remaining worker time and make fault injection use the same connector path.
3. Recheck ticket time in the owner immediately before consume.
4. Convert promotion into an acknowledged transition and make every failed transition use the single release path.
5. Make admission collision-safe and drain release/promotion messages through shutdown.
6. Add deterministic unit tests for each timeout/cancellation boundary and exact count recovery.

Phase gate: no pre-Accept server worker, dial, admission, or behavior permit survives deadline or shutdown; stale time cannot authorize a ticket.

### 4.4 Phase D — Complete pump and lifecycle evidence

Files:

- `crates/p2x-proxy/src/lib.rs`
- `crates/p2x-net/src/lifecycle.rs`
- `apps/p2x-client/src/main.rs`
- `apps/p2x-server/src/main.rs`
- `apps/p2x-server/src/proxy_open.rs`

Steps:

1. Add the missing terminal, side, path, and setup-duration lifecycle fields as closed values.
2. Map all clean/error/cancel/idle outcomes without replacing errors with synthetic zero-byte cancellation.
3. Add the pump test matrix, including fairness and no-survivor checks.
4. Emit final zero-resource evidence after client and server drain, not merely a periodic sample that happened before exit.

Phase gate: every accepted stream has exactly one terminal per component with matching fingerprints, compatible byte counts/EOF observations, and an explicit terminal class.

### 4.5 Phase E — Extend same-process owner coverage

Files:

- `apps/p2x-server/tests/owner_pipeline.rs`
- focused client integration tests under `apps/p2x-client`
- `crates/p2x-net/tests/proxy_network.rs`

Steps:

1. Change the owner-pipeline selector to TCP and construct an immutable loopback `LocalUpstream`.
2. Pass the real exchange-issued ticket through verification, live owner validation, stream preflight/reserve, upstream connect, promotion, Accepted, opaque bytes, pump terminal, and release.
3. Replay the consumed ticket and prove no second upstream connection is created.
4. Add table-driven failure injection at decision loss, dial refusal/timeout, promotion loss, Accepted write failure, idle, I/O reset, and shutdown.
5. Assert replay, behavior, admission, task, and socket counts after every branch.

Phase gate: the same-process test proves the actual Plan 06 owner path rather than only protocol framing or ticket authorization.

### 4.6 Phase F — Replace representative tunnel evidence with exact subcases

Files:

- `tests/tunnel/live.py`
- `tests/tunnel/local.sh`
- `tests/tunnel/README.md`
- `tests/resolution/local.sh`

Implement these explicit additions:

| Case/subcase | Required executable assertion |
| --- | --- |
| `per-ingress-failure-recovery` | Resolve/path/upstream/client-capacity failures close only one local socket; the same daemon later carries opaque bytes. |
| `stream-limits/client-ingress` | Exactly `N` local sockets are admitted, `N+1` is rejected before route work, existing streams progress, and released capacity is reused. |
| `stream-limits/client-server` | Active plus pending reaches the configured per-server `N`; `N+1` is rejected locally without daemon exit. |
| `stream-limits/server-global` | Global worker `N/N+1` is isolated from per-client/service/dial limits. |
| `stream-limits/server-client` | One client reaches its exact limit while another authenticated client still succeeds. |
| `stream-limits/server-service` | Service `N/N+1` rejects before an extra upstream socket and reuses released capacity. |
| `stream-limits/server-dial` | Held dials reach exact `N`; `N+1` rejects before replay consume and all dial entries drain. |
| `shutdown/client-setup` | Client shutdown cancels a held setup, stops new ingress, and leaves zero ingress/route/path/handshake owners. |
| `shutdown/client-active` | Client shutdown cancels an accepted tunnel and emits explicit cancelled terminals/resources. |
| `shutdown/server-dial` | Server shutdown interrupts a held dial inside five seconds, preserves consumed replay semantics, and drains behavior/admission/task counts. |
| `shutdown/server-active` | Server shutdown cancels an accepted pump, rejects new streams as draining, and emits final zero resources. |
| `idle-timeout` | Server emits `upstream.idle_timeout` plus `idle_timeout` terminal class, while a concurrent non-idle stream continues. |
| `deadline-stages` | Deterministically hold resolve, relay dial, direct preference, exact open, verification, owner decision, and upstream dial; each remains under the original client accept deadline. |
| `terminal-correlation` | For each accepted stream, client/server request and stream hashes match; exactly one terminal per side exists and endpoint-observed bytes agree with directional counters. |
| `resource-baseline` | The 128-stream profile records before/peak/after RSS, FDs, ingress, route, behavior, task, dial, service, active, and replay counts and returns within declared tolerance. |

Update the privacy scan to include fresh credential values, raw ticket/session markers, selector keys and values, upstream ID, configured upstream address, and a run-random payload sentinel. Fail if any marker appears in any component output or summary artifact.

Do not set summary booleans from the case name. Construct `observed_assertions` only from assertions that actually ran, and fail if a required assertion key is absent.

For resolution `concurrent-opens`, add either:

- a deterministic guarded barrier that holds exactly 64 owner entries before release; or
- a synchronous owner high-water lifecycle event emitted on every count transition.

Assert the authoritative high-water value rather than hoping the one-second periodic sampler observes the peak.

Phase gate: `--case all` is deterministic across at least three consecutive runs and each summary maps to concrete event/endpoint assertions.

### 4.7 Phase G — Documentation and final closure

Update after the executable gates pass:

- `docs/protocol/proxy-v1.md`: remove the stale Open-side EOF requirement; state that Open is one flushed frame, server reads no application payload before admission, and opaque bytes begin only after Accepted;
- `docs/operations/client-connections.md`: document per-ingress nonfatal failure behavior, immediate pre-Accept EOF cancellation, exact per-server totals, and terminal classes;
- `docs/operations/server-availability.md` and `docs/operations/raw-tcp-tunnels.md`: document the worker deadline, clipped connect timeout, shutdown cancellation, and final resource evidence;
- `docs/security/identity-and-credentials.md`: document fresh time recheck and collision-safe capacity-before-consume ordering;
- `tests/tunnel/README.md`, `tests/resolution/README.md`, and `tests/README.md`: list the exact automated subcases and retain the owner-executed platform remainder as incomplete.

Create a Plan 06a run log under `rlogs/` containing commands, exit statuses, artifact paths, and the still-manual §5.5 gates. Do not mark a manual gate complete from local loopback evidence.

## 5. Required Validation Sequence

Run these gates from a clean worktree after each focused test group passes:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
cargo tree -e features
git diff --check

./tests/tunnel/local.sh --case all
./tests/resolution/local.sh --case all
./tests/auth/local.sh --case all
./tests/registry/local.sh --case all
./tests/connectivity/local.sh --case all
```

Also run bounded fuzz checks for the proxy frame codec and any changed lifecycle/config parser corpus. Record toolchain, duration, and artifact paths in the Plan 06a run log.

The tunnel and resolution suites must each pass three consecutive `--case all` runs before closure because the review observed a timing-dependent full-suite failure that an isolated rerun concealed.

## 6. Definition of Done

Plan 06a is complete only when:

- a resolve, path, proxy, capacity, connection, deadline, or upstream failure for one product ingress cannot stop the client daemon or disturb unrelated active streams;
- local EOF/error before Accepted immediately cancels the exact setup and cannot proceed to a later ticket consume/upstream dial;
- the configured active-plus-pending per-server limit is enforced literally for all valid configurations;
- server Open verification, owner wait, upstream dial, promotion, and Accepted write are bounded by one worker deadline and cancellable on shutdown;
- ticket time is current at authorization, an admission collision preserves the prior entry, and every release is exactly once;
- both components emit one fully classified, correlated terminal per accepted tunnel and final resource records are zero after drain;
- same-process coverage passes a real exchange ticket through immutable upstream connect, Accepted, bytes, replay rejection, and cleanup;
- each client/server limit and shutdown stage has an independent real-process `N/N+1` or cancellation subcase;
- privacy scans include payload, selector, upstream ID/address, session/ticket, credentials, and key markers;
- tunnel and resolution full suites pass three consecutive runs, and all auth/registry/connectivity plus Rust static/test gates pass;
- protocol and operations documents match the tested flush-without-close/Accepted behavior;
- Plan 06 §5.5 owner-executed platform/topology/soak work is either completed with artifacts or remains explicitly marked incomplete without blocking this locally automatable closure.

## 7. Suggested Commit Sequence

1. `Fix product ingress failure isolation`
2. `Enforce client ingress and per-server ownership`
3. `Bound server proxy setup and shutdown`
4. `Make stream admission collision safe`
5. `Complete tunnel lifecycle and pump coverage`
6. `Extend raw tunnel owner pipeline tests`
7. `Close tunnel limit shutdown and privacy gates`
8. `Stabilize concurrent resolution evidence`
9. `Document and certify Plan 06a closure`
