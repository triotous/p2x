# Remediation Plan: Make the Raw TCP Tunnel Phase Gate Honest and Complete

- **Document status:** implementation-ready
- **Scope:** corrective follow-up to [`06-raw-tcp-proxy-tunnel.md`](06-raw-tcp-proxy-tunnel.md) and [`06a-raw-tcp-tunnel-executable-closure.md`](06a-raw-tcp-tunnel-executable-closure.md)
- **Baseline reviewed:** `feat/06-raw-tcp-proxy-tunnel` at `0e2ccfb`
- **Phase decision:** **Plan 07 is blocked** until the locally automatable Definition of Done in §7 passes
- **Required outcome:** preserve the working direct/relay raw TCP data path, but close the remaining product-owner failure paths, make server worker completion impossible to lose or outlive its deadline, preserve immutable Accepted lifecycle data, and replace representative or synthetic-green tunnel assertions with the exact executable evidence claimed by Plans 06/06a

## 1. Review Result and Scope

The current branch has a functional raw TCP tunnel. The Rust workspace, all 14 currently named tunnel cases, all 20 resolution cases, and the auth/registry/connectivity regressions pass. The resolution owner high-water correction is also present and deterministic.

The branch is not eligible for Plan 07, however. Expected product route-admission errors can still escape `p2x-client` as process-level `io::Error`; several rejection paths bypass the centralized cleanup and leave per-ingress state or same-selector resolver waiters behind; server promotion, Accepted-event, and release delivery can block without the worker deadline or lose the only release; and the tunnel runner still reports privacy, terminal, limit, shutdown, and headroom assertions that it did not execute.

This plan addresses only those remaining Phase 4 closure defects. It does not implement HTTP Host routing, TLS SNI routing, DNS upstreams, dashboards, deployment packaging, final SLO tuning, or active-stream resumption.

### 1.1 Verification completed during this review

| Check | Review result |
| --- | --- |
| Clean baseline | passed before review at `0e2ccfb`; only this Plan 06b document is added by the review |
| `cargo fmt --all -- --check` | passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-targets --all-features` | passed when rerun with loopback socket permission; the restricted sandbox run failed only at listener bind with `Operation not permitted` |
| `cargo deny check` | passed; duplicate-version findings remain warnings |
| `cargo tree -e features` | passed |
| `git diff --check` | passed before this document was added |
| `./tests/tunnel/local.sh --case all` | all 14 current cases passed, but the runner inspection found unexecuted/overstated assertions described below |
| `./tests/resolution/local.sh --case all` | all 20 cases passed, including authoritative 64-open high-water evidence |
| `./tests/auth/local.sh --case all` | passed |
| `./tests/registry/local.sh --case all` | passed |
| `./tests/connectivity/local.sh --case all` | C01 and C05-C13 passed, including 64/128 connectivity probes |
| Plan 06 §5.5 owner-executed gates | still incomplete: namespace/firewall, cross-host/NAT, native/container matrix, and long soak remain correctly separated from local automation |

### 1.2 Confirmed remaining gaps

| Priority | Confirmed current behavior | Required correction |
| --- | --- | --- |
| P0 | In `apps/p2x-client/src/main.rs`, the product resolve-success branch converts `ConnectionManager::begin_path_at_deadline_with_capabilities` capacity/deadline errors into `io::Error`; failed waiter tracking, metadata update, and route-path insertion also return from `main`. At least the capacity/deadline cases are expected per-ingress failures, not daemon failures. | Route every attributable path-admission outcome through one product completion transaction. Only an ownership invariant that cannot be tied to a current ingress may terminate the process. |
| P0 | Product proxy rejection still has a custom branch that removes only `open_by_ingress` and the command sender. It does not remove/cancel every ingress record, emit `IngressRejected`, or promote the next same-selector resolver waiter. Other cancellation paths call `resolver.cancel` without calling `RouteOpenSupervisor::promote_waiters`. | Remove custom rejection cleanup. Make one helper own route completion, resolver cancellation/promotion, connection-manager release, ingress rejection, and all generation maps. |
| P0 | `proxy_open::run_worker` bounds candidate send and decision wait, but `promotions.send(...).await`, the promotion acknowledgement wait, `accepts.send(...).await`, and `releases.send(...).await` are not all bounded by the five-second worker deadline/cancellation. A full or abandoned channel can retain the socket/admission indefinitely; release delivery is best effort even though it is the only owner release. | Track proxy workers in the server owner, bound every pre-Accept transition by the same deadline, reserve Accepted evidence before writing Accepted, and make completion/release owner-driven even when a task panics or its channel closes. |
| P1 | `ingress_started` is inserted before route/auth/admission checks but is removed only after `TunnelFinished`. Auth-not-ready, route rejection, admission rejection, pre-Accept close, and proxy rejection can retain one timestamp entry per local connection indefinitely. Parallel maps make it easy for cleanup paths to remove different subsets. | Replace parallel ingress maps with one setup owner record and one active record; every terminal transition must `remove` the whole record exactly once. Add high-water/current-count evidence and repeated-failure tests. |
| P1 | After wire Accepted, a failed `StartTunnel` command removes active accounting but emits no client tunnel terminal. Client and server terminal `setup_duration_ms` are recomputed at terminal time, and selected path is looked up from mutable connection state; shutdown synthesizes zero-duration/zero-byte terminals. A direct path removed before terminal can be reported as relay/absent. | Freeze setup duration and selected path at Accepted, store them in the active owner, and use the immutable values for the one terminal. An Accepted handoff failure must emit `cancelled` and release exactly once. |
| P1 | `ingress::run_connection` converts an unexpected pump `io::Error` into a zero-byte `Cancelled` result. Server pump errors are discarded with `.ok()`. The pump test suite has no deterministic local/remote read/write failure matrix, activity-reset test, blocked-writer idle case, cancellation variants, or task/socket drop proof; the fairness test does not prove the heartbeat overlapped active hot-copy work. | Preserve or eliminate impossible pump setup errors explicitly, complete the deterministic pump matrix, and make fairness/no-survivor assertions causally synchronized. |
| P1 | `apps/p2x-server/tests/owner_pipeline.rs` manually calls the ledger, stream admission, connector, codec, and pump. It does not invoke the owner decision code in `apps/p2x-server/src/main.rs` or `proxy_open::run_worker`, and has only the happy path plus replay. | Extract the production proxy owner transition into a testable library owner and drive the same implementation through success and every failure/release boundary. |
| P1 | Stream-ID collision now preserves the prior `StreamAdmission` entry, but reservation happens before replay consumption, so the collision rejection leaves the presented one-use ticket unconsumed. Plan 06a required collision to be terminal for that ticket without retrying stream-ID allocation. | Put preflight, allocation, consume, and collision-safe reserve in one synchronous owner transition; a collision preserves the old entry, consumes the presented ticket once, and a replay is rejected. |
| P1 | `tests/tunnel/live.py` has one service-limit-oriented `stream-limits` path, one active client-then-server shutdown path, 64 concurrent streams only, no per-ingress recovery case, no deadline-stage matrix, no independent client/server setup/active shutdown cases, and no 128-stream tunnel resource profile. Idle timeout does not prove unrelated traffic continues. | Implement the explicit subcases in §3.6 and require their observed owner transitions, endpoint results, and final counts. |
| P1 | The runner generates `run.payload_sentinel` but scans a stale constant string instead. Selector/upstream privacy markers use YAML-like strings rather than fresh run values. The unused `one_terminal` helper is never called; after shutdown the runner only waits for a terminal and writes `one_terminal_each: true`. Final resource assertions are optional when no resource row exists. | Use fresh run-random private values and scan their exact values; require exactly one process terminal for every process, exactly one tunnel terminal per Accepted per side, and a mandatory final zero-resource record. Construct summary booleans only from executed assertions. |
| P1 | The large-stream resource check samples only client RSS/FD min/max while processes are live, declares only four buffers, and does not establish before/peak/after for client and server. The 64-stream case is documented as proving 128-stream headroom although it never opens 128 tunnels. | Add authoritative logical counts and before/peak/after RSS/FD samples for both components, exercise 64 sustained plus 128 headroom tunnels, and validate the complete client/server buffer formula. |
| P2 | Operations/test documentation says product failures are fully isolated, resolver waiters are promoted after cancellation, server shutdown emits final zero resources, privacy scans include the random payload sentinel, and concurrency proves 128 headroom. The reviewed code/runner does not yet prove those statements. | Correct the implementation and executable evidence first, then update documentation to the exact observed contract. |

## 2. Required Invariants

Plan 06b must preserve these working Phase 4 properties:

- fixed raw TCP listeners bind only validated nonzero loopback addresses and reference exactly one TCP selector;
- the setup deadline originates at local TCP `accept` and is never restarted by resolve, path selection, fresh-ticket retry, proxy Open, server admission, or upstream dial;
- the client sends no P2P application byte before a correlated `Accepted`;
- the server obtains the upstream socket address only from immutable local configuration and never emits that address, selector metadata, ticket/session material, credentials, or payload;
- ticket verification and current owner validation remain distinct; all capacity checks occur before replay consumption, and a consumed ticket is never restored after dial/write/cancel/shutdown failure;
- one active tunnel owns one ingress permit, one client active count, one server admission, one behavior admission, one worker task, and one socket pair until exactly one terminal release;
- active direct streams survive exchange-control loss; selected path loss resets only affected streams and never replays application bytes;
- the proxy pump uses one fixed buffer per direction, counts only successful writes, propagates each half-close independently, and applies idle timeout only on the server;
- expected failure of one local ingress cannot emit a process terminal, stop listeners, alter unrelated active owners, or strand a same-selector waiter;
- owner-executed Plan 06 §5.5 evidence remains explicitly incomplete until run and is never inferred from loopback automation.

## 3. Required Design Corrections

### 3.1 One client ingress/setup owner and one completion transaction

Replace the parallel `ingress_by_id`, `ingress_route`, `ingress_cancel`, and `ingress_started` maps with records equivalent to:

```text
IngressSetupOwner {
    ingress_id,
    route_id,
    accepted_at,
    deadline,
    command,
    cancel,
    open_id: optional,
}

ActiveTunnelOwner {
    ingress_id,
    open_id,
    server,
    connection,
    request_id_hash,
    stream_id_hash,
    selected_path,
    setup_duration,
    cancel,
}
```

Keep one `OpenId -> IngressId` index for reverse correlation, but store all ingress-owned values in exactly one setup or active record. A record may move from setup to active; it may not exist in both.

Introduce one product completion function with a closed source enum:

```text
finish_product_open(
    open_id,
    result: Result<(), PublicErrorCode>,
    source: resolve | path | proxy | connection | ingress | deadline | shutdown,
) -> Vec<RouteAction>
```

For an expected failure it must, in this order:

1. verify that `OpenId -> IngressId` still names the same live setup generation; ignore a late event for a removed generation;
2. remove matching resolve wire and proxy request indexes and cancel the exact behavior request where supported;
3. call `RouteOpenSupervisor::complete` or `cancel` exactly once and remove its setup owner;
4. call `ResolverState::cancel` for the exact request, then immediately append `RouteOpenSupervisor::promote_waiters` actions so the next FIFO same-selector waiter reaches the wire;
5. release the exact connection-manager waiter/pending owner when one was acquired, checking the transition instead of silently returning;
6. take the complete `IngressSetupOwner`, cancel its token, send `IngressCommand::Reject`, and emit one `IngressRejected` with its real route hash and stable code;
7. continue the product event loop without a process terminal.

Use the same transaction for resolve timeout/rejection, path admission/timeout/failure, proxy rejection/worker failure, selected setup connection loss, pre-Accept EOF/I/O, deadline, and shutdown-before-Accept. Delete the custom proxy-error and pre-Accept cleanup loops after they delegate to this function.

In the resolve-success branch, handle `ConnectionManager::begin_path_at_deadline_with_capabilities` as an attributable route result. `LimitPeerConnections`, `LimitProxyStreams`, and `PeerSetupTimeout` complete only that ingress. A missing owner after a successful checked transition remains an invariant error and may terminate the daemon, but must include the current `OpenId` in an internal diagnostic and must not be used for normal capacity.

Add setup owner `len` and high-water accessors for tests/lifecycle. Repeated auth-not-ready or route-limit connections must leave setup/active/open/resolver/manager counts at zero and must not grow memory-owned maps.

### 3.2 Transactional Accepted handoff and immutable lifecycle context

Make client handoff one checked transition:

1. load the current setup owner, selected connection/path, route owner, proxy request, and manager pending owner without removing any of them;
2. compute `setup_duration = accepted_at.elapsed()` once and freeze selected path from the accepted connection record;
3. promote manager pending-to-active and remove the route setup owner using checked methods;
4. move the setup record into `ActiveTunnelOwner`;
5. emit `TunnelAccepted` from that immutable active record;
6. send `StartTunnel` to the ingress task.

If step 6 fails after wire Accepted, emit exactly one client `TunnelTerminal` with `accepted: true`, `terminal_class: cancelled`, frozen path/setup duration, and zero counters only because no pump started; then release active/ingress ownership. Do not convert it into `IngressRejected`, and do not leave the server-side Accepted stream without a correlated client terminal.

On normal terminal, connection loss, and shutdown, use the active record's frozen `selected_path` and `setup_duration`. Never derive them from a connection book that may already have removed the connection. Pump `duration_ms` remains separate from setup duration.

Change `IngressEvent::TunnelFinished` to carry `Result<PumpResult, PumpFailure>` or make validated pump construction infallible. Do not synthesize `Cancelled` from an unrelated error. Map a real runtime I/O terminal from `PumpResult`; reserve an internal invariant terminal for impossible buffer/config construction failures.

### 3.3 Deadline-bounded and owner-guaranteed server workers

Move server proxy task ownership into a `JoinSet` or equivalent owner table keyed by a new `ProxyWorkerId`. The server owner must know, for every spawned worker, its peer, connection, behavior admission, optional stream admission token, request/stream hashes, and whether Accepted was written. Derive `proxy_workers` from this table; remove both `saturating_sub` sites.

Change the worker/owner protocol as follows:

- add `worker_id` to `Candidate` and `Promotion` so the owner can attach the reserved `AdmissionToken` to the correct task before returning `Admit`;
- make candidate send, decision wait, promotion send, and promotion acknowledgement all select against both shutdown and the same absolute `worker_deadline`;
- before writing Accepted, reserve capacity for the server Accepted lifecycle event under the remaining worker deadline; if the event cannot be guaranteed, close/reject without writing Accepted and release the admission;
- send the reserved Accepted event immediately after the wire write succeeds, then begin the pump without waiting on an unbounded telemetry channel;
- return a `WorkerOutcome` from the task instead of best-effort `releases.send(...).await`; the owner processes the join result and releases behavior/stream admission even if the worker returns an error or panics;
- retain the owner table as the recovery source if a join error has no `WorkerOutcome`;
- distinguish connector cancellation from timeout so shutdown produces drain/cancel evidence rather than `upstream.connect_timeout`;
- store `setup_duration` at Accepted; do not replace it with `started.elapsed()` after a long-lived pump.

During shutdown:

1. mark behavior draining before cancelling workers and reject new candidates as `peer.draining`;
2. cancel every worker token;
3. continue processing candidates, promotions, reserved Accepted events, and `JoinSet` completions until the owner table is empty or the five-second drain deadline expires;
4. if the deadline expires, abort and await each remaining task, then release from its owner-table record and emit an explicit cancelled terminal for every known Accepted stream;
5. assert behavior inbound count, worker table, stream admission dialing/active counts, and event channels are zero;
6. emit one mandatory final `Resources` record with zero logical workers/tasks/pending opens before the process terminal.

Do not call `proxy_admission.clear()` to make leaked entries appear drained. A nonempty admission after all task joins is an invariant failure that the focused tests must expose.

### 3.4 Complete pump outcome and scheduler coverage

Add deterministic I/O doubles under `crates/p2x-proxy` that can fail one configured read, write, or close and that expose drop counters. Cover at least:

- clean two-way EOF and response continuation after local half-close;
- the symmetric remote-half-close case;
- idle reset by successful local-to-remote writes and by successful remote-to-local writes;
- a blocked writer reaching idle timeout without allocating beyond its fixed direction buffer;
- local read failure and local-to-remote write failure with exact committed byte counts and `LocalIo`;
- remote read failure and remote-to-local write failure with exact committed byte counts and `RemoteIo`;
- cancellation while both reads are pending;
- cancellation while one writer is blocked and the reverse direction is active;
- both I/O objects and all spawned helpers dropped after clean, idle, I/O, and cancellation completion;
- a hot transfer that is known to be in progress before a separate heartbeat starts, with the heartbeat completing before the hot transfer is released/finished.

Use barriers/notifies and bounded Tokio timeouts rather than sleeps as the causal assertion. If an I/O error can occur after partial progress, `PumpResult` must preserve the already committed counters and EOF flags.

### 3.5 Put the production server owner under same-process tests

Extract the candidate-to-decision logic currently embedded in `apps/p2x-server/src/main.rs` into a library owner, for example `ServerProxyOwner`, that owns `TicketAdmissionLedger`, `StreamAdmission`, immutable service lookup, current registration/auth context input, and worker-to-admission correlation. The binary remains the sole swarm executor and calls this owner synchronously.

The owner API must expose checked methods equivalent to:

```text
decide(worker_id, candidate, current_context, now) -> ServerDecision
promote(worker_id, admission) -> Result<(), OwnerError>
complete(worker_id, outcome) -> ReleaseSummary
cancel(worker_id) -> ReleaseSummary
snapshot() -> { workers, dialing, active, per_peer, per_service, replay }
```

The admission transaction must execute synchronously in the owner as: validate current context and ticket time, preflight replay/capacity, allocate one stream ID, consume the ticket, then reserve the collision-safe stream entry. Because the owner does not interleave another mutation between these steps, the earlier preflight remains authoritative. If the generated ID collides, reject without replacing the prior entry, do not allocate a second ID, and keep the presented ticket consumed.

Update `owner_pipeline.rs` to call this production owner rather than recreating its ordering manually. Drive the exchange-issued ticket through the actual decision, immutable upstream, promotion, Accepted codec, opaque pump, completion, and replay rejection. Add table-driven cases for:

- invalid/stale current auth, service, revision, time, and ticket bindings before consume;
- replay full/replayed, global worker, per-client, per-service, and dial rejection before consume;
- stream-ID collision preserving the prior live entry, consuming the presented ticket, and rejecting its replay without allocating a second stream ID;
- decision receiver loss after reserve;
- dial refusal, dial timeout, and dial cancellation;
- promotion channel loss, missing token, duplicate promotion, and stale worker ID;
- Accepted-event reservation failure and Accepted write failure;
- clean, idle, local I/O, remote I/O, cancellation, selected connection loss, and shutdown pump terminals;
- task panic/join error and duplicate/late completion;
- zero owner/admission/socket/task counts after every row.

### 3.6 Replace representative tunnel evidence with exact subcases

Keep `./tests/tunnel/local.sh --case <name|all>` as the canonical entry point, but add explicit case names or named subcases whose summaries prove each requirement independently.

| Case/subcase | Required executable assertion |
| --- | --- |
| `per-ingress-failure-recovery/resolve` | One resolve rejection closes one local socket, leaves the daemon/listener alive, promotes a queued same-selector ingress, and a later ingress succeeds. |
| `per-ingress-failure-recovery/path-capacity` | Exact client path/pending capacity N/N+1 rejects only N+1 without a process terminal; released capacity is reused. |
| `per-ingress-failure-recovery/upstream` | A consumed-ticket upstream failure closes only the failed ingress; after the run-scoped service fixture becomes healthy, the same client/server processes carry a later ingress. |
| `per-ingress-failure-recovery/pre-accept-eof` | Local EOF cancels the exact Open before later ticket consume/dial and promotes the next same-selector waiter. |
| `stream-limits/client-ingress` | Exact configured ingress N is held, N+1 creates no route owner, existing streams progress, and released capacity is reused. |
| `stream-limits/client-server` | Client pending plus active reaches `max_streams_per_server`; N+1 is local-only and the daemon survives. |
| `stream-limits/server-global` | Global stream admission N/N+1 is isolated from the larger per-client/service/dial limits. |
| `stream-limits/server-client` | One authenticated client reaches N while a second client still succeeds. |
| `stream-limits/server-service` | Service N/N+1 creates no extra upstream connection and reuses released capacity. |
| `stream-limits/server-dial` | Held dials reach exact N, N+1 is rejected before consume, and dialing entries return to zero. |
| `shutdown/client-setup` | Client shutdown cancels a held resolve/path/proxy setup and ends with zero setup/open/waiter/manager owners. |
| `shutdown/client-active` | Client shutdown emits one cancelled terminal for each Accepted tunnel and zero active/ingress owners. |
| `shutdown/server-setup` | Server shutdown interrupts held verification/decision/dial inside five seconds, rejects new Open, and drains owner/behavior/admission tasks. |
| `shutdown/server-active` | Server shutdown cancels Accepted pumps, emits one terminal each, rejects new streams as draining, and emits mandatory final zero resources. |
| `idle-timeout` | One idle stream terminates with `upstream.idle_timeout` while a concurrent non-idle stream continues within its latency bound. |
| `deadline-stages` | Deterministic barriers hold resolve, relay dial, direct preference, exact Open, verification, owner decision, promotion, and upstream dial; each result remains under the original client accept deadline. |
| `terminal-correlation` | Request/stream/connection hashes, side, frozen path, frozen setup duration, terminal class, EOF, and directional counters are compatible on both components and with endpoint-observed bytes. |
| `concurrent-streams/64-sustained` | 64 tunnels remain Accepted simultaneously behind a barrier before transfer/release; all have unique upstream sockets/substreams. |
| `concurrent-streams/128-headroom` | 128 tunnels are actually opened and completed under the configured headroom; no documentation infers this from a 64-stream run. |
| `resource-baseline/128` | Before/peak/after RSS, FDs, setup/active owners, behavior admissions, worker tasks, dials, services, and replay counts are captured for both client and server and return within declared tolerance. |

For resource accounting, calculate and record the complete formula per active tunnel: two configured direction buffers in the client pump plus two in the server pump, plus at most one client pre-Accept buffer while setup is pending. Kernel/libp2p overhead uses a separately declared measured RSS tolerance; do not label four total buffers as the whole two-component budget.

Make every run-scoped private marker random, including selector metadata key/value, upstream ID, credential values, ticket/session sentinels where observable to the fixture, upstream address, and payload sentinel. Scan the exact generated values in all process NDJSON and summary artifacts. Do not scan an unrelated hard-coded prefix and report the generated sentinel clean.

After stopping processes, call the exact-one helper for client, server, and every exchange instance. Require:

- exactly one process `terminal` per process log;
- exactly one `tunnel_terminal` per `tunnel_accepted` on each component;
- no terminal for an unaccepted stream;
- one mandatory last resource record with all relevant logical fields zero;
- no remaining P2X process or fixture socket owned by the run.

Build `observed_assertions` from named assertion functions that returned successfully. A summary must fail if a required case assertion key is absent. Never assign `privacy_scan_clean`, `one_terminal_each`, `resources_drained`, `128_headroom`, or a case-specific boolean as an unconditional literal.

### 3.7 Correct documentation and closure records last

Only after the new executable gates pass, update:

- `docs/operations/client-connections.md`: actual product completion transaction, waiter promotion, immutable Accepted lifecycle, and exact setup/active count evidence;
- `docs/operations/server-availability.md`: owner-tracked workers, bounded promotion, guaranteed completion, cancellation classification, and mandatory final zero resources;
- `docs/operations/raw-tcp-tunnels.md`: exact local case/subcase matrix and 64/128 behavior;
- `docs/security/identity-and-credentials.md`: final collision/consume decision and run-random privacy evidence;
- `tests/tunnel/README.md` and `tests/README.md`: assertion-derived summaries, complete privacy markers, resource formula, and owner-executed remainder.

Create an append-only `rlogs/06b-raw-tcp-tunnel-phase-gate-closure__<timestamp>.rlog` with commands, exit statuses, focused test names, three-run artifact paths, and the still-incomplete Plan 06 §5.5 gates. Do not edit Plans 06/06a to hide the review result.

## 4. Ordered Implementation Plan

### 4.1 Phase A — Consolidate client ingress ownership

Files:

- `apps/p2x-client/src/main.rs`
- `apps/p2x-client/src/route_open.rs`
- `apps/p2x-client/src/resolver.rs`
- focused client unit/integration tests

Steps:

1. Add `IngressSetupOwner`, `ActiveTunnelOwner`, and the reverse Open index.
2. Implement `finish_product_open` and make it return resolver waiter-promotion actions.
3. Route product path-admission capacity/deadline errors through the helper instead of `?`.
4. Replace proxy rejection and pre-Accept custom cleanup with the helper.
5. Make route/manager release checked and generation-specific.
6. Add repeated auth-not-ready, path-limit, proxy-reject, EOF, timeout, and same-selector queue tests.

Phase gate: 10,000 sequential rejected local ingresses and a bounded concurrent rejection run leave all client logical owner counts at zero, keep the process alive, and permit a later successful tunnel.

### 4.2 Phase B — Make Accepted handoff and lifecycle exact

Files:

- `apps/p2x-client/src/main.rs`
- `apps/p2x-client/src/ingress.rs`
- `crates/p2x-net/src/lifecycle.rs`

Steps:

1. Make pending-to-active handoff a checked transaction.
2. Freeze selected path and setup duration in `ActiveTunnelOwner`.
3. Emit a cancelled terminal when the post-Accept ingress command cannot be delivered.
4. Preserve pump construction/runtime failures instead of synthesizing cancellation.
5. Use the immutable active record for normal, connection-loss, and shutdown terminals.

Phase gate: every client Accepted record has exactly one terminal with identical path/setup duration and one active release, including command-loss and shutdown branches.

### 4.3 Phase C — Own server tasks and bound every transition

Files:

- `apps/p2x-server/src/main.rs`
- `apps/p2x-server/src/proxy_open.rs`
- `apps/p2x-server/src/upstream.rs`
- `apps/p2x-server/src/stream_admission.rs`

Steps:

1. Add `ProxyWorkerId`, owner table, and `JoinSet` completion.
2. Attach admission tokens to worker IDs in the owner before returning Admit.
3. Bound promotion send and acknowledgement by the existing worker deadline and shutdown.
4. Reserve Accepted-event capacity before wire Accepted.
5. Return worker outcomes through task join; remove best-effort release send and saturating counts.
6. Distinguish cancellation from connect timeout.
7. Drain/abort-and-await workers with checked releases and mandatory final zero resources.

Phase gate: a deliberately full candidate/promotion/Accepted channel, dropped decision receiver, worker panic, held dial, and shutdown all finish within the declared bound with zero owner/admission/behavior counts.

### 4.4 Phase D — Complete pump and owner same-process coverage

Files:

- `crates/p2x-proxy/src/lib.rs`
- new test support beside the pump module
- extracted `p2x-server` proxy owner module
- `apps/p2x-server/tests/owner_pipeline.rs`

Steps:

1. Add deterministic failing/blocking/drop-observed I/O doubles.
2. Implement the complete pump matrix in §3.4.
3. Extract and use the production `ServerProxyOwner` from the binary.
4. Rewrite the owner pipeline to use that owner.
5. Add the table-driven owner failure/release matrix in §3.5.

Phase gate: every pump terminal and every server owner transition has exact counter/release assertions; the integration test no longer duplicates production admission order.

### 4.5 Phase E — Make the real-process gate exact

Files:

- `tests/tunnel/live.py`
- `tests/tunnel/local.sh`
- optional focused helper modules under `tests/tunnel/`

Steps:

1. Add the per-ingress, limit, shutdown, deadline, correlation, 64/128, and resource subcases from §3.6.
2. Add deterministic barriers/high-water events instead of periodic-sample guesses for exact ownership peaks.
3. Make selectors/upstream IDs/payload markers run-random and scan their exact values.
4. Invoke exact process/tunnel terminal cardinality checks.
5. Require final zero resource records, process cleanup, and endpoint-observed counters.
6. Construct summaries exclusively from executed assertion functions.

Phase gate: each subcase fails when its defining assertion is locally disabled, and `--case all` passes three consecutive runs without changing thresholds or rerunning isolated failures.

### 4.6 Phase F — Documentation and final phase certification

Files:

- the operations/security/test documents listed in §3.7
- new Plan 06b run log under `rlogs/`

Steps:

1. Update claims to the now-executable behavior and exact case names.
2. Run the validation sequence in §5 from a clean worktree.
3. Record commands, versions, durations, and artifact paths.
4. Record Plan 06 §5.5 as incomplete unless real owner artifacts exist.
5. Perform a final source review against every row in §1.2 before declaring Plan 07 eligible.

Phase gate: documentation, summaries, source ownership, and the run log describe the same verified behavior with no unconditional pass claims.

## 5. Required Validation Sequence

Run from a clean worktree after focused phase tests pass:

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

Also run:

- bounded fuzzing for every proxy frame target and any changed lifecycle/config parser target;
- the pump failure/cancellation matrix under Tokio's deterministic time where applicable;
- the tunnel and resolution `--case all` suites three consecutive times;
- a source scan proving no product expected-error branch maps a `PublicErrorCode` to top-level `io::Error` before passing through the product completion transaction;
- a source/summary scan proving no required observed assertion is assigned an unconditional `true`.

Restore any fuzz corpus change generated only by execution and remove Python bytecode/test processes before checking the final worktree.

## 6. Owner-Executed Remainder

Plan 06 §5.5 remains a separate owner-executed phase:

- Linux namespace direct/relay with firewall and traffic shaping;
- two-host real-network direct-capable and forced-relay topology;
- native Linux/macOS plus required container behavior;
- long-running 64-stream soak and 128-stream headroom with loss, reconnect, churn, RSS, and FD sampling.

Unavailable environments remain incomplete, not passed. Consistent with Plan 06, this remainder does not block locally automatable closure or Plan 07 once §7 is satisfied, but it must stay visible for the Phase 6 launch/operations gate.

## 7. Definition of Done and Plan 07 Gate

Plan 06b is complete, and Plan 07 may begin, only when:

- every expected resolve/path/proxy/capacity/connection/deadline/ingress failure completes one local ingress without returning from the product client main loop;
- one completion transaction removes the exact route, resolver, wire, manager, command, cancel, and ingress owner and promotes the next same-selector waiter;
- rejected/pre-Accept ingresses cannot grow any timestamp or auxiliary map;
- every server pre-Accept transition, including promotion send/ack and Accepted evidence reservation, obeys one five-second deadline and shutdown cancellation;
- server task completion and release are owner-guaranteed across normal return, channel loss, panic, abort, and shutdown; no `clear` or saturating decrement masks leaked ownership;
- Accepted path and setup duration are frozen, and each component emits exactly one classified terminal for every Accepted tunnel;
- pump tests cover both half-closes, both activity directions, blocked writer, four I/O failure directions, cancellation variants, fairness overlap, exact counters, and object/task drop;
- the same-process owner pipeline executes the production server owner rather than duplicating its logic;
- real-process cases independently prove per-ingress recovery, every client/server N/N+1 limit, every client/server setup/active shutdown stage, idle isolation, deadline stages, 64 sustained streams, actual 128 headroom, and before/peak/after resources;
- privacy scans use and detect exact run-random payload, selector, upstream, ticket/session, credential, and address values;
- every process terminal, tunnel terminal, final resource record, and summary boolean is derived from an executed assertion;
- static/Rust/fuzz gates pass, tunnel and resolution pass three consecutive full runs, and auth/registry/connectivity regressions pass;
- documentation and the Plan 06b run log match the executable evidence and continue to label owner-executed §5.5 work accurately.

Until every item above is true, the repository must not claim the Plan 06 phase gate complete and must not start Plan 07 domain ingress adapters on top of this tunnel core.

## 8. Suggested Commit Sequence

1. `Unify product ingress completion ownership`
2. `Make accepted tunnel lifecycle transactional`
3. `Own and bound server proxy workers`
4. `Complete pump failure and fairness coverage`
5. `Test the production server proxy owner`
6. `Add exact tunnel limit and shutdown subcases`
7. `Prove tunnel privacy correlation and resources`
8. `Document and certify Plan 06b closure`
