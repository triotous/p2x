# Remediation Plan: Close Plan 05 Resolution and Proxy Authorization Gaps

- **Document status:** implementation-ready
- **Scope:** corrective follow-up to [`05-resolution-tickets-and-peer-connection-manager.md`](05-resolution-tickets-and-peer-connection-manager.md)
- **Baseline reviewed:** `feat/05-resolution-tickets-and-peer-connection-manager` at `33f32ad`
- **Required outcome:** complete every locally automatable Plan 05 behavior and canonical process case, retain deployment-dependent checks for the final owner-executed phase, and produce enough executable evidence to decide whether Plan 06 may begin

## 1. Review Result and Scope

The implemented Plan 05 path successfully authenticates, resolves an exact tenant-scoped selector, issues a one-use signed ticket, selects an exact direct or relayed `ConnectionId`, and obtains one correlated empty-stream `Authorized` response. The supported TCP, QUIC, direct, relay, lookup-rejection, auth, registry, and connectivity regressions pass. The implementation is not yet eligible for Plan 06 because the canonical resolution runner explicitly reports 13 locally automatable cases as incomplete, and several product owners remain structured around a single finite open rather than the bounded concurrent/recovery behavior those cases must prove.

This remediation must finish Plan 05. It must not weaken a required case into a documentation-only assertion or reclassify a locally executable case as manual testing.

### 1.1 Verification completed during review

| Check | Review result |
| --- | --- |
| `cargo fmt --all -- --check` | passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-targets --all-features` | passed with loopback listener permission, including TCP/QUIC network tests |
| `cargo deny check` | passed; existing duplicate-version findings are warnings |
| `cargo tree -e features` | passed |
| Seven fuzz targets | completed bounded nightly libFuzzer runs without a crash |
| `tests/auth/local.sh --case all` | passed |
| `tests/registry/local.sh --case all` | passed with final exchange logical resources at zero |
| `tests/connectivity/local.sh --case all` | C01 and C05-C13 passed, including 64/128 probe concurrency, direct/relay transfer, renewal, and churn |
| Supported `tests/resolution/local.sh` cases | `resolve-ticket-tcp`, `resolve-ticket-quic`, `unknown-selector`, `offline-selector`, `cross-tenant`, `forced-relay`, and `direct-preferred` passed |
| Remaining resolution cases | runner returns status 2 before executing them |

The review also fixed one server gate defect in `7787b3d`: an Open must now be followed by client write-half closure, and an early application byte is rejected as `protocol.malformed` before authorization.

### 1.2 Confirmed completion gaps

| Priority | Confirmed current behavior | Required correction |
| --- | --- | --- |
| P0 | `tests/resolution/local.sh` lists 20 cases but its `SUPPORTED` map implements only seven. The other 13 return status 2 with an incomplete message. | Make every declared case executable and machine-asserted. `--case all` must execute all cases and return zero only when every case passes. |
| P0 | `apps/p2x-client/src/main.rs` owns one `resolve_request`, `proxy_open`, `proxy_attempt`, `pending_proxy`, deadline, and terminal. The finite diagnostic exits after one result. | Add a bounded route-open owner that can run sequential and concurrent logical opens, correlate each event independently, retry only under the Plan 05 rules, and keep the product swarm responsive. |
| P0 | `ResolverState` contains FIFO waiter and metadata/negative-cache seams, but the app dispatch does not drive `next_request()` after every terminal and does not exercise multiple waiters. | Integrate queue promotion, cancellation, session renewal, negative-cache short-circuiting, retransmission, and late-event rejection into the app owner. One logical waiter must receive exactly one ticket. |
| P0 | `ConnectionManager` is currently a connection-ledger wrapper. It does not own per-server relay dial/DCUtR generations, validated relay metadata/revision, joined waiters, or surplus-connection close actions. | Make it the bounded per-server setup owner required by Plan 05, with relay dial singleflight, stale-generation rejection, reuse, LRU eviction, direct preference, and explicit close commands. |
| P0 | After a proxy/path result, the client generally emits a terminal. It does not implement the one allowed fresh-ticket retry after an ambiguous/post-Open retryable failure. | Centralize retry classification and obtain a fresh resolve/ticket once when allowed and still inside the original absolute deadline. Never replay a ticket after Open bytes may have been written. |
| P0 | The server worker reads the Open, but `TicketAdmissionLedger::authorize_open` performs envelope decoding, Ed25519 verification, all binding checks, live recheck, replay consumption, and stream allocation synchronously in the swarm owner. | Split immutable cryptographic verification into the bounded worker and retain only live availability/service/revision recheck plus replay consumption in the single server owner. Stale worker snapshots must fail closed. |
| P0 | Replay validation has one unit test covering successful consume and immediate replay. It does not cover every binding, concurrent consume, expiry/skew retention, capacity recovery, or owner/worker cancellation. | Add exhaustive ticket-admission state tests and real product process evidence for replay, binding failure, expiry, revision replacement, saturation, and cleanup. |
| P1 | Resolution issuance has three unit tests. CSPRNG/signing failure, lifetime boundaries, authorization-before-replay, request-ID/body/session mismatch, deterministic capacity behavior, and live session/reservation races are not comprehensively covered. | Add injected randomness/signing seams and table/state tests for every Plan 05 issuance/idempotency invariant. |
| P1 | `crates/p2x-net/tests/resolve_network.rs` and `proxy_network.rs` prove synthetic protocol round trips but do not run authenticated exchange registry/ticket owners end to end. | Add same-process product integration tests that use real auth, registry, issuance, ticket verification, replay, and exact-open owners over TCP and QUIC. |
| P1 | `crates/p2x-protocol/testdata/resolve-v1.json` and `proxy-v1.json` are descriptive placeholders rather than byte-exact committed vectors, and neither protocol module verifies them. | Commit byte-exact non-production vectors and tests for every v1 request/response discriminant and framing boundary. |
| P1 | `fuzz/corpus/resolve_frame_decode/seed` and `proxy_frame_decode/seed` each contain only `01 00`. The proxy fuzz target calls domain decoders but not the raw-stream length-framing codec. | Commit valid and malformed corpus entries required by Plan 05 and fuzz both domain and framed codec paths with bounded allocation. |
| P1 | Resolve/proxy admission limits are mostly fixed constants, so canonical live `N`/`N+1` tests cannot lower limits or hold work deterministically. | Add validated limit configuration with Plan 05 defaults/hard maxima and narrowly scoped deterministic test hooks guarded by `P2X_ENABLE_TEST_HOOKS=1`. |
| P1 | Current lifecycle evidence does not expose all generations, retry/fallback state, response fingerprints, ticket issuance count, replay size, or resolve/proxy owner counts needed by the missing cases. | Add privacy-safe lifecycle fields/events and include resolve idempotency/admission plus proxy worker/replay ownership in final zero-resource assertions. |
| P2 | `tests/resolution/README.md` accurately admits incompleteness, but protocol/operations documentation cannot yet point to executable evidence for recovery, replay, reuse, concurrency, limits, or drain. | Update documentation only after the named cases pass; remove the incomplete-case language and map each claim to a test case. |

## 2. Goal, Boundaries, and Non-Goals

### 2.1 Required result

Complete the smallest coherent Plan 05 product and diagnostic ownership needed to prove:

1. resolve retransmission is byte-identical and issues one ticket;
2. a direct exact-open failure before Open bytes falls back once to the prepared relay connection;
3. tickets are one-use, binding-complete, time-bounded, and retained in replay state through expiry plus skew;
4. stale registration revisions fail closed and recover through a fresh resolve;
5. services on one server reuse connectivity while every open receives a distinct ticket and stream;
6. 64 concurrent opens and 128-open headroom are bounded and independently correlated;
7. resolve, proxy, worker, peer-pool, and replay limits enforce exact `N`/`N+1` behavior without starving auth or registry refresh;
8. the same client process recovers across exchange and server restart;
9. drain/cancellation releases every owner exactly once and never makes a consumed ticket reusable.

### 2.2 Preserve these Plan 05 invariants

- The one absolute setup deadline begins before resolve and is never extended by retransmission, dial, DCUtR preference, fallback, fresh-ticket retry, or handshake work.
- A ticket belongs to one logical open. Metadata and peer-connect work may be shared; ticket bytes may not be shared across waiters.
- A ticket may be reused only for the exact idempotent Resolve response or one pre-handshake exact-open relay fallback where no Open byte was written.
- Once Open bytes may have reached the server, any retry uses a fresh request ID and fresh ticket.
- Every proxy stream is opened through `NotifyHandler::One(connection_id)` on the selected `ConnectionId`.
- The server owner serializes live registration recheck and replay consume. Concurrent candidates for one ticket yield at most one `Authorized`.
- `Authorized` is an empty Phase 3 gate, not a usable tunnel. Neither side sends application bytes and the server never emits `Accepted` in this plan.
- No normal lifecycle record contains raw selector/metadata values, session IDs, ticket IDs/bytes, credentials, key material, or future private targets.
- Product and connectivity-lab protocol surfaces remain distinct; `/p2x/spike/1` cannot satisfy any Plan 05 case.

### 2.3 Non-goals

Do not add fixed TCP ingress, Host/SNI parsing, upstream sockets, `Accepted`, application byte copying, half-close propagation for application data, idle timeouts, load balancing, persistence, dynamic key/service/route reload, multiple exchanges, or a new crate/actor framework. Those remain Plan 06 or later work.

## 3. Required Ownership and Configuration

### 3.1 Bounded client route-open supervisor

Add a focused owner in `apps/p2x-client/src/route_open.rs` or extend `proxy_open.rs` if that keeps the module smaller. `main.rs` remains the sole `Swarm` executor and applies returned commands.

Each logical open must own:

```text
OpenId / route_id
selector and committed PrincipalBinding
resolve request ID and outbound request-response ID
AuthorizationGrant (move-only RawTicket)
server PeerId and expected registration revision
PathAttempt / exact proxy request ID / selected ConnectionId
absolute setup deadline
resolve retransmission count
fresh-ticket retry count
handshake_started boolean
terminal-delivered boolean
```

The owner must provide bounded actions such as `SendResolve`, `DialRelay`, `OpenExact`, `StartHandshakeWorker`, `CloseConnection`, `Complete`, and `Cancel`. Event handlers must locate an open by authoritative libp2p request ID, proxy request ID, connection generation, or worker ID; no global `Option` may accept an unrelated late event.

Required behavior:

- Admit configured global/per-server limits before allocating an open.
- Enqueue same-selector waiters in `ResolverState`; after every completion/cancellation, call `next_request()` until no newly promoted request is ready.
- Consult the one-second negative cache before sending new work. Positive metadata may seed peer connection reuse but never removes the need for a fresh ticket.
- Retransmit the exact Resolve body/request ID once on timeout. A changed session/body creates a fresh request ID.
- If a retryable failure occurs after handshake ownership is ambiguous, discard the old grant, invalidate only the affected metadata/peer state, resolve once for a fresh ticket, and continue under the same deadline.
- Emit exactly one terminal per logical open, then release resolver, connection-manager, proxy behavior, worker, and ticket ownership exactly once.
- The finite diagnostic may aggregate multiple per-open results into one final process terminal, but normal product ownership must remain long-running until shutdown.

For canonical tests, extend the finite diagnostic with validated hidden options, enabled only when `P2X_ENABLE_TEST_HOOKS=1`:

```text
--test-proxy-open-count <1..=128>
--test-proxy-concurrency <1..=128>
--test-delay-after-resolve-ms <0..=10000>
--test-replay-first-ticket
--test-open-mutation <none|ticket-byte|upstream-id|revision>
--test-fail-first-direct-open-before-handshake
--test-hold-proxy-handshake-ms <0..=10000>
```

These options control only the finite diagnostic and must not alter normal product defaults. Invalid combinations fail before listeners or credential access.

### 3.2 Resolver completion and idempotency

Update `apps/p2x-client/src/resolver.rs` and its app integration:

- Give every waiter an explicit state and terminal outcome; queued and wire-owned requests together remain within 128 globally and 64 per selector.
- Promote FIFO waiters immediately after the prior terminal, including rejection and cancellation.
- Preserve metadata on session-ID-only renewal with identical `PrincipalBinding`; cancel/restart wire work with fresh request IDs. Clear metadata, negatives, and pending work on binding change.
- Short-circuit valid negative cache entries without allocating a libp2p outbound request.
- Reject responses after deadline, for a non-current outbound owner, wrong session/binding/selector, or cancelled waiter.
- Add deterministic clock injection for positive/negative expiry tests; avoid using `Instant::now()` inside pure state decisions.
- Expose privacy-safe pending/waiter/cache counts for zero-resource assertions; continue to report zero cached tickets by construction.

Update `apps/p2x-exchange/src/resolution.rs`:

- Inject ticket ID generation and signing behind narrow fallible seams. Production uses `getrandom` and `TicketKey`; tests force failure/collision-free deterministic IDs without exposing key material.
- Authorize drain/current client session/role/scope/quota before any idempotency lookup.
- Hash the exact canonical Resolve request body. Same `(peer, request_id, digest)` replays the exact response bytes; a body/session mismatch returns non-retryable `protocol.malformed`.
- Sweep entries only after `ticket_expires_at + maximum skew`. Never evict a live entry to admit a caller; return `limit.resolve_requests` when per-client/global live capacity is full.
- Record response and ticket fingerprints only as one-way stable hashes suitable for test correlation, plus cumulative issuance count. Do not emit ticket ID or bytes.
- Add validated exchange options for global/per-client/rate/bucket limits using defaults 128/16/120/256 and hard maxima 1024/128/1200/2048.
- Add test-only response controls for dropping the first successful Resolve response after it has been cached and for holding admitted responses. Both require `P2X_ENABLE_TEST_HOOKS=1`.

### 3.3 Product connection manager

Refactor `apps/p2x-client/src/connection_manager.rs` around one `PeerState` per server:

- Store the latest validated relay addresses, compatible capabilities, registration revision, and registration expiry.
- Own one relay dial generation, one DCUtR coordination generation, joined waiter IDs, and their individual direct-preference/absolute deadlines.
- Return one `DialRelay` action for concurrent waiters and ignore stale dial/connection/DCUtR events from prior generations.
- Reuse a healthy DCUtR-confirmed direct connection immediately. Otherwise reuse or establish the expected-exchange relay path, then wait for direct only when compatible capabilities allow it.
- On an injected or real direct exact-open failure before handshake start, perform one `OpenExact` on the prepared relay connection with the same move-owned grant. Mark fallback used so later failures cannot loop.
- Retain a late direct success for future opens without changing an already selected stream.
- Retain at most one eligible relay, one preferred direct TCP, and one preferred direct QUIC connection per server. Return explicit close actions for surplus idle connections and mark them closing in `ConnectionBook` before dispatch.
- LRU-evict only a peer with zero waiters, zero active handshakes/streams, and no draining cleanup. When all peers are busy, return `limit.peer_connections` without losing ledger state.
- Make pending, active, dial-generation, path, and selected-connection fingerprints observable without raw peer/route values.

The direct-open failure hook must enter through the same manager event used by a real `ProxyOutput::OutboundFailed`, must target the selected direct `ConnectionId`, and must fire before a stream is handed to the handshake worker. It cannot simply relabel a relay success as fallback.

### 3.4 Server worker verification and replay owner

Refactor `apps/p2x-server/src/proxy_open.rs`, `ticket_admission.rs`, and `main.rs` into two explicit stages:

1. The bounded worker reads exactly one Open, requires write-half closure, rejects early application bytes, decodes the envelope, and verifies signature/time/static claim structure against an immutable key-ring and identity snapshot.
2. The worker sends a `ValidationCandidate` containing validated claims plus Open hints, peer/connection/worker IDs, and a one-shot decision channel.
3. The server owner rechecks current non-draining auth session, tenant, enabled service fingerprint, registration revision/expiry, server authorization revision, Open hints, and availability generation.
4. The owner atomically consumes `ticket_id`, allocates `stream_id`, and returns one decision.
5. The worker writes one Authorized/Rejected, closes the empty stream, and releases behavior/worker/one-shot ownership exactly once.

Do not run Ed25519 verification in the swarm owner. Do not trust a worker's old availability snapshot for live registration or drain decisions.

Add validated server configuration for:

| Limit | Default | Hard maximum |
| --- | ---: | ---: |
| Inbound proxy streams/workers globally | 256 | 2,048 |
| Inbound proxy streams/workers per client | 32 | 256 |
| Replay entries | 8,192 | 65,536 |
| Ticket clock skew seconds | 5 | 30 |

The behavior queue, worker channels, pending owner map, and one-shot count must use the same or smaller effective limits. Test-only handshake holding may delay a worker before candidate delivery but must remain bounded and cancellable.

Replay rules remain:

- verify before allocating replay state;
- sweep entries only when `expires_at + clock_skew <= now`;
- never evict an unexpired entry;
- replay capacity returns retryable `limit.proxy_streams` for new valid tickets;
- a consumed ticket stays consumed after worker write failure, cancellation, connection loss, or shutdown;
- concurrent candidates for one ticket produce exactly one `Authorized` and the rest `auth.ticket_replayed`.

### 3.5 Test-hook safety and lifecycle evidence

Follow the existing registry harness convention: every fault/control option must require `P2X_ENABLE_TEST_HOOKS=1`, be hidden from normal help where appropriate, and fail startup when supplied without the guard. Test hooks must be deterministic, bounded, and visible through a privacy-safe `test_fault_applied` lifecycle event so a case cannot pass without proving its fault actually ran.

Add or extend lifecycle records for:

- resolve accepted/replayed/dropped/terminal, canonical request fingerprint, response fingerprint, and issuance count;
- resolver waiter promotion, pending count, metadata/negative-cache outcome, and zero cached tickets;
- peer dial/DCUtR generation, joined waiter count, selected path, selected connection fingerprint, fallback-used flag, and surplus close;
- proxy exact-open and handshake-start state;
- ticket verification class, live-recheck result, replay rejection, replay-entry count, and worker count;
- final resolve admission/idempotency, route-open, peer-state, proxy behavior, worker, one-shot, and replay counts.

Final summaries and runner assertions must use these records. A case name, injected flag, server-only event, Ping, or uncorrelated `Authorized` is not success evidence.

## 4. Canonical Case Requirements

Replace the current `SUPPORTED` early exit in `tests/resolution/local.sh`. Prefer moving the embedded Python into `tests/resolution/live.py`, following `tests/registry/live.py`, while retaining exactly one executable entry point:

```text
./tests/resolution/local.sh --case <name|all>
```

Every case creates run-scoped identities, credentials, key files, service/route files, ports, processes, and artifacts; validates strict NDJSON and one summary; scans artifacts for secrets/private values; terminates every process; and proves final logical resources return to zero.

### 4.1 Existing cases that must remain passing

| Case | Required evidence |
| --- | --- |
| `resolve-ticket-tcp` | real product TCP Resolve, one ticket issuance, exact selected connection, correlated client/server Authorized |
| `resolve-ticket-quic` | same evidence over QUIC exchange transport |
| `unknown-selector` | client/exchange correlate `registry.not_found`, zero issuance, no server proxy event |
| `offline-selector` | client/exchange correlate `registry.offline`, zero issuance, no proxy authorization |
| `cross-tenant` | same public not-found result as absent selector, no cross-tenant peer/service evidence |
| `forced-relay` | selected exact connection is classified relay and correlates with Authorized |
| `direct-preferred` | DCUtR-confirmed exact direct connection is selected and correlates with Authorized |

### 4.2 Missing cases to implement

| Case | Deterministic setup | Required pass evidence |
| --- | --- | --- |
| `idempotent-resolve` | Exchange drops the first successful Resolved response only after caching it; client timeout retransmits the exact body/request ID. | Fault-applied event exists; two accepted Resolve observations have one canonical request fingerprint and one response fingerprint; issuance count is exactly one; client ultimately authorizes; all resolve owners/cache entries drain or expire as expected. |
| `direct-open-fallback` | Establish eligible relay and confirmed direct paths; client injects one direct exact-open failure before handshake start. | First selected/opened connection is direct; failure is explicitly pre-handshake; exactly one fallback opens on the prepared relay `ConnectionId` with the same grant; server receives one Open and returns one correlated Authorized; no loop or fresh issuance occurs. |
| `ticket-replay` | Complete one valid authorization, then open a second substream using the exact consumed ticket under the guarded diagnostic hook. | First result is Authorized; second is `auth.ticket_replayed`; one stream ID and one replay entry are allocated; ticket is not re-resolved or silently replaced; final replay state follows expiry/skew retention. |
| `ticket-bindings` | Run bounded subcases for ticket-byte mutation, Open upstream mismatch, Open revision mismatch, wrong transport client, wrong server/local identity, tenant/service fingerprint, authorization revision, issuer/key, permissions, and max-stream mismatch. Use unit/same-process tests for bindings that cannot be safely driven through the product CLI and representative real-process mutations for the public case. | Every mismatch fails before replay allocation with `auth.ticket_invalid`, except stale current registration revision which uses `registry.stale_revision` and time expiry which uses `auth.ticket_expired`; no subcase emits Authorized or leaks which binding failed publicly. |
| `ticket-expiry` | Use five-second ticket lifetime, server clock skew zero, and guarded delay until `now >= expires_at` before Open. | Server returns `auth.ticket_expired`; replay count remains zero; client never retries the expired ticket; any allowed recovery uses a fresh resolve and remains inside the original deadline in a separate state test. |
| `registration-revision-change` | Pause the client after Resolve; replace/restart the same persisted server identity so it registers a new revision; release the old Open, then permit recovery. | Old ticket/Open is rejected `registry.stale_revision` before replay consume; client invalidates metadata; one fresh Resolve returns the new revision/ticket; later Authorized correlates to the new revision; old ticket never authorizes. |
| `connection-reuse` | Configure at least two route IDs/selectors owned by one server; open them sequentially and again after direct upgrade. | Each logical open has a distinct Resolve request, ticket/response fingerprint, and stream ID; the same eligible relay/direct connection fingerprint is reused; only one relay dial generation occurs while healthy; active/pending counts return to zero. |
| `concurrent-opens` | Run 64 simultaneous opens across multiple selectors/servers, then the 128-open headroom configuration. | Every accepted open has a unique request/response/ticket fingerprint and stream ID; same-server waiters share dial/DCUtR generations but not tickets; unrelated servers progress; no duplicate terminal or nonzero final owner remains. |
| `resolve-limit` | Configure low global/per-client/rate/bucket bounds and hold admitted responses so exact `N` remains live while `N+1` arrives. | Correct boundary returns `limit.resolve_requests` or `exchange.overloaded` as specified; no rejected request allocates idempotency/ticket state; auth Ping and registry Refresh remain timely; release/connection-close/drain paths return resolve in-flight to zero. |
| `proxy-limit` | Configure low behavior/worker/per-client/replay limits and hold workers/candidates to reach exact `N`. | `N` is admitted, `N+1` receives `limit.proxy_streams`, unrelated clients make progress within their bounds, live replay entries are never evicted, capacity becomes usable only after permitted release/expiry, and all worker/behavior/one-shot counts return to zero. |
| `exchange-restart` | Stop and restart the exchange with the same persisted identity while the original client and server processes remain running. | Client/server lose control readiness; old registry/idempotency state disappears; server reauthenticates and registers a new revision; the same client process reauthenticates, resolves again, and obtains correlated Authorized without reusing stale work. |
| `server-restart` | Stop and restart the server with the same persisted identity and configuration while the original exchange/client remain running. | Old reservation/registration is removed; client peer state becomes unusable without disturbing unrelated state; restarted server registers fresh revision; same client process resolves fresh metadata/ticket and authorizes. |
| `graceful-drain` | Execute bounded subcases that signal exchange, server, and client with admitted resolve/proxy work held at deterministic stages. | New work is rejected with the component's draining code; already-owned response/worker cleanup is polled up to five seconds; consumed tickets remain consumed; readiness false/Withdraw ordering is observed; every final resource count is zero; each process emits exactly one terminal. |

For multi-subcase names such as `ticket-bindings` and `graceful-drain`, the summary must list each required subcase and fail if any is missing. Do not report one representative mutation as the complete matrix.

## 5. Protocol Vectors, Fuzzing, and Same-Process Tests

### 5.1 Byte-exact vectors

Replace the placeholder JSON in:

- `crates/p2x-protocol/testdata/resolve-v1.json`
- `crates/p2x-protocol/testdata/proxy-v1.json`

Each vector must contain named hex/base64 canonical bodies and framed bytes generated from fixed non-production values. Include:

- Resolve request, Resolved, and Rejected with/without request ID;
- Open, Authorized, Accepted (defined but not emitted), and Rejected;
- fixed PeerIds/multiaddresses, selector order, revision, capabilities, timestamps, and a clearly non-production RawTicket;
- exact expected length prefix and total size.

Protocol tests decode every committed vector, re-encode byte-identically, and verify mutations/trailing data fail. The vector generator may be an example/tool, but committed tests must not regenerate expected bytes at assertion time.

### 5.2 Fuzz corpus and targets

Commit corpus entries for both `resolve_frame_decode` and `proxy_frame_decode` covering:

- every valid request/response vector;
- zero, exact maximum, and maximum-plus-one declared lengths;
- truncation at header/body boundaries and trailing bytes;
- unknown version/discriminant/capability/error/ingress/upstream mode;
- malformed/non-canonical PeerId, multiaddress/circuit shape, selector order, identifier, and revision;
- minimum/maximum/oversized ticket;
- both raw canonical body decoding and `u32` framed async codec decoding.

Extend `proxy_frame_decode` to invoke `p2x-net::proxy_codec` read paths, not only domain decoders. Fuzz inputs must never allocate from an unvalidated declared length.

### 5.3 Focused and same-process coverage

Add unit/state tests before process hooks:

- exchange authorization-before-replay, digest mismatch, live capacity/no eviction, expiry+skew retention, injected random/sign failure, lifetime boundaries, and session/reservation/removal races;
- resolver deterministic cache time, FIFO promotion after every terminal, old-session restart, late response, cancellation, negative-cache exclusions, and unique ticket delivery;
- connection manager dial/DCUtR singleflight, stale generations, existing-direct fast path, early direct-to-relay fallback, post-handshake fresh-ticket action, surplus close, LRU busy rejection, deadline clipping, and cleanup;
- server every ticket binding/time/key mismatch, concurrent replay, capacity/no live eviction, stale worker candidate, drain, write failure, one-shot drop, connection close, and expiry sweep;
- protocol direction and exact selected-connection behavior remain unchanged.

Replace or extend `crates/p2x-net/tests/resolve_network.rs` and `proxy_network.rs` with authenticated same-process tests over TCP and QUIC. At least one test must run the actual exchange resolution owner and server ticket owner rather than constructing a synthetic Resolved/Authorized response in the test event loop.

## 6. Ordered Implementation Plan

### 6.1 Lock the reviewed gaps with failing tests

- Add named failing tests for every row in section 1.2.
- Add fixture builders for authenticated sessions, ready registrations, validated relay addresses, signed tickets, deterministic clocks, injected ticket IDs, and exact connection events.
- Keep production ticket bytes and private selectors out of failure output.

### 6.2 Complete vectors and framed fuzz coverage

- Replace placeholder resolve/proxy vectors with committed bytes.
- Extend proxy framed-codec fuzzing and seed both corpora with all required valid/malformed classes.
- Run protocol tests and bounded fuzzing before app-owner refactors.

### 6.3 Harden exchange resolution and admission controls

- Add injected randomness/signing, complete idempotency/lifetime/capacity tests, validated limits, held-response/drop-first-response test controls, and lifecycle evidence.
- Preserve the synchronous lookup/sign/cache transition and authorization-before-replay ordering.
- Verify every response/request/connection/drain terminal releases admission exactly once.

### 6.4 Build the multi-open client owner

- Replace global single-open `Option` state in `main.rs` with bounded per-open maps and action dispatch.
- Integrate resolver FIFO/caches, one retransmission, fresh-ticket retry, cancellation, late-event rejection, and aggregation for finite diagnostics.
- Keep normal product auth/redial/swarm polling independent of one slow open.

### 6.5 Complete per-server connection ownership

- Add metadata/revision, relay dial/DCUtR generations, joined waiters, exact-open fallback, connection reuse, surplus close, and LRU cleanup to `ConnectionManager`.
- Drive all returned dial/open/close actions from `main.rs` and test stale generation/cancellation paths before live cases.

### 6.6 Split server verification and live consume

- Move immutable cryptographic verification into bounded workers.
- Keep live registration/auth/drain recheck and replay consume in the owner.
- Wire configurable behavior/worker/replay limits, held-worker controls, and exactly-once release.

### 6.7 Implement all canonical process cases

- Refactor the resolution runner into reusable harness ownership without changing its public entry point.
- Implement section 4 cases one group at a time: ticket semantics, path/reuse/concurrency, limits, restart, then drain.
- After each group, verify strict summary schema, fault-applied evidence, privacy scan, terminal cardinality, and final zero resources.
- `--case all` must not skip, mark prepared, or accept status 2 for any declared case.

### 6.8 Regressions and documentation

- Rerun auth, registry, and C01/C05-C13 after owner changes.
- Update protocol, security, client-connection, server-availability, and test documentation only to behavior proven by named cases.
- Record the remaining owner-executed deployment/platform checks as incomplete; do not mark them passed locally.

Implement and review each section as an independent commit. Keep one append-only `rlogs/05a-resolution-and-proxy-executable-closure__<timestamp>.rlog` for the execution session, and do not modify Plan 05 or this Plan 05a during implementation.

## 7. Verification

### 7.1 Static and automated checks

Run from the repository root:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
cargo tree -e features
```

Listener-based tests must run in an environment that permits loopback TCP/QUIC binding. A sandbox listener denial is an environment failure, not a passing test.

Run every fuzz target with the repository's bounded CI duration using nightly Rust, without committing generated corpus noise:

```text
auth_frame_decode
proxy_frame_decode
registry_frame_decode
resolve_frame_decode
ticket_claims_decode
ticket_envelope_decode
token_parse
```

Any crash, panic, excessive allocation, non-canonical acceptance, raw-ticket leak, unknown-code coercion, or unbounded wait/queue fails the phase.

### 7.2 Canonical local process gates

These are locally automatable and must pass before the next phase:

```text
./tests/resolution/local.sh --case all
./tests/auth/local.sh --case all
./tests/registry/local.sh --case all
./tests/connectivity/local.sh --case all
```

For resolution, assert all 20 case summaries exist, contain `passed: true`, enumerate required subcases, and were created by the current run. The aggregate command must fail on a missing summary, duplicate terminal, unobserved test hook, privacy finding, or nonzero final resource.

### 7.3 Concurrency, timing, and cleanup gates

- Run 64 concurrent empty proxy opens and the 128-open headroom profile; every successful open has a unique ticket/stream and unrelated targets progress.
- Run same-server multi-route reuse and verify one healthy connection generation serves multiple independent tickets/substreams.
- Saturate resolve and proxy limits while auth Ping and registry Refresh remain within their established deadlines.
- Inject delay separately at resolve, relay dial, DCUtR preference, exact open, worker verification, and owner decision. Each logical open must finish no later than its configured 20-second setup deadline plus bounded scheduler tolerance.
- Repeat direct/relay loss, cancellation, exchange restart, server restart, and re-resolution cycles. Pending requests, peer states, connections, behavior requests, workers, one-shots, replay entries after their retention window, and ticket buffers must return to baseline.
- Scan all NDJSON, summaries, stderr, and failure artifacts for credential/token values and digests, session IDs, raw tickets/ticket IDs, raw selectors/metadata, verification material, and private targets.

### 7.4 Final owner-executed deployment/platform phase

Only after sections 7.1-7.3 pass, run or hand off these environment-dependent checks:

- complete Linux namespace connectivity matrix;
- two-host C14 plus real product direct-preferred and forced-relay ticket authorization over TCP and QUIC exchange transports;
- real firewall/NAT and packet inspection evidence;
- Linux and native macOS direct/relay behavior, with macOS VM-backed container direct remaining measured best effort;
- long churn/load/soak and deployment packaging checks assigned to the final project phase.

Record unavailable environments as incomplete, not passed. These owner-executed checks are the only Plan 05a work intentionally deferred beyond the local phase gate.

## 8. Documentation Updates

After executable evidence passes, update:

- `docs/protocol/resolve-v1.md`: byte-exact vectors, idempotency identity/retention, admission limits, errors, and compatibility;
- `docs/protocol/proxy-v1.md`: framed vectors, half-close-before-authorization, fallback boundary, worker/live recheck split, replay retention, and no `Accepted` emission;
- `docs/operations/client-connections.md`: multi-open owner, queue promotion, metadata versus ticket reuse, connection generations, fresh-ticket retry, limits, restarts, and shutdown;
- `docs/operations/server-availability.md`: stale-ticket/revision behavior and proxy worker/drain ordering;
- `docs/security/identity-and-credentials.md`: verification-ring/replay behavior and the bounded revocation window of already issued tickets;
- `tests/resolution/README.md` and `tests/README.md`: all executable cases, required environment, summary schema, artifact/privacy rules, and final owner-executed checks.

Do not claim data tunneling, upstream acceptance, active-stream migration, dynamic reload, or deployment/platform success that Plan 05a does not implement or execute.

## 9. Definition of Done and Phase Gate

Plan 05a is complete only when all of the following are true:

- every confirmed P0/P1 gap in section 1.2 has implementation and regression coverage;
- the client supports bounded independently correlated sequential/concurrent route opens without sharing tickets;
- resolver retransmission, FIFO promotion, caches, session transitions, and one fresh-ticket retry follow the single absolute deadline;
- the connection manager owns relay/DCUtR generations, reuse, exact fallback, pool bounds, surplus closing, and stale-event rejection;
- the server verifies tickets outside the swarm owner and atomically live-rechecks/consumes replay state inside it;
- byte-exact resolve/proxy vectors and representative fuzz corpora are committed and tested;
- all 20 resolution cases execute and pass through the real product binaries, with no status-2 placeholders;
- auth, registry, connectivity, static, dependency, fuzz, concurrency, deadline, cleanup, and privacy checks pass;
- final lifecycle records prove zero locally owned logical resources and exactly one terminal per finite process;
- documentation matches executable behavior;
- deployment/platform-dependent checks are clearly listed for the final owner-executed phase and are not used to hide a local failure.

Only after this local Definition of Done passes may the branch be declared ready for Plan 06. Plan 06 may then add fixed TCP ingress, server-local upstream policy, final `Accepted`, bounded bidirectional copy, application half-close, idle timeout, cancellation, and stream permits without inheriting unresolved Plan 05 ownership or verification debt.
