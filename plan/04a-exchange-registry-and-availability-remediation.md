# Remediation Plan: Close Plan 04 Registry and Server Availability Gaps

- **Document status:** implementation-ready
- **Scope:** corrective follow-up to [`04-exchange-registry-and-server-availability.md`](04-exchange-registry-and-server-availability.md)
- **Baseline reviewed:** `feat/04-exchange-registry-and-server-availability` at `32a0feb`
- **Required outcome:** make the implemented Phase 2 product path satisfy Plan 04's protocol, admission, lease, recovery, readiness, shutdown, and executable-verification guarantees before Phase 3 begins

## 1. Review Result and Scope

The Plan 04 branch compiles cleanly and its current automated suite passes when loopback TCP/QUIC listeners are permitted. It is not ready to be accepted as Plan 04 complete: the current tests cover codec round trips and isolated happy paths, but several required failure and recovery paths are either missing or implemented incorrectly.

This remediation changes only the existing Plan 04 seams. Do not add registry persistence, client resolution, ticket issuance, proxy streams, upstream probing, multi-exchange support, or a new framework/crate.

### 1.1 Verification performed during review

| Check | Review result |
| --- | --- |
| `cargo fmt --all -- --check` | passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-targets --all-features` | passed outside the filesystem/network sandbox; 110 tests total |
| `cargo deny check` | passed with existing duplicate-version warnings |
| `git diff --check feat/03-identity-authentication-and-bounded-protocols..HEAD` | passed |
| `tests/registry/local.sh` | not an executable test harness; it writes `status: prepared` and always exits 2 |

### 1.2 Confirmed defects

| Priority | Confirmed current behavior | Required correction |
| --- | --- | --- |
| P0 | `ServiceSet::new` sorts by `upstream_id` and checks selector equality only in adjacent pairs, so non-adjacent duplicate selectors are accepted. | Enforce selector uniqueness independently of ID order and add a three-entry regression test. |
| P0 | `Registry::refresh` can extend a record whose `expires_at <= now` if the one-second sweep has not run yet. | Remove/expire the record before returning `registry.not_found`; an expired lease must require a full Register and must never be resurrected by Refresh. |
| P0 | The server treats every rejected registry response as a generic registration loss and then remains degraded; it does not implement the required error-specific retry/full-register behavior. Transport failure immediately sends a new Register with a new request ID and no backoff. | Implement a bounded registry supervisor with exact retry classification, retained timeout request bodies/IDs, and 250 ms–10 s jittered backoff. |
| P0 | Register response acceptance does not verify `service_set_hash` or the reservation generation captured when the request was sent. | Correlate outbound ID, wire request ID, instance ID, expected hash, operation kind/revision, and generation before mutating readiness. |
| P0 | Exchange registry requests have no 128-global, one-per-peer, 30-per-minute, or 256-bucket admission ledger and no exactly-once permit release path. | Add the bounded admission owner required by Plan 04 and wire every request-response terminal event. |
| P0 | A failed/poisoned/full `RelayAdmissionHandle::install` result is ignored and the exchange still returns `Authenticated`. | Make relay admission installation part of the auth commit; roll back the newly created session and send a stable rejection/close action if it cannot be installed. Poisoning must mark exchange readiness false and start bounded shutdown. |
| P0 | Auth renewal writes the replacement session's `expires_at` into the retained prior session before replacement Ping succeeds. A failed replacement Ping can therefore make an already-invalid old session appear current until the new expiry. | Track pending and current session expiries separately and implement the old-session/new-session race exactly as specified. |
| P0 | `tests/registry/local.sh` is a placeholder, while the operations document claims retry, replay, restart, and recovery behaviors that the implementation does not currently provide. | Replace it with an executable, machine-asserted product harness and correct documentation only after evidence exists. |
| P1 | Refresh/Withdraw idempotency digests omit `session_id`; Register hashes Rust `Debug` output rather than canonical protocol bytes. | Hash the exact canonical request body for every operation so changing a session while reusing a request ID is rejected as `protocol.malformed`. |
| P1 | The idempotency cache clears all entries at the global limit and evicts an arbitrary per-peer entry from `HashMap` iteration order. | Use deterministic oldest-entry eviction while preserving unrelated replay protection and both configured bounds. |
| P1 | Revision allocation tries OS randomness only once; zero or a collision returns overload instead of retrying against retained revisions. | Add an injected allocator and a small bounded retry loop; fail before mutation only after exhaustion. |
| P1 | `resolve_exact` and its not-found/offline/eligible semantics are absent. | Add the exchange-internal lookup seam needed by Phase 3 and test health, expiry, reservation removal, and tenant isolation. |
| P1 | Phase 2 accepts capability sets containing `DCUTR`. | Reject `DCUTR` in product Register while continuing to reject unknown bits in the codec. |
| P1 | Registry protocol support is always inbound on the exchange, including connectivity-lab mode. | Toggle registry behavior by role and runtime mode so only the product exchange is inbound and only the product server is outbound. |
| P1 | Product relay rates are 256/512 reservation and 1024/2048 circuit starts per minute, not Plan 04's 8/32 and 64/256 defaults; the limits are not exposed through validated product configuration. | Apply the documented logical defaults, retain the pinned `N - 1` per-peer adapter, add validated CLI limits/hard maxima, and prove live `N`/`N + 1` boundaries. |
| P1 | `refresh_seconds` is parsed but unused. Refresh is scheduled at one third of the observed lease with no jitter. | Schedule from configured `refresh_seconds` with full-range ±10% jitter and clamp to no later than five seconds before expiry. |
| P1 | Auth renewal always starts 60 seconds before expiry; it does not use half the remaining lifetime for sessions shorter than 120 seconds. | Store the session start/accept time and calculate the required short-session renewal threshold. |
| P1 | Server readiness generation is reservation generation, increments on loss, and is not limited to false-to-true transitions. Shutdown does not first publish false or drive `Draining -> Withdrawn -> Stopped`. | Separate reservation attempt generation from readiness generation and implement the required shutdown transitions. |
| P1 | Exchange shutdown exits its event loop, immediately clears state, and never performs the five-second drain while rejecting new work and polling existing responses. | Add an explicit draining phase and deadline; remove admission/registry/session state in the required order after the bounded drain. |
| P1 | Registry fuzz seeds contain only a frame header plus version/discriminant, not valid Register/Refresh/Withdraw/response frames or the required malformed variants. | Commit real encoded corpus entries for every request/response and the specified boundary mutations. |
| P2 | Unknown public error strings decode as `ProtocolMalformed` instead of making the response frame invalid. | Add a fallible `PublicErrorCode` parser for wire decoding while retaining any intentionally lossy diagnostic parser separately. |
| P2 | Service-file validation does not explicitly enforce 1–128 total entries before filtering disabled entries. | Validate the complete file entry count, then validate every entry, then project the non-empty enabled set. |

## 2. Required Design Corrections

### 2.1 Canonical registry domain and wire identity

Update `crates/p2x-protocol/src/registry.rs`, `selector.rs`, and `error.rs`:

- Check duplicate `upstream_id` values and duplicate selectors with independent bounded sets. Preserve canonical sorting by `upstream_id` only after validation.
- Provide one canonical byte encoding/hash function for `ServiceSet` and one for each complete `RegistryRequestV1`. Include a version/domain prefix and length delimiters; include `session_id` in Register, Refresh, and Withdraw identity.
- Use the shared service-set hash on both exchange and server. Remove the exchange-private ad hoc hash and the `format!("{request:?}")` digest.
- Add `PublicErrorCode::try_from_wire(&str) -> Result<_, _>` and make both auth and registry codecs reject unknown error strings. Do not silently reinterpret an unknown peer-controlled string as the valid `protocol.malformed` code.
- Keep selectors/metadata out of routine `Debug` output or provide redacted wrappers before any request/domain value is passed to lifecycle diagnostics.

Update `crates/p2x-net/src/registry_codec.rs`:

- Keep the current frame bound and closed discriminants, but test exact-maximum, zero, truncated, trailing, duplicate selector, duplicate ID, non-canonical metadata/service order, unknown error code, unknown capability, and every request/response round trip.
- Expose only the canonical body encoder needed for idempotency/corpus construction; do not expose private mutable wire structs.

### 2.2 Exchange registry invariants

Refactor `apps/p2x-exchange/src/registry.rs` so every operation first prepares a non-mutating decision and then commits synchronously:

- On Refresh and Withdraw, treat `record.expires_at <= now` as absent. Remove the expired record and all selector owners through `remove_peer`, then return `registry.not_found` without extending or reporting the old revision.
- Reject `DCUTR`; require `RELAY_V2` and exactly the allowed Phase 2 direct transport subset.
- Replace the idempotency `HashMap`-clear behavior with deterministic per-peer/global oldest eviction. A request-ID/body mismatch returns `protocol.malformed`, not `registry.invalid_advertisement`; represent this distinction in `RegistryError`.
- Inject revision randomness behind a small allocator trait/function used by tests. Retry zero/current collisions a bounded number of times and prove exhaustion leaves records/index/cache unchanged.
- Add `resolve_exact(&ScopedSelector, now)` returning an immutable owner view or typed `NotFound`/`Offline`. It must reject expired records even before sweep; `Health::Unavailable` owns the selector but resolves offline.
- Continuously assert in state-sequence/property tests that every selector owner points to exactly one matching live record and that every record service has exactly one owner entry.

Do not let idempotency replay bypass the current transport session, role, scope, quota, drain, or reservation checks in `main.rs`. Authorization occurs for the current request first; replay only avoids a second mutation after authorization succeeds.

### 2.3 Registry admission and response ownership

Add `apps/p2x-exchange/src/registry_admission.rs` following the existing auth admission ownership pattern:

- Bound accepted work to 128 requests globally, one request per peer, 30 accepted operations per server per rolling minute, and 256 tracked rate buckets.
- Key ownership by libp2p inbound request ID plus connection ID and peer ID. Return `limit.registry_requests` with `retryable = true` for bounded admission rejection.
- Release exactly once on `ResponseSent`, `InboundFailure`, owning connection close, or shutdown. A response channel failure must also release ownership rather than terminate the exchange with a leaked permit.
- Map retryability exactly: reservation-required, stale-revision/not-found recovery, overload/limit, and draining are retryable in their documented contexts; conflict, malformed advertisement, role/scope/profile denial, and capability mismatch are not blind-retryable.

In `crates/p2x-net/src/builder.rs`, make the exchange registry behavior a toggle just like the role-specific peer surface. Add negotiation tests proving product exchange inbound, product server outbound, product client disabled, and every connectivity-lab peer/exchange disabled.

### 2.4 Relay admission, limits, and exchange drain

Update `crates/p2x-net/src/relay_admission.rs`, `builder.rs`, and `apps/p2x-exchange/src/main.rs`:

- Split relay snapshot installation into a checked prepare/commit result that distinguishes capacity, draining, and poison. The auth owner must not send `Authenticated` until installation succeeds. If auth session creation happened first, remove that exact new session and produce its close/cleanup actions before replying.
- Surface poisoned snapshot state to the exchange owner. Fail all relay checks closed, publish exchange readiness false, set registry/admission draining, and enter the normal bounded shutdown path.
- Keep the authorization limiter first, followed by libp2p peer/IP rate limiters.
- Set product logical defaults to reservation attempts 8/peer and 32/IP per minute and circuit starts 64/peer and 256/IP per minute. Validate configurable values and Plan 04 hard maxima before swarm construction.
- Preserve the pinned libp2p translation of logical per-peer count `N` to raw `N - 1` for both reservations and circuits. Add live tests proving one reservation per server and 32 circuits per client accept exactly `N` and reject `N + 1`, including renewal at the reservation boundary.
- During Ctrl-C/drain, continue polling the swarm for up to five seconds, reject new Register/Refresh and relay admission, allow correlated Withdraw/terminal response cleanup, then clear registry, relay snapshot, sessions, and pending owners in that order.

### 2.5 Session renewal correctness

Refactor `crates/p2x-net/src/auth_state.rs` and its client/server consumers:

- Store a complete current session lease and a separate pending replacement lease. Receiving replacement `Authenticated` must not overwrite the prior lease's expiry.
- For an accepted session lifetime below 120 seconds, renew after half its original lifetime; otherwise renew 60 seconds before expiry. Use the time the response was accepted, not a repeatedly recomputed remaining duration.
- While replacement Ping is pending, availability may retain the prior lease only until its real expiry. After the exchange replaces the session, an `auth.session_required` registry rejection must retry once with the correlated new current session and a fresh request ID after replacement Ping succeeds.
- A replacement timeout/overload backs off without extending the old lease. Old expiry, terminal auth rejection, revocation, or final exchange connection loss clears availability immediately.
- Add races for replacement Authenticate response versus Refresh, replacement Ping timeout, prior expiry during reauth backoff, stale Pong, and successful renewal with no readiness flap.

## 3. Rebuild the Server Availability Supervisor

Replace the distributed booleans in `apps/p2x-server/src/main.rs` with actions owned by `apps/p2x-server/src/availability.rs`. Keep `Swarm` and I/O in `main.rs`.

### 3.1 State and correlation ownership

The supervisor must own:

- auth lease presence, reservation attempt generation/readiness, registration revision/expiry, and a separate readiness generation;
- one pending canonical registry operation containing operation kind, outbound request ID, wire request ID, session ID, instance ID, reservation generation, expected service-set hash, optional revision, exact request body, attempt count, and deadline;
- one retry timer and one refresh timer; duplicate failure/loss events cannot create duplicates;
- terminal configuration/protocol failures distinct from transient degraded state.

Readiness remains exactly current auth + ready current reservation generation + matching unexpired registration + not draining. Increment `readiness_generation` only when readiness changes from false to true.

### 3.2 Register, Refresh, and retry behavior

- Register only after both reservation acceptance and canonical circuit listen-address confirmation for the same generation.
- Accept Registered only if outbound ID, request ID, instance ID, service-set hash, and generation all match the pending operation.
- Use `refresh_seconds` with ±10% jitter. Clamp the result so it is never after `expires_at - 5 seconds`; for the minimum ten-second lease, schedule a positive immediate-safe deadline without a busy loop.
- A transport timeout retains the exact request and request ID for idempotent replay. Other retry attempts that change session/body allocate a fresh request ID.
- `registry.stale_revision` or `registry.not_found` clears revision and schedules full Register. `auth.session_required` waits for/uses the current replacement session and retries once with a fresh ID. `registry.reservation_required` waits for reservation recovery. Overload, request limit, timeout, and draining use capped backoff. Conflict, invalid advertisement, service limit, unsupported capability/version, and role/scope/profile rejection are terminal until operator configuration/auth changes.
- Never retry directly from a request-response failure event. Schedule 250 ms exponential backoff with full ±10% jitter, cap at ten seconds, and dispatch only from the supervisor timer.
- At local lease expiry, publish readiness false even with a Refresh in flight. A late Refreshed response whose prior lease already expired must not resurrect the old registration; perform a full Register.

### 3.3 Loss and shutdown

- Reservation loss clears registration locally, invalidates its generation, closes only the generation-owned circuit listener/exchange connection, and schedules reservation reacquisition once.
- Final exchange disconnect clears pending request ownership and schedules redial/auth/reservation/full Register. Non-final exchange connection loss and healthy direct non-exchange connections do not flap availability.
- Begin shutdown by publishing readiness false and cancelling retry/refresh timers. Send at most one current Withdraw, wait up to five seconds for its exact response, close the circuit listener and exchange connection IDs, drain pending ownership, then transition `Draining -> Withdrawn -> Stopped`.
- Emit subsystem lifecycle transitions and one `ServerReadiness` record only on meaningful state changes. Never emit hard-coded all-false component fields when some gates remain current.

## 4. Configuration, Lookup, and Documentation Corrections

Update `apps/p2x-server/src/config.rs`:

- Require 1–128 total YAML service entries before filtering `enabled: false` entries.
- Validate every disabled entry exactly like an enabled entry, then require a non-empty enabled projection.
- Compute and retain the shared canonical service-set hash for response correlation and privacy-safe startup diagnostics.

Update `docs/protocol/registry-v1.md` and `docs/operations/server-availability.md` only after the behavior is executable. Remove or correct every claim not proven by a named automated/harness case. Document the distinction between retrying identical timeout bytes and allocating a new request ID after a session/body change.

## 5. Executable Verification

### 5.1 Focused automated tests

Add tests that fail on the reviewed baseline and pass after remediation:

1. non-adjacent duplicate selector rejection;
2. Refresh at `now == expires_at` removes the record/index and returns not-found;
3. request-ID reuse with a changed session for Register, Refresh, and Withdraw is malformed;
4. idempotency eviction is deterministic and never clears unrelated entries at the global limit;
5. revision zero/collision retry and exhausted allocator atomicity;
6. exact lookup ready/offline/expired/cross-tenant behavior;
7. registry global/per-peer/rate admission `N`/`N + 1` and exactly-once release on every terminal event;
8. relay admission install capacity/poison failure cannot produce authenticated success;
9. exact relay logical count/rate boundaries with authorization first;
10. short-session renewal midpoint and replacement-expiry race cases;
11. Register/Refresh response correlation including stale hash/generation;
12. retry classification, retained timeout bytes, backoff/jitter cap, lease-expiry race, and no duplicate timer;
13. readiness generation and shutdown transition sequence;
14. exact runtime protocol negotiation matrix;
15. service file total-entry bounds and canonical hash;
16. valid and malformed fuzz corpus decoding without panic or excessive allocation.

### 5.2 Replace the placeholder registry harness

Rewrite `tests/registry/local.sh` using the existing auth harness conventions. It must create run-scoped identities, ticket key, strict credentials, service files, and ports; start the real product binaries; validate NDJSON records; clean up every process; and return 0 only after assertions pass.

Provide executable cases for at least:

- TCP and QUIC authenticated reserve/register/refresh/withdraw;
- multi-service atomic registration and same-selector conflict/cross-tenant isolation;
- unauthenticated/wrong-role/wrong-scope relay and registry denial with zero allocated state;
- reservation loss, lease expiry, revocation, and final exchange disconnect cleanup;
- dropped Register response followed by byte-identical replay returning one revision/mutation;
- exchange restart with the same server PID/PeerId restoring readiness within 60 seconds;
- registry request/service/relay `N` and `N + 1` limits;
- graceful server and exchange drain with zero logical resources;
- lifecycle artifact scan proving no credential, session ID, raw selector/metadata, or private target is present.

Each case must write a machine-readable summary containing observed assertions and resource counts. Do not use a requested case label as proof, and do not report `prepared` as a pass.

### 5.3 Final commands

Run from the repository root:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
cargo tree -e features
./tests/registry/local.sh --case all
./tests/auth/local.sh --case all
./tests/connectivity/local.sh
```

Run every fuzz target for the repository's bounded CI duration, including `registry_frame_decode` with the corrected corpus. Record owner-executed platform/two-host results honestly when the environment cannot run them locally.

## 6. Acceptance Criteria

- Every P0/P1 defect in §1.2 has a regression test that demonstrably fails on `32a0feb` and passes after remediation.
- No expired registration can be refreshed or resolved, and every removal path leaves the selector index consistent.
- Registry and relay admission enforce all global/per-peer/rate limits before allocation and release ownership exactly once.
- The server automatically restores reservation, registration, and truthful readiness after every documented transient loss without process restart or retry storms.
- Auth renewal never extends or reuses an invalid prior session and does not flap availability on successful replacement.
- Product/lab protocol surfaces, relay logical limits, readiness generations, and drain ordering match Plan 04 exactly.
- The real three-process registry harness passes its TCP, QUIC, recovery, limit, replay, privacy, and cleanup assertions.
- Format, clippy, workspace tests, dependency policy, auth regression, and connectivity regression all pass before Plan 04 is marked complete.
