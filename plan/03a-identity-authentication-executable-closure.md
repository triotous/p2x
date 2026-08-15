# Remediation Plan: Identity and Authentication Executable Closure

- **Document status:** implementation-ready corrective plan
- **Reviewed baseline:** `30b74c4` (`feat/03-identity-authentication-and-bounded-protocols`), clean worktree on 2026-08-15
- **Corrects:** [`03-identity-authentication-and-bounded-protocols.md`](03-identity-authentication-and-bounded-protocols.md)
- **Decision:** Plan 03 is not complete; Plan 04 remains blocked until this plan's definition of done is satisfied
- **Scope boundary:** close Phase 1 identity, authentication, ticket, product/lab isolation, and executable-verification gaps without implementing registry, selector resolution, relay authorization, ticket issuance from registry state, replay consumption, or proxy streams

## 1. Goal and Review Outcome

The Plan 03 implementation establishes useful foundations: persistent Ed25519 identity loading, fixed-token digest validation, bounded binary auth frames, session and admission ledgers, deterministic ticket bytes and signatures, TCP/QUIC auth round trips, and a finite three-process harness. Formatting, Clippy, the workspace test suite, and `cargo deny check` pass at the reviewed baseline when loopback socket tests are run outside the restricted sandbox.

Plan 03 is nevertheless not complete. Several product-mode paths still expose Phase 0 facilities without authorization, connection admission can undercount after a rejected connection closes, protocol capabilities are carried but never enforced, secret-bearing wire values are copied into ordinary public buffers, and several live test cases pass without exercising their named failure. These are security and correctness gaps, not optional refinements, so the next document is this Plan 03a rather than Plan 04.

This remediation must preserve the accepted Phase 0 connectivity implementation in explicit connectivity-lab mode. It must not weaken the direct/relay exact-connection, bounded worker, reservation, or lifecycle invariants already accepted by ADR 0001.

## 2. Confirmed Findings

| ID | Confirmed evidence | Required closure |
| --- | --- | --- |
| 03A-01 | [`PeerBehaviour`](../crates/p2x-net/src/builder.rs) always installs `ProbeStreamBehaviour`, advertises auth with `ProtocolSupport::Full`, and [`p2x-server`](../apps/p2x-server/src/main.rs) accepts inbound probe streams without a product authorization check. The server also requests a relay reservation before auth completes. | Product mode must not advertise or execute `/p2x/spike/1`, accept inbound auth requests on client/server, or start unauthenticated relay/probe work. Phase 0 behavior remains available only under `--unsafe-connectivity-lab`. |
| 03A-02 | Client/server read `credential_env` before validating exchange trust, accept the first `/p2p` component rather than requiring the address to end in the configured exchange pin, and do not use [`p2x_config::trust`](../crates/p2x-config/src/trust.rs) in the app entrypoints. | Validate all complete exchange addresses and the authenticated remote `PeerId` before resolving or borrowing token material. A mismatch closes/fails with `auth.exchange_identity_mismatch` and emits zero auth requests. |
| 03A-03 | [`AuthRequest`](../crates/p2x-protocol/src/auth.rs) publicly exposes a serializable `[u8; 32]`; [`AuthCodec`](../crates/p2x-net/src/auth_codec.rs) encodes it into an ordinary `Vec`, does not close the write half, maps distinct protocol failures to one generic I/O error, and ignores feature negotiation. Runtime randomness uses `expect`, while request correlation is random rather than checked monotonic allocation. | Make secret ownership and zeroization explicit, enforce capability/version semantics, preserve typed local errors, close request/response writes, and make all runtime ID allocation fail closed without panics. |
| 03A-04 | [`AdmissionLedger`](../apps/p2x-exchange/src/admission.rs) does not own connection IDs. After a connection is rejected, its later `ConnectionClosed` takes the `connection_ips` miss path and decrements the global count for an unrelated admitted connection. An auth admission rejection at [`main.rs`](../apps/p2x-exchange/src/main.rs) line 162 drops the request channel without sending the returned stable code. | Use one connection-ID-owned ledger with transactional admission/rollback and exactly-once close. Keep inbound request permits through response delivery and send a bounded `Rejected` response for every decoded request rejected by admission. |
| 03A-05 | There is no `CredentialProvider` trait; role/scope validation allows client `register_services` and server `open_proxy_stream`; replacement does not enforce monotonic authorization revisions; and snapshot revocation actions are not connected to an owner action that closes the affected peer. `CredentialRecord`/`FixedTokenFile` derived `Debug` exposes token digests. | Restore the provider boundary, exact role/scope policy, validated monotonic replacement, redaction, and explicit revocation/connection-close actions without adding a file watcher. |
| 03A-06 | [`read_secret_file`](../crates/p2x-config/src/secret_file.rs) validates path metadata before opening, so a regular-file swap can bypass the checked mode/type; failed writes can leave secret temporary files. Bounded YAML uses `metadata` followed by `fs::read`, leaving the same size-check race, and anchor/alias rejection is a text heuristic without structural budgets. | Validate the opened descriptor, read through hard limits, clean temporary secrets on every failure, and make YAML bounds/duplicate/alias/depth checks parser-aware and race-safe. |
| 03A-07 | Requiring a ticket-key path does not prove its Ed25519 public key differs from the exchange transport key. `TicketKey.signing` is public, `verify_envelope` offers signature-only verification without binding context, and verification decodes twice then returns no validated claims/ticket ID. Binding, time/skew, and key-window tests are incomplete. | Enforce key separation, keep signing material private/redacted, expose only context-complete verification, select exactly one active key by envelope key ID, and return a validated ticket value usable by the future replay cache without reparsing. |
| 03A-08 | Product client/server exit immediately after the first `Pong`. `AuthState::disconnected` schedules no exchange redial, and the live `exchange-restart` case starts a new client instead of proving the original peer reconnects and re-authenticates. Backoff has no jitter. | Separate finite test mode from the long-running product owner; product readiness survives as state, drops on control loss, and is restored by bounded jittered reconnect plus re-authentication. |
| 03A-09 | [`tests/auth/local.sh`](../tests/auth/local.sh) hard-codes the pin-mismatch summary; `malformed` and `limits` run a valid live auth plus one unit test; rotation never installs a higher snapshot or revokes the old token; restart uses a new peer process; terminal cardinality and zero-resource cleanup are not schema-validated. | Replace every named case with an observed end-to-end condition and fail on missing/duplicate terminals, absent fault application, secret leakage, nonzero final logical resources, or a fresh process masquerading as recovery. |
| 03A-10 | [`auth-v1.md`](../docs/protocol/auth-v1.md) does not specify the byte layout, feature-bit policy, exact limits, or compatibility/error mapping, while [`identity-and-credentials.md`](../docs/security/identity-and-credentials.md) omits backup/restore, onboarding, key-separation, and concrete rotation procedures required by Plan 03. | Make the protocol and operator documents normative enough for Plans 04+ to consume without rediscovering Phase 1 rules. |

## 3. Required Result and Design Decisions

### 3.1 Explicit runtime modes and protocol surfaces

Add a shared, non-boolean mode to swarm configuration:

```text
RuntimeMode::Product
RuntimeMode::ConnectivityLab
```

Apply it in `ExchangeSwarmConfig`, `PeerSwarmConfig`, and all three app entrypoints.

- `ConnectivityLab` preserves the accepted relay, DCUtR, exact probe, and connectivity harness behavior and requires the existing unsafe acknowledgement flags.
- `Product` advertises `/p2x/auth/1` with exchange `Inbound` and client/server `Outbound` support only.
- `Product` does not advertise `/p2x/spike/1` and never dispatches a `ProbeOutput`.
- Until Plan 04 implements principal-aware relay admission, product mode must not expose an exchange relay reservation/circuit service or initiate a server relay reservation. If rust-libp2p cannot reject a relay request before allocating relay state, omit/toggle the relay behavior in product mode rather than accepting and closing afterward.
- Connectivity-lab protocol events must be structurally unreachable from product owner code, not guarded only by a late boolean inside the inbound event arm.

Use the smallest existing rust-libp2p composition that makes the supported protocol set observable, such as separate product/lab builders or `Toggle` behavior fields. Do not duplicate transport configuration or create more executable packages.

### 3.2 Exchange trust before credentials

Replace string-list pin checking with a validated `ExchangeTrustConfig` containing one parsed `PeerId` and a non-empty bounded list of `Multiaddr` values.

For each address:

1. require exactly one terminal `/p2p/<peer_id>` for a direct exchange dial;
2. reject a missing pin, a pin in the middle of a longer circuit address, multiple conflicting peer components, or trailing components;
3. compare the terminal peer to the configured pin;
4. retain the parsed address rather than reparsing unchecked CLI strings later.

Both client and server must complete identity and trust validation before reading the credential environment value. Prefer retaining only a validated `CredentialRef` until an authenticated `ConnectionEstablished` event confirms the expected exchange `PeerId`; then resolve the environment value and move a redacted, zeroizing secret into the bounded auth request. A static address mismatch and a runtime remote mismatch must both prove the credential value was not read or transmitted.

Support one or more exchange addresses through the existing CLI/config boundary, with deterministic bounded retry across them. Do not infer the exchange identity from a target server circuit address in product mode.

### 3.3 Closed auth domain and wire types

Refactor `p2x-protocol::auth` and `p2x-net::auth_codec` around validated domain values and private codec wire structs.

- `AuthRequest::Authenticate` owns `TokenSecret`, not a public raw array. Remove generic `Serialize`/`Deserialize` from secret-bearing domain messages.
- The codec creates a zeroizing bounded payload buffer, explicitly borrows the token only while encoding, writes the frame, flushes, closes the write half, and drops/zeroizes all token-bearing temporaries on every success/error path.
- Add a typed `AuthProtocolError` with stable mapping for frame-too-large, malformed, unsupported version, and capability mismatch. Convert to `io::Error` only at the request-response trait boundary; tests and lifecycle diagnostics retain the typed code and never attacker text.
- Define `KNOWN_AUTH_FEATURES_V1`. Because Phase 1 currently implements no optional features, any nonzero unknown/required request feature or response exchange feature is `protocol.capability_mismatch`. Future plans may add known bits without changing version 1 framing.
- Allocate wire request IDs through an injected checked monotonic `u128` correlation generator and encode them as big-endian `[u8; 16]`. Exhaustion is a typed terminal error. Keep session IDs CSPRNG-generated.
- Replace runtime `getrandom(...).expect(...)` calls in client, server, and exchange with fallible helpers whose errors prevent auth readiness.

The peer auth behavior must be outbound-only. Add a network test proving another peer cannot negotiate an inbound `/p2x/auth/1` request with a client or server.

### 3.4 Admission and session ownership

Move authoritative connection tracking into `AdmissionLedger`; remove the parallel `connection_ips` map from the exchange owner. The ledger must be keyed by libp2p `ConnectionId` and store the admitted peer and source IP.

Required transitions:

```text
ConnectionEstablished(connection_id, peer_id, source_ip)
BeginInbound(request_response_id, connection_id, peer_id, now)
ResponseDelivered(request_response_id, result, now)
ConnectionClosed(connection_id)
Sweep(now)
Shutdown
```

- Connection admission checks global, per-IP, and per-peer limits atomically. Rejection changes no counters.
- Closing an unknown or previously rejected connection is an idempotent no-op plus a bounded local diagnostic; it cannot decrement any admitted count.
- `BeginInbound` derives peer/IP from the admitted connection record and owns a permit keyed by the libp2p inbound request ID. A peer/body string cannot choose its bucket.
- Keep the permit until `ResponseSent`, response-channel failure, connection close, or shutdown. Release exactly once on all paths.
- If admission rejects a decoded request, send exactly one `AuthResponse::Rejected` containing the request's domain request ID when present and the returned `limit.auth_requests` or `exchange.overloaded` code. Do not `continue` while silently abandoning the response channel.
- Maintain bounded global and per-peer outbound request ownership in client/server by libp2p outbound request ID. Auth then Ping are sequential; stale response/failure events cannot release or advance the current request.
- Session connection counts are updated only for admitted connections. Final admitted connection close removes the session exactly once.

Add regression tests for the exact undercount sequence: fill at least two admitted connections, reject another at an IP/peer/global boundary, deliver its close event, and prove the admitted counts and next rejection remain unchanged.

### 3.5 Credential provider, policy, and revocation

Introduce the Plan 03 private provider interface around `authenticate(peer_id, presented, now) -> AuthPrincipal`; keep `FixedTokenProvider` as its only implementation.

- Validate credential records into typed IDs, peer IDs, roles, scopes, quota profiles, digest arrays, and times before constructing the installed snapshot.
- Define the v1 role/scope matrix explicitly: client credentials may hold `open_proxy_stream`; server credentials may hold `register_services` and `reserve_relay`. Reject cross-role scopes, unknown/duplicate scopes, and more than 32 scope bits.
- Give secret-bearing config types manual redacted `Debug`; token digests and environment values must not appear.
- Add `replace_snapshot(current, candidate, now)` that rejects a decreased revision and rejects changed binding/digest/status/scope/quota data without a strictly increased revision. An identical snapshot/revision is idempotent.
- Return explicit actions for every invalidated session: `PrincipalRevoked`, `ClosePeerConnections`, and Phase 2/3 handoff events. Test an owner adapter that consumes the close action for all current exchange connection IDs.
- Keep activation restart-based in v1. Do not add a watcher, signal reload, admin endpoint, or general dynamic configuration framework.

### 3.6 Descriptor-safe files and key separation

Refactor `p2x-config::secret_file` so validation applies to the opened file descriptor:

1. open with final-component no-follow;
2. call descriptor metadata/fstat;
3. require a regular, non-empty file, safe Unix mode, and the 4 KiB maximum;
4. read through a `MAX + 1` limiter and reject growth/truncation inconsistencies;
5. zeroize the returned temporary bytes after decoding private material.

Use an RAII temporary-file cleanup guard in `write_secret_file` so open, write, sync, install, and directory-sync failures do not leave private temporary files. Preserve same-directory, `0600`, no-clobber, concurrent-creator behavior; the losing creator reopens the installed destination.

Provide a separate bounded descriptor reader for digest-only YAML and public key rings. Enforce the 512 KiB limit during read, not only through pre-read metadata. Replace textual anchor/alias scanning with parser-aware rejection and bounded document/node/depth/scalar accounting, while retaining duplicate-key, one-document, strict-boolean, and `deny_unknown_fields` behavior.

After both keys are loaded, compare the exchange transport Ed25519 public key with the ticket signing public key and fail startup if equal. Make `TicketKey` signing material private; expose only redacted signing operations, derived key ID, and public verification material.

### 3.7 Context-complete ticket API

Keep the committed v1 bytes unchanged, but close the API around them.

- Make claims fields private and construct them through a validated constructor.
- Replace raw ticket `Vec<u8>` return values with a redacted bounded `RawTicket` wrapper that exposes bytes only through an explicit borrow.
- Make signature-only `verify_envelope` private/test-only. The public verifier always requires `TicketValidation` with issuer, client, server, tenant, upstream, selector fingerprint, registration revision, authorization revision, permissions, max streams, time, and clock skew.
- Decode the envelope once, select exactly one active verification key by its included key ID, verify its signature, validate every expected binding/time field, and return `VerifiedTicket` containing the validated claims and ticket ID. Unknown, inactive, retired, malformed, and invalid signatures map to `auth.ticket_invalid`; time expiry maps to `auth.ticket_expired`.
- Keep key-ring lookup bounded and exact; never try all keys.

Add tests for every binding mismatch, `now/skew/not_before/expires_at` boundary, lifetime overflow, activation/retirement edge, unknown key ID, incorrect key ID derivation, equal transport/signing keys, every signed-field mutation, envelope/claims bounds, truncation, trailing data, and raw-ticket/key/config redaction.

### 3.8 Long-running auth owner and finite test mode

Extract client/server auth ownership from the monolithic `main.rs` files into testable library modules while retaining one task as the sole swarm owner.

- Product mode stays running after Pong, publishes an authenticated readiness transition, and retains the current session only while its matching exchange control connection is valid.
- A dedicated explicit finite-auth-check option may emit one terminal and exit after Pong for the Phase 1 harness. It must not be the default product lifecycle.
- Matching exchange loss clears readiness/session state, cancels outstanding auth/Ping requests, and schedules a redial over the validated exchange address list using injected full-range jitter and capped exponential backoff.
- A successful redial performs a fresh Authenticate and correlated Ping before restoring readiness.
- Invalid credential, role, pin, and capability errors remain terminal until configuration changes; transport close, timeout, and overload follow only their declared retryability.
- Connectivity-lab mode keeps its existing finite probe lifecycle and does not instantiate the product auth-readiness owner unless explicitly requested by an auth test.

Test state/action tables for disconnect in every phase, stale response after reconnect, timeout versus response races, retry cap/jitter boundaries, request-ID exhaustion, two concurrent exchange connections, final-connection loss, and readiness generation changes.

## 4. Implementation Order

1. Add failing unit/integration tests for findings 03A-01 through 03A-09 before changing behavior. Preserve each regression as a named test.
2. Add `RuntimeMode` to swarm/app configuration; make product and connectivity-lab protocol surfaces distinct; set peer auth support to outbound-only.
3. Replace exchange trust parsing and reorder credential acquisition so all static and runtime pin checks precede token access.
4. Close auth domain/wire types, typed protocol errors, feature validation, zeroization, write-half closure, fallible randomness, and checked correlation IDs.
5. Refactor exchange admission around connection and request IDs, then connect response-delivery and session-close transitions to the owner.
6. Add the provider trait, exact scope policy, monotonic snapshot replacement, redacted config diagnostics, and revocation close actions.
7. Harden descriptor/YAML reads and temporary-file cleanup; enforce transport/ticket key separation.
8. Close the ticket signing/verification APIs and expand binding, time, key-window, and mutation coverage without changing the committed vector.
9. Extract the long-running client/server auth owner, add explicit finite mode, and implement same-process reconnect/re-authentication.
10. Replace the auth harness false positives, rerun affected connectivity gates, and finish normative documentation.

Do not begin registry or proxy work while implementing these steps. Plan 04 consumes the resulting authenticated principal, product-mode protocol surface, revocation actions, and validated ticket API only after this plan passes.

## 5. Verification

### 5.1 Local static and automated checks

Run from the repository root:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny --version
cargo deny check
cargo tree -e features
```

Run each fuzz target against its committed seed corpus for the repository's bounded CI duration:

```text
auth_frame_decode
token_parse
ticket_claims_decode
ticket_envelope_decode
```

A panic, unbounded allocation, leaked secret in diagnostics, accepted non-canonical value, or missing typed failure fails verification.

### 5.2 Protocol-surface and owner integration checks

Automated TCP and QUIC tests must prove:

- product exchange advertises inbound `/p2x/auth/1` but not relay service or `/p2x/spike/1`;
- product client/server advertise outbound `/p2x/auth/1` and reject inbound auth negotiation;
- connectivity-lab peers retain relay, DCUtR, and `/p2x/spike/1` behavior;
- no product probe/relay event reaches an app owner before the later authenticated handlers exist;
- a decoded request rejected by connection/request/rate/session admission receives exactly one stable public response;
- rejected and duplicate connection-close events cannot reduce admitted counts;
- token-bearing buffers are redacted and zeroized on encode success, encode failure, timeout, and cancellation;
- one long-running client and server lose readiness across an exchange restart and restore it after reconnect/auth/Ping without process replacement.

### 5.3 Canonical live auth cases

Keep `tests/auth/local.sh` as the entrypoint, but make each case apply and prove its named condition. Split combined aliases when necessary:

```text
./tests/auth/local.sh --case valid-client
./tests/auth/local.sh --case valid-server
./tests/auth/local.sh --case wrong-token
./tests/auth/local.sh --case wrong-peer
./tests/auth/local.sh --case wrong-role
./tests/auth/local.sh --case wrong-scope
./tests/auth/local.sh --case revoked
./tests/auth/local.sh --case expired
./tests/auth/local.sh --case pin-mismatch
./tests/auth/local.sh --case rotation-overlap
./tests/auth/local.sh --case rotation-revoke-old
./tests/auth/local.sh --case unsupported-version
./tests/auth/local.sh --case oversized-frame
./tests/auth/local.sh --case malformed-frame
./tests/auth/local.sh --case connection-limit
./tests/auth/local.sh --case request-limit
./tests/auth/local.sh --case session-limit
./tests/auth/local.sh --case exchange-restart
```

The harness must use run-scoped process groups and a schema-aware validator. It must derive summaries from observed lifecycle records rather than printing expected values. Pass only when:

- the fault/action named by the case is present in raw artifacts;
- applicable endpoints observe the same stable result code and correlation IDs;
- the pin-mismatch case proves the environment sentinel was not read and the exchange observed zero auth requests;
- rotation installs a higher snapshot, authenticates the new credential, revokes the old one, closes the old session, and proves the old token can no longer authenticate;
- malformed/version/oversize cases send real bytes over a negotiated live substream;
- limit cases reach the configured boundary concurrently and observe the correct rejection without counter drift;
- restart keeps the original client/server PIDs and PeerIds, observes readiness loss, and then observes a higher readiness generation after re-authentication;
- each finite peer emits exactly one terminal, long-running peers emit the expected readiness transitions, and shutdown returns connections, inbound/outbound requests, sessions, buckets, workers, and tasks to zero;
- no artifact contains token values, token digests, private keys, signing seeds, raw tickets, secret environment values, selectors, or private upstream addresses.

### 5.4 Connectivity non-regression

Because product/lab behavior composition and request-response support change, rerun at least the accepted local C01, C05, C10-128, and C13 gates on TCP and QUIC where applicable. Run the same cases in the canonical Linux namespace environment. If libp2p versions, transport features, relay behavior, DCUtR, Yamux, or the exact-stream handler change, rerun the complete ADR 0001 C01-C14 matrix instead.

Record environment-dependent Linux/macOS permission, symlink/swap, identity backup/restore, transport-key replacement, and packet/log inspection as owner-executed checks. Do not claim them from unit tests running on only one host OS.

## 6. Documentation Updates

Expand [`docs/protocol/auth-v1.md`](../docs/protocol/auth-v1.md) with:

- byte-exact request/response layouts and integer/string encodings;
- frame, field, connection, request, session, and failure-bucket default/hard limits;
- product versus connectivity-lab protocol surfaces;
- feature-bit policy and version/capability compatibility rules;
- typed decode/failure-to-public-code mapping;
- request/session correlation and retryability rules;
- the complete stable public error table.

Expand [`docs/security/identity-and-credentials.md`](../docs/security/identity-and-credentials.md) with explicit identity onboarding, backup/restore, pin distribution and transport-key replacement, token generation/digest provisioning, add/deploy/observe/revoke rotation, revision rules, immediate-versus-bounded revocation effects, transport/ticket key separation, ticket verification-ring rotation, native Unix permission expectations, and recovery from rejected unsafe files.

Document that product relay admission, registry consumption of `AuthPrincipal`, ticket issuance, replay defense, and proxy authorization remain blocked for Plan 04+ rather than silently using connectivity-lab paths.

## 7. Definition of Done

- Findings 03A-01 through 03A-10 are closed by code and named regression tests.
- Product mode exposes only the Phase 1 auth surface; Phase 0 probe/relay facilities remain available only in explicit connectivity-lab mode.
- Exchange pins are validated before token access, and authenticated remote identity is authoritative for every auth request.
- Secret values and digests are private, redacted, bounded, and zeroized across config, domain, codec, cancellation, and diagnostic paths.
- Admission/session accounting is keyed to authoritative connection/request IDs, never undercounts, releases exactly once, and returns stable rejection responses.
- Credential replacement is revision-monotonic; role/scope policy is exact; revocation invalidates the session and produces connection-close/handoff actions.
- Exchange transport and ticket signing keys are cryptographically distinct; the only public ticket verification API validates all bindings/time/key state and returns a validated ticket without reparsing.
- Product client/server remain alive after readiness and recover from an exchange restart with the same PID and PeerId; finite exit exists only as an explicit test mode.
- Every canonical auth case applies a real live condition, derives its summary from schema-valid observations, scans secrets, and proves zero logical-resource cleanup.
- Static checks, fuzz smoke, live auth cases, required connectivity regressions, and owner-executed platform security checks pass.
- Only after all conditions above pass may Plan 03 be marked complete and planning proceed to the next Phase 2 work package from [`00-product-analysis.md`](00-product-analysis.md).
