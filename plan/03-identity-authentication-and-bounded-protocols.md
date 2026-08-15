# Plan: Identity, Authentication, Tickets, and Bounded Control Protocols

- **Document status:** implementation-ready; Phase 0 gate accepted on 2026-08-15
- **Scope:** Phase 1 from [`00-product-analysis.md`](00-product-analysis.md) §24
- **Depends on:** [`01-connectivity-spike-and-libp2p-design.md`](01-connectivity-spike-and-libp2p-design.md), corrective Plans 02–02d, and ADR 0001
- **Required outcome:** authenticated peers can exchange one bounded control ping; persistent identities, fixed-token authorization, deterministic tickets, public errors, and secret redaction are ready for later registry/proxy phases

## 1. Goal and Scope

Implement the smallest security and protocol foundation on top of the proven `libp2p` swarm:

1. persist a distinct Ed25519 transport identity for each exchange, client, and server process;
2. require clients and servers to pin the exchange `PeerId` before sending credentials;
3. authenticate each peer with one high-entropy fixed token bound to its transport `PeerId`, tenant, role, scopes, and quota profile;
4. encode every authentication/control frame with an explicit protocol version and hard pre-allocation size limit;
5. define stable public errors independently of internal error chains;
6. persist an exchange ticket-signing key distinct from the transport identity;
7. define deterministic ticket bytes, signatures, key IDs, validation, and committed test vectors;
8. prove the complete path with valid, invalid, mismatched, expired, rotated, revoked, oversized, malformed, and concurrent requests.

This plan does not implement service registration, selector resolution, relay authorization, ticket issuance from registry state, ticket replay consumption, proxy streams, or ingress adapters. It provides the types and authenticated control boundary those phases will call.

The existing probe protocol remains a Phase 0 lab facility. It must not become an authentication bypass in product mode.

## 2. Current State and Constraints

### 2.1 Phase 0 gate outcome

The Phase 0 gate is satisfied:

- [`docs/adr/0001-rust-libp2p-connectivity.md`](../docs/adr/0001-rust-libp2p-connectivity.md) is `Accepted — custom exact-connection handler required`;
- [`plan/evidence/01-connectivity-spike-results.md`](evidence/01-connectivity-spike-results.md) records passing native macOS C01 and C05–C13 runs;
- canonical Linux namespace C02–C13 summaries report `passed: true`;
- C14 passed between native Linux and macOS hosts on separate networks;
- the product owner confirmed the complete Plan 02 test set and accepted ADR 0001 on 2026-08-15.

Implementation may proceed from the accepted, committed connectivity baseline. Preserve these gate conditions:

1. keep the custom exact-connection behaviour/handler as required architecture;
2. preserve the accepted relay/DCUtR, timeout, half-close, concurrency, renewal, and cleanup invariants;
3. rerun the affected gate cases if a connectivity dependency or behaviour changes;
4. begin Phase 1 from a committed baseline with only intentional Plan 03 changes in the worktree.

The evidence acceptance removes the implementation blocker; it does not waive the Plan 03 verification and non-regression work in §5.

### 2.2 Confirmed repository baseline

| Area | Current implementation | Required Phase 1 change |
| --- | --- | --- |
| Workspace | Three apps and only `p2x-net` as a shared crate | Add `p2x-protocol` and `p2x-config`; keep exactly three executable packages |
| Identity | `p2x_net::builder::lab_identity(seed)` generates deterministic lab keys | Product mode loads a persisted key; creation requires an explicit onboarding flag |
| Exchange trust | `ConnectionBook` validates the exchange identity embedded before `/p2p-circuit` | Also require one configured exchange pin for every direct exchange dial and auth session |
| Swarm | Relay, DCUtR, Identify, Ping, and exact probe behaviours | Add a bounded `/p2x/auth/1` request-response behaviour without changing exact probe selection |
| Authentication | None | Fixed-token provider plus bounded authenticated-session state |
| Tickets | None | Deterministic claims/envelope codec, Ed25519 signer/verifier, key ring, and vectors |
| Protocol errors | Probe-specific terminal enums and lifecycle strings | Shared stable `PublicErrorCode` registry and non-secret wire error |
| Config | Lab-oriented CLI flags | Add validated secret/key/trust primitives and minimal component config; retain lab options only behind explicit unsafe lab mode |
| Tests | Connectivity matrix and exact-connection integration | Preserve that matrix and add identity, auth, codec, ticket, redaction, and live control tests |

`p2x-net` is already structured around one task owning each `Swarm`. Authentication events must preserve that ownership model; no task may lock or poll a shared swarm.

### 2.3 Normative inherited decisions

- Initial enrollment uses one unique fixed token per peer.
- A token is bound to exactly one `PeerId`, tenant, role, scope set, and quota profile.
- The exchange transport key and ticket-signing key are distinct and durable.
- The exchange is a single instance in v1.
- Every application protocol is versioned in its libp2p protocol ID.
- All frames, fields, pending operations, sessions, and caches are bounded.
- Network timestamps use UTC Unix seconds and an injected `now` in tests.
- Stable public codes cross the wire; internal causes stay in local structured diagnostics.
- Private keys, token material, token digests, tickets, selectors, and upstream addresses never appear in `Debug`, `Display`, logs, metrics labels, or lifecycle artifacts.

## 3. Required Architecture and Invariants

### 3.1 Workspace boundaries

Add these library crates:

```text
crates/p2x-protocol/
  src/auth.rs          # public auth/control domain messages and validation
  src/error.rs         # stable public code registry and retry classification
  src/frame.rs         # bounded length-prefix helpers used by codecs
  src/ids.rs           # validated tenant, upstream, request, session, and ticket IDs
  src/ticket.rs        # canonical claims/envelope bytes and Ed25519 verification
  testdata/ticket-v1.json

crates/p2x-config/
  src/identity.rs      # secure libp2p identity load/create
  src/secret_file.rs   # bounded, no-follow, permission-checked secret files
  src/credential.rs    # environment token reference and fixed-token file schema
  src/trust.rs         # pinned exchange identity/address validation
  src/yaml.rs          # bounded strict YAML loading
```

Keep runtime integration in existing owners:

```text
crates/p2x-net/src/auth_codec.rs
apps/p2x-exchange/src/authn.rs
apps/p2x-exchange/src/auth_sessions.rs
apps/p2x-exchange/src/config.rs
apps/p2x-client/src/exchange_auth.rs
apps/p2x-server/src/exchange_auth.rs
```

`p2x-protocol` must not depend on Tokio or the libp2p swarm. It may depend on `libp2p-identity`/`PeerId` types only if that avoids a second peer-ID parser; it must not depend on the full `libp2p` feature set. `p2x-config` owns file parsing and secret acquisition, not authentication decisions. The fixed-token provider and authenticated-session ledger remain exchange-owned modules.

Convert each app package to a thin `main.rs` plus `lib.rs` only as needed for integration tests. This does not add an executable.

### 3.2 Persistent identities and exchange pinning

Use `libp2p::identity::Keypair::{to_protobuf_encoding, from_protobuf_encoding}` for transport identity files. The loader must enforce:

- a hard 4 KiB file limit before allocation/read completion;
- a regular file opened without following a final symlink on Linux and macOS;
- no group/other permission bits on Unix (`mode & 0o077 == 0`);
- Ed25519 only for newly generated product identities;
- exact decode with no silent regeneration on missing, empty, malformed, unsupported, or permission-unsafe files;
- explicit `generate_if_missing: true` as the only production onboarding path;
- creation through a same-directory temporary file using `create_new`, mode `0600`, file sync, atomic rename, and parent-directory sync;
- a typed result containing the keypair, derived `PeerId`, and a non-secret public fingerprint.

Concurrent creators must not overwrite one another. The loser reopens and validates the completed destination or returns a stable onboarding conflict; it never installs a second identity.

Every client/server exchange configuration contains one `peer_id` and one or more complete exchange multiaddresses. Validate at startup that every address ends in the same `/p2p/<peer_id>`. On an exchange `ConnectionEstablished` event, compare the authenticated remote `PeerId` to the configured pin before emitting an auth request. A mismatch closes the connection, records `auth.exchange_identity_mismatch`, and never reads or transmits the token.

Keep deterministic seeded identities only for `--unsafe-connectivity-lab`. Reject that option in product mode and reject accidental public exchange use unless the existing unsafe public-lab acknowledgement is also present.

### 3.3 Fixed-token credential model

The peer secret supplied through `credential_env` uses this bounded representation:

```text
p2x1.<credential_id>.<base64url-no-pad 32-byte secret>
```

- `credential_id` is 1–64 ASCII characters matching `^[a-zA-Z0-9_-]+$`;
- the decoded secret is exactly 32 bytes generated by an OS CSPRNG;
- parsing rejects whitespace, alternate base64 alphabets, padding, trailing data, and unsupported prefixes;
- token wrappers own a fixed-size zeroizing buffer, expose bytes only through an explicit borrow, implement redacted `Debug`, and do not implement `Display`, `Serialize`, or `Clone`.

The exchange fixed-token file stores no plaintext token:

```yaml
schema_version: 1
authorization_revision: 7
credentials:
  - credential_id: server-orders-2026q3
    token_sha256: "<base64url-no-pad 32-byte digest>"
    peer_id: "12D3KooW..."
    tenant: production
    role: server
    scopes: [register_services, reserve_relay]
    quota_profile: standard-server
    not_before: 1786752000
    expires_at: 1798761600
    revoked: false
```

Use the domain-separated digest `SHA-256("p2x-fixed-token-v1\0" || secret)` and `subtle::ConstantTimeEq` over fixed `[u8; 32]` arrays. The input secret has 256 bits of entropy, so a deliberately fast digest is acceptable; do not replace it with a password KDF or accept human passwords.

Validate the entire provider snapshot before installing it:

- at most 256 credential records and a 512 KiB file;
- unique credential IDs;
- exactly one peer/tenant/role binding per credential;
- role is `client` or `server`;
- scopes are known, unique, role-compatible enum values with at most 32 bits;
- quota profile names are 1–64 bounded identifiers;
- `not_before < expires_at`, with a maximum credential lifetime of 400 days;
- `authorization_revision` increases whenever an installed binding, status, scope, or quota changes.

Define a private `CredentialProvider` trait around `authenticate(peer_id, presented, now) -> AuthPrincipal`; implement `FixedTokenProvider` with an immutable validated snapshot. Do not expose registry or relay types through this interface.

Unknown IDs, wrong secrets, revoked credentials, expired credentials, and peer mismatches all return the same wire code `auth.invalid_credential`. Local audit records may distinguish the reason, but must contain only credential-ID and peer-ID fingerprints. A dummy fixed digest comparison must run for unknown IDs so lookup outcome does not skip the constant-time comparison path.

### 3.4 Authentication sessions and rotation/revocation

An accepted credential creates an exchange-local session:

```text
AuthPrincipal {
  peer_id,
  credential_id,
  tenant,
  role,
  scopes,
  quota_profile,
  authorization_revision,
  credential_expires_at,
}

AuthSession {
  session_id: [u8; 16],
  principal,
  established_at,
  expires_at,
}
```

Generate session IDs with an OS CSPRNG. Cap sessions at 256 globally and one current session per `PeerId`; successful re-authentication atomically replaces the same peer's prior session. Session expiry is the earliest of 15 minutes, credential expiry, or provider invalidation. Sweep expired sessions on a fixed interval and on every lookup; do not rely on network events alone.

State rules:

- no non-auth control operation is processed without a current session and matching session ID;
- when a peer's final exchange connection closes, remove its session;
- a provider snapshot replacement invalidates sessions whose credential disappeared, changed binding/digest, became inactive, or has an older authorization revision;
- rotation is performed by adding a second credential for the same peer, deploying the new peer token, observing successful re-authentication, then revoking/removing the old credential in a higher provider revision;
- revocation immediately denies new control work and closes that peer's exchange connections;
- Phase 2 must consume the resulting revocation event to withdraw registrations and relay admission;
- Phase 3 must stop issuing tickets. Already issued tickets remain bounded by their short expiry; active direct streams cannot be centrally recalled by the single exchange and are not promised immediate termination.

The initial provider is loaded at process start. Provide a tested `replace_snapshot` API, but do not add a file watcher or general dynamic application-config reload in this phase. A controlled exchange restart is the v1 activation mechanism until an authenticated admin/reload design exists.

### 3.5 Bounded `/p2x/auth/1` protocol

Enable the pinned libp2p `request-response` feature and add `AuthCodec` in `p2x-net`. Use one protocol ID:

```text
/p2x/auth/1
```

The exchange advertises inbound support; clients and servers advertise outbound support. Each request uses one substream as provided by rust-libp2p request-response. Set the behaviour request timeout to 5 seconds. The app owner, not the codec, enforces one in-flight auth/control request per peer, 128 global inbound requests, 128 global outbound requests, and checked monotonic local request correlation.

Frame format is `u32` big-endian payload length followed by exactly that many bytes. `MAX_AUTH_FRAME = 4096`. The codec must:

1. read exactly four length bytes under the request-response deadline;
2. reject zero length and values above 4096 before allocating the payload;
3. allocate only the declared bounded length and `read_exact` it;
4. decode one versioned message and reject missing required fields, invalid enum values, duplicate one-of bodies, non-canonical token encoding, and trailing payload bytes;
5. encode into a bounded temporary buffer, check size, write length and body, flush, and close the write half;
6. map I/O/decode failures to local typed causes without echoing attacker-controlled text.

Use private wire structs plus explicit conversion into validated public domain types. Do not derive or expose secret-bearing `Debug`. Unknown optional fields may be ignored only inside protocol version 1; unknown required message kinds, feature bits, or versions return `protocol.unsupported_version` or `protocol.capability_mismatch`.

Version 1 contains only:

```text
AuthRequest::Authenticate {
  request_id: [u8; 16],
  credential_id,
  token_secret: [u8; 32],
  requested_role,
  supported_features: u64,
}

AuthRequest::Ping {
  request_id: [u8; 16],
  session_id: [u8; 16],
  nonce: u64,
}

AuthResponse::Authenticated {
  request_id,
  session_id,
  tenant,
  role,
  scopes: u32,
  quota_profile,
  authorization_revision,
  expires_at,
  exchange_features: u64,
}

AuthResponse::Pong {
  request_id,
  nonce,
  exchange_time,
}

AuthResponse::Rejected {
  request_id?,
  error: PublicError,
}
```

The transport-authenticated event `PeerId` is authoritative. Do not send or trust a peer ID in `Authenticate`. A successful response must echo the request ID; peers ignore stale/unknown response IDs and must not transition to authenticated. `Ping` succeeds only when the session ID belongs to that event's `PeerId` and is current.

### 3.6 Admission and failure bounds

Before executing credential validation, the exchange owner maintains bounded connection/admission ledgers:

| Limit | Default | Hard maximum |
| --- | ---: | ---: |
| Established exchange connections | 256 | 512 |
| Connections per source IP | 8 | 32 |
| Connections per authenticated peer | 2 | 4 |
| In-flight inbound auth requests | 128 | 256 |
| In-flight requests per peer | 1 | 2 |
| Auth sessions | 256 | 512 |
| Tracked peer/IP failure buckets | 1,024 | 4,096 |
| Failed auth attempts per peer/IP window | 10/minute | 60/minute |

Reject at admission rather than queueing past the bound. Expiring rate buckets use a deterministic sweep and never evict an unexpired bucket merely to admit an attacker-controlled key. If the bounded tracking ledger is full, fail closed with `exchange.overloaded` and keep existing authenticated work available.

Source IP is derived from the authoritative `ConnectedPoint`, never from Identify or request content. Track connection IDs to IPs on establish/close; if an auth request cannot be mapped safely because the peer has ambiguous active endpoints, charge the peer bucket and the strictest applicable IP bucket rather than inventing an address.

### 3.7 Deterministic connection ticket format

Define `ConnectionTicketClaimsV1` now so registry and proxy phases do not invent incompatible signing bytes later:

```text
version: u16 = 1
issuer_exchange_peer_id
tenant
client_peer_id
server_peer_id
upstream_id
selector_fingerprint: [u8; 32]
registration_revision: u64
authorization_revision: u64
permissions: u32              # v1 requires OPEN_PROXY_STREAM only
not_before: i64               # UTC Unix seconds
expires_at: i64
ticket_id: [u8; 16]
max_streams: u16              # v1 requires 1
```

The extra `authorization_revision` binds issuance to the credential/provider generation and gives later phases an explicit stale-authorization check. It does not promise instant revocation at disconnected servers.

Use a manually specified canonical binary encoding, not YAML/JSON or generic map serialization:

- integers are unsigned/signed fixed-width big-endian values;
- `PeerId` uses `PeerId::to_bytes()` and a one-byte length;
- UTF-8 identifiers use a two-byte length and their validated bytes;
- fixed arrays have no length prefix;
- fields appear exactly in the order above;
- decoders reject non-minimal/invalid IDs, invalid UTF-8, values outside domain limits, unknown permission bits, trailing bytes, and a non-canonical decode/re-encode result;
- `MAX_TICKET_CLAIMS = 1024` and `MAX_TICKET_ENVELOPE = 2048`.

Ticket envelope v1 is:

```text
magic "P2XT" | envelope_version u8 | key_id_len u8 | key_id |
claims_len u16 | claims | Ed25519 signature [64]
```

Sign exactly:

```text
"p2x-ticket-v1\0" || claims_len_u16_be || claims
```

Ticket signing uses an Ed25519 key distinct from the libp2p identity. Derive `key_id` as the lowercase hex of the first 16 bytes of `SHA-256(public_key)` so it cannot drift from key material. Store the 32-byte signing seed in a versioned, permission-checked secret file; derive and verify the public key on load. A verifier key ring contains only public keys, activation times, and retirement times.

Defaults and hard validation:

- ticket lifetime default 30 seconds, maximum 60 seconds;
- clock skew default 5 seconds, maximum 30 seconds;
- `not_before <= expires_at`, lifetime within the maximum, issuer equals the pinned exchange, and current time is within the skew-adjusted window;
- client, server, tenant, upstream, selector fingerprint, registration revision, authorization revision, permission, and `max_streams` are checked by explicit validator inputs rather than optional follow-up checks;
- one-use replay admission remains a Phase 3 server responsibility, but `ticket_id` and expiry are available without reparsing unbounded data.

For rotation, issue only with the current signing key. Keep the previous public key verifiable through its last issued ticket expiry plus maximum skew. Never select a verification key by trying every key; require a known `key_id`. Unknown, retired, malformed, or invalid signatures use the same public `auth.ticket_invalid` code.

Commit `crates/p2x-protocol/testdata/ticket-v1.json` with an explicitly non-production deterministic signing seed, all claims, canonical claims hex, signature hex, and full envelope hex. Unit tests must reproduce it byte for byte and verify one-byte mutation failures for every signed field.

### 3.8 Public errors and redaction

Implement a non-exhaustive internal mapping around a stable wire enum/string registry. Phase 1 owns at least:

```text
auth.invalid_credential
auth.exchange_identity_mismatch
auth.session_required
auth.session_expired
auth.role_forbidden
auth.ticket_invalid
auth.ticket_expired
exchange.overloaded
exchange.timeout
limit.auth_connections
limit.auth_requests
limit.auth_sessions
protocol.frame_too_large
protocol.malformed
protocol.unsupported_version
protocol.capability_mismatch
```

`PublicError` contains only `code` and `retryable`; do not put arbitrary messages or source chains on the wire. `PublicErrorCode::as_str()` is stable and has round-trip tests. Unknown received codes map to `protocol.malformed` locally rather than being reflected.

Create explicit redacted wrappers for token, token digest, private key, signing key, raw ticket, and secret-bearing config. Tests must format every public config/error/auth type through `Debug` and `Display` where implemented and assert that known sentinel secrets, full digests, raw ticket bytes, and environment values do not appear. Lifecycle records may include peer ID, credential-ID fingerprint, key ID, role, result code, and authorization revision; they may not include token material or a raw ticket.

## 4. Implementation Plan

### 4.1 Freeze the accepted baseline and dependencies

- Record the accepted ADR commit at the top of the implementation PR and preserve the evidence baseline while implementing.
- Add `p2x-protocol` and `p2x-config` to [`Cargo.toml`](../Cargo.toml).
- Enable libp2p's `request-response` feature without changing the accepted `libp2p = 0.56.0` version unless ADR 0001 explicitly selects another version.
- Add direct, workspace-pinned dependencies for Ed25519 signing, SHA-256, constant-time equality, base64url, zeroization/secret wrappers, strict bounded YAML parsing, secure Unix no-follow file opening, and test temporary directories.
- Prefer already resolved compatible crates in `Cargo.lock`, but declare every crate used directly rather than relying on transitive dependencies.
- Run `cargo tree -e features`, `cargo deny check`, and license review before implementation. Any libp2p component change invalidates the connectivity evidence and requires the ADR matrix to be rerun.

### 4.2 Build validated protocol primitives first

- Add IDs, roles, scopes, features, quota-profile references, Unix time, and public errors in `p2x-protocol`.
- Give every string/byte constructor a bound and validation error; keep fields private so invalid values cannot be assembled with a struct literal.
- Implement canonical token parsing and redacted secret wrappers.
- Implement bounded frame helpers and auth domain/wire conversion independently from libp2p I/O.
- Add table tests for every minimum, maximum, maximum+1, invalid character, unknown bit, unknown enum, unsupported version, duplicate body, truncated body, and trailing byte.

### 4.3 Implement secret files and strict configuration

- Build `p2x-config::secret_file` and identity load/create before changing any app entrypoint.
- Parse YAML only after enforcing file size. Configure duplicate-key rejection, merge-key rejection, strict booleans, alias/event budgets, and one-document-only parsing; apply `#[serde(deny_unknown_fields)]` at every config layer.
- Implement `IdentityConfig`, `ExchangeTrustConfig`, `CredentialRef`, `FixedTokenFile`, and `TicketKeyConfig` with aggregated semantic validation.
- Ensure an explicit missing/unreadable config is fatal, an absent environment variable is fatal, and diagnostics name the field/reference without printing its resolved value.
- Test real Unix modes, symlinks, oversize files, concurrent create, crash-safe replacement boundaries, wrong key types, pin/address disagreement, and environment redaction. Gate Unix-specific tests with platform cfg while keeping Linux and macOS behavior equivalent.

### 4.4 Implement fixed-token provider and session ledger

- Add exchange `authn.rs` with `CredentialProvider`, immutable `FixedTokenProvider`, digest validation, role/scope checks, and provider replacement diff.
- Add `auth_sessions.rs` with the bounded peer/session/rate ledgers, injected time/randomness, deterministic sweeps, and typed `Authenticate`, `AuthorizeControl`, `ConnectionClosed`, `ProviderReplaced`, and `Shutdown` transitions.
- Make every transition return explicit actions such as `SendResponse`, `ClosePeer`, `PrincipalAuthenticated`, `PrincipalRevoked`, `Reject`, and `Audit`; do not perform network I/O while mutating the ledger.
- Test replacement, rotation overlap, revocation, final-connection removal, cap exhaustion, rate boundaries, session-ID mismatch, stale revision, request duplication, and exactly-once removal.

### 4.5 Implement deterministic tickets and keys

- Implement canonical claims and envelope encode/decode in `p2x-protocol::ticket`.
- Add ticket secret-key load/create and public verification-key-ring parsing in `p2x-config`.
- Implement `TicketSigner` and explicit-context `TicketVerifier`; never offer a weak `verify(ticket)` API that omits expected peer/service/revision inputs.
- Generate and review the committed v1 test vector. Add mutation tests, wrong key/issuer/binding tests, time/skew boundaries, key activation/retirement tests, oversize/truncation/trailing tests, and fuzz targets for claims/envelope decoding.
- Do not connect ticket issuance to a fake registry. Phase 3 will construct claims only inside atomic resolve-and-authorize.

### 4.6 Add the auth behaviour to `p2x-net`

- Implement the request-response `Codec` in [`crates/p2x-net/src/auth_codec.rs`](../crates/p2x-net/src/auth_codec.rs) using the `p2x-protocol` frame/domain conversions.
- Add the behaviour to both structs in [`crates/p2x-net/src/builder.rs`](../crates/p2x-net/src/builder.rs), add typed `ExchangeEvent::Auth`/`PeerEvent::Auth`, set inbound/outbound support by component, and apply the five-second timeout.
- Change protocol-surface tests: `/p2x/auth/1` is now required while rendezvous, AutoNAT, WebSocket, UPnP, and registry/proxy protocols remain absent. Keep `/p2x/spike/1` only in explicit connectivity-lab configuration.
- Add same-process network tests proving bounded request/response over TCP and QUIC, incompatible protocol rejection, timeout, malformed/oversized inbound frames, request cap release, and no impact on exact direct/relay probe selection.

### 4.7 Integrate exchange, client, and server owners

- Split each app enough that the swarm loop can be integration-tested without invoking CLI parsing.
- Exchange loads identity, ticket key, and fixed-token snapshot before binding public listeners. It handles auth behaviour events through `AuthSessionLedger`, sends exactly one response, closes rejected/mismatched peers when required, and sweeps sessions/rate buckets on an interval.
- Client and server load their identity and credential secret before networking, validate all exchange addresses against the pin, and keep a small `ExchangeAuthState` (`Disconnected`, `Authenticating`, `Authenticated`, `Backoff`).
- On pinned exchange connection, send one `Authenticate`; after `Authenticated`, send one correlated `Ping`; publish Phase 1 readiness only after `Pong` succeeds. Credential errors are terminal until configuration changes; transport/timeouts retry with bounded jittered backoff.
- Never include the token in a command/event that can be cloned into an unbounded queue. Move one owned secret into the bounded auth request encoding path and zeroize temporary wire buffers immediately after write.
- Product mode rejects missing auth configuration. Connectivity-lab mode remains explicit, emits `unsafe_lab_mode: true`, and cannot call future registry/resolve/proxy handlers.

### 4.8 Preserve and extend executable tests

- Update `tests/local/common.sh`, canonical connectivity scripts, namespace scripts, and C14 scripts only as needed to pass the renamed explicit lab mode. Do not weaken their existing schema/path/resource assertions.
- Add `tests/auth/local.sh` as the canonical finite three-process Phase 1 test. It creates run-scoped product identity files and fixed-token configuration, runs exchange/server/client on loopback, waits for authenticated ping terminals, validates exactly one terminal per finite peer, and verifies cleanup.
- Cases must include valid client/server, wrong token, token bound to the wrong `PeerId`, wrong role/scope, revoked/expired token, exchange pin mismatch with proof that no credential was sent, rotated token overlap, unknown protocol version, 4097-byte frame, request/session capacity, and exchange restart followed by re-authentication.
- Write only scrubbed NDJSON below `target/p2x-auth/<run-id>/`; validator rejects any occurrence of injected sentinel secrets or raw token/ticket fields.

### 4.9 Documentation and handoff contracts

- Add a versioned protocol document under `docs/protocol/auth-v1.md` containing the exact frame/message limits, feature bits, public error codes, and compatibility rules.
- Add `docs/security/identity-and-credentials.md` covering secure key creation, backups, exchange-pin distribution, token generation/digest provisioning, rotation order, revocation limitations, and file permissions.
- Document that the fixed-token file is exchange-only and contains digests; peer YAML references an environment variable, not the token value.
- Add comments/TODO handoff points only where Phase 2/3 integration is required: authenticated principal into registry/relay admission, revocation event consumption, atomic ticket issuance, verification-key distribution, and replay cache ownership.
- Update `deny.toml` with only reviewed licenses/advisories and removal conditions. Do not broaden existing ignores.

## 5. Verification

### 5.1 Local automated checks

Run from the repository root with the accepted toolchain and lockfile:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny --version
cargo deny check
cargo tree -e features
```

Add fuzz targets for auth frame decode, fixed-token parsing, ticket claims decode, and ticket envelope decode. Run each against its seed corpus and a bounded CI duration; a panic, allocation above the input limit, or accepted non-canonical value fails.

### 5.2 Phase 1 live checks

```text
./tests/auth/local.sh --case valid-client
./tests/auth/local.sh --case valid-server
./tests/auth/local.sh --case wrong-token
./tests/auth/local.sh --case wrong-peer
./tests/auth/local.sh --case wrong-role
./tests/auth/local.sh --case revoked
./tests/auth/local.sh --case expired
./tests/auth/local.sh --case pin-mismatch
./tests/auth/local.sh --case rotation
./tests/auth/local.sh --case malformed
./tests/auth/local.sh --case limits
./tests/auth/local.sh --case exchange-restart
```

Pass conditions for every live case:

- expected success or stable public failure code is observed by both applicable endpoints;
- success includes matching request ID, session ID ownership, role, authorization revision, nonce, and one `Pong`;
- failure never transitions readiness to authenticated;
- invalid pin transmits zero auth requests;
- no artifact contains the sentinel token, digest, private key, raw ticket, or secret environment value;
- pending requests, sessions, connection/IP entries, and tasks return to zero/baseline after shutdown.

### 5.3 Connectivity non-regression

Run the canonical local matrix after the auth behaviour is composed into swarms:

```text
./tests/connectivity/local.sh --case C01 --exchange-transport tcp
./tests/connectivity/local.sh --case C01 --exchange-transport quic
./tests/connectivity/local.sh --case C05
./tests/connectivity/local.sh --case C06
./tests/connectivity/local.sh --case C07
./tests/connectivity/local.sh --case C08
./tests/connectivity/local.sh --case C09
./tests/connectivity/local.sh --case C10 --streams 128
./tests/connectivity/local.sh --case C11 --bytes 268435456 --path direct
./tests/connectivity/local.sh --case C11 --bytes 268435456 --path relay
./tests/connectivity/local.sh --case C12
./tests/connectivity/local.sh --case C13 --iterations 100
```

If libp2p or any accepted connectivity component changed, rerun the full Linux C02–C13 and C14 architecture gates before accepting Phase 1. Adding only the request-response feature still requires at least C01, C05, C10, and C13 on Linux because the composed behaviour changes protocol negotiation and concurrency.

### 5.4 Owner-executed security checks

After local tests pass, the owner performs and records:

1. backup/restore of all three identity files without `PeerId` change;
2. exchange transport-key replacement causing the old peer pin to fail closed;
3. token rotation using the add/deploy/observe/revoke order;
4. ticket signing-key rotation with old tickets valid only through the declared overlap;
5. file-permission and symlink attacks on native Linux and macOS;
6. packet/log/artifact inspection showing credentials are encrypted on the wire by libp2p and absent from application diagnostics.

## 6. Definition of Done

- Phase 0 gate §2.1 was accepted before the first implementation change.
- Product startup never generates or replaces an identity unless `generate_if_missing` is explicit.
- Restart and backup/restore preserve each component `PeerId`; unsafe/malformed identity files fail closed.
- Peers validate the exchange pin before transmitting credentials.
- Fixed tokens are unique, 256-bit, digest-only at exchange, constant-time compared, bound to peer/tenant/role/scope/quota, zeroized in memory where owned, and redacted everywhere.
- Rotation and revocation transitions have deterministic tests and documented limits.
- `/p2x/auth/1` frames, fields, pending operations, failure buckets, and sessions enforce the stated bounds.
- A valid client and server authenticate and complete one correlated `Ping`/`Pong`; all invalid cases fail with stable public codes and no readiness.
- Ticket v1 encoding/signature reproduces the committed vector byte for byte and rejects all binding/time/key/mutation failures.
- Exchange transport and ticket-signing keys are distinct and independently rotatable.
- Static checks, fuzz smoke, live auth cases, secret scans, and required connectivity regressions pass with zero leaked logical resources.
- No registry, resolve, relay admission, or proxy implementation can execute without an `AuthPrincipal`; their actual handlers remain for Plans 04 and later.

## 7. Open Decision Required

The approved product license family is AGPL, but the repository still has no precise SPDX choice. The owner must select either `AGPL-3.0-only` or `AGPL-3.0-or-later` before Phase 1 is distributed and before removing the current cargo-deny exception for unpublished workspace packages. That choice determines the root `LICENSE`, package `license` fields, notices, and source-offer wording; implementation must not guess it.
