# Plan: Authenticated Exchange Registry and Server Availability

- **Document status:** implementation-ready
- **Scope:** Phase 2 from [`00-product-analysis.md`](00-product-analysis.md) §24
- **Depends on:** completed Plans 01–03/03a and accepted ADR 0001
- **Required outcome:** an authenticated private server acquires an authorized relay reservation, atomically registers an exact tenant-scoped service set, remains current through lease refresh and auth renewal, and automatically restores reservation, registration, and readiness after exchange or network loss

The Stage 1 work-package filenames in §25 predate the corrective 02/03a plans. The implemented repository sequence is authoritative: Plan 03 completed Phase 1 identity/authentication and explicitly hands Plan 04 the Phase 2 registry, relay-admission, and server-availability work. Plan 04 therefore follows §24 Phase 2 rather than using the old §25 item-4 client-ingress title.

## 1. Goal and Scope

Implement the smallest complete Phase 2 control path:

1. define canonical selectors, service advertisements, registration IDs, and a bounded `/p2x/registry/1` protocol;
2. consume the authenticated `AuthPrincipal`, session, role, scopes, authorization revision, and quota profile produced by Plan 03;
3. enable Circuit Relay v2 in product mode only behind pre-allocation authorization gates for server reservations and client circuit sources;
4. implement an in-memory, tenant-scoped registry with atomic full-set replacement, exact selector ownership, finite leases, idempotent retries, deterministic conflict behavior, and no public enumeration surface;
5. implement the product server reservation and registration supervisors on the existing single-swarm-owner event loop;
6. make server readiness require current auth, a confirmed relay reservation/address, and a current registration lease;
7. remove registrations and relay authority on lease expiry, reservation loss, final exchange disconnect, credential revocation, session expiry, or drain;
8. prove same-process server recovery after exchange restart and prove relay reachability through the authenticated product surface.

This plan does **not** implement:

- client resolve-and-authorize, ticket issuance from registry state, or a resolution cache;
- ticket replay consumption or server-side ticket validation;
- selected-connection proxy substreams, upstream dialing, byte copying, or ingress adapters;
- DCUtR path selection in product mode; Phase 0 lab behavior remains the accepted evidence until the Phase 3 connection manager consumes it;
- dynamic application/service reload, registry persistence, multiple exchanges, replicas, load balancing, wildcard selectors, or public registry listing;
- the final HTTP health endpoint, metrics backend, dashboards, or load tuning assigned to Phase 6. This phase supplies truthful internal readiness state and structured lifecycle evidence for those later surfaces.

## 2. Current State and Confirmed Constraints

### 2.1 Accepted baseline

- The workspace produces exactly `p2x-exchange`, `p2x-client`, and `p2x-server` plus the shared `p2x-protocol`, `p2x-config`, and `p2x-net` crates.
- `libp2p = 0.56.0` is pinned and resolves `libp2p-relay = 0.21.1`.
- Product peers persist Ed25519 identities, pin the exchange identity before reading credentials, authenticate through `/p2x/auth/1`, and receive a bounded session containing tenant, role, scopes, quota profile, authorization revision, and expiry.
- `p2x-exchange` owns `FixedTokenProvider`, `AuthSessionLedger`, and authoritative connection/request admission. Revocation already produces peer-close handoff actions.
- `p2x-protocol` already owns stable public auth/protocol errors and the context-complete ticket type that later phases bind to `selector_fingerprint` and `registration_revision`.
- `p2x-net::reservation::ReservationContext` contains the Phase 0 reservation-generation, acceptance/address ordering, renewal, loss, and retry foundation.
- The accepted exact-connection behavior, connection book, path selector, bounded workers, and C01–C14 lab must remain unchanged unless a proportional ADR 0001 rerun accepts the change.

At planning time, `cargo test --workspace --all-targets --all-features` passes in an environment permitted to bind the required loopback TCP/UDP listeners.

### 2.2 Relevant code seams

| Area | Current repository state | Required Plan 04 change |
| --- | --- | --- |
| Product relay | `builder.rs` toggles exchange relay and peer relay client off in product mode | Enable them only with authenticated relay admission installed; keep the spike protocol lab-only |
| Auth lifetime | client/server owners authenticate and Ping once; `AuthState` does not retain the returned session expiry | Add proactive session renewal and a current-session accessor without flapping availability while the prior session is still valid |
| Session expiry | `AuthSessionLedger::sweep` drops expired entries silently | Return explicit expiry/revoke/close handoffs and consume them in relay and registry owners |
| Server reservation | reservation state exists, but `p2x-server` drives it only in connectivity-lab mode | Extract a product reservation supervisor that starts only after server auth and `reserve_relay` authorization |
| Registry model/protocol | absent | Add canonical service types, codec, exchange state, handlers, and server registration supervisor |
| Server config | product auth/networking is CLI-driven; no service advertisement file exists | Add one strict bounded service file and validate the complete projection before networking starts |
| Readiness | `AuthReadiness` means only Auth+Ping | Add component readiness whose server predicate includes auth + reservation + registration lease |
| Revocation handoff | close actions exist, but no Phase 2 consumer exists | Revoke relay access and remove the server registration before closing its exchange connections |

### 2.3 Relay admission extension is available without a fork

The resolved `libp2p-relay 0.21.1` `Config` accepts custom reservation and circuit-source `RateLimiter` implementations. Both hooks receive the authenticated transport `PeerId` and execute before the relay behavior inserts reservation/circuit state. Plan 04 must use this public extension point:

- a reservation gate allows only a current server principal with `reserve_relay`;
- a circuit-source gate allows only a current client principal with `open_proxy_stream`;
- a missing, expired, revoked, role-incompatible, scope-incompatible, poisoned, or draining admission snapshot returns `false` and allocates no relay state;
- fixed libp2p rate and resource limiters remain in the chain after the authorization gate.

Do not accept a reservation first and close it afterward. Do not fork or vendor `libp2p-relay` for this phase.

The pinned relay implementation compares per-peer reservation/circuit counts with `>` while global counts use `>=`. Hide that version-specific behavior inside one `RelayLimits::to_libp2p_config` adapter that translates a logical positive per-peer limit `N` to the pinned raw value `N - 1`. Live boundary tests must prove exactly `N` requests are accepted and `N + 1` is rejected. A libp2p upgrade may remove that translation only together with those tests and the ADR-required relay/connectivity rerun.

### 2.4 Inherited invariants

1. Tenant, role, scopes, quota profile, peer identity, and authorization revision come from the active auth session, never the registry request.
2. A client/server request never supplies a private upstream address to exchange.
3. One live `(tenant, protocol, complete metadata map)` has one owning server in v1.
4. A full service-set replacement is all-or-nothing; a conflict or malformed member leaves the previous set and index unchanged.
5. A registry entry is eligible only while its server has current auth, a live relay reservation, and an unexpired lease.
6. The exchange registry stays in memory in v1. Exchange restart empties it; servers repopulate it automatically.
7. Registry/control handlers execute short, synchronous state transitions on the swarm owner. They perform no socket/file I/O and await nothing while registry state is borrowed.
8. Protocol frames, selectors, service sets, in-flight requests, idempotency entries, leases, retries, relay resources, and diagnostic queues are bounded before allocation or admission.
9. Raw selectors are not normal log fields. Telemetry uses a selector fingerprint; private connect targets remain server-local and absent from all exchange artifacts.

## 3. Required Design

### 3.1 Repository boundaries and files

Add or extend these files:

```text
crates/p2x-protocol/
  src/ids.rs                 # UpstreamId, InstanceId, RegistrationRevision
  src/selector.rs            # ProtocolClass, metadata validation, scoped fingerprint
  src/registry.rs            # validated registry request/response domain values
  src/error.rs               # stable registry/relay/limit errors
  src/frame.rs               # protocol-specific frame bounds, not auth-only helpers
  testdata/selector-v1.json  # committed canonical selector/fingerprint vector

crates/p2x-net/
  src/registry_codec.rs      # /p2x/registry/1 binary codec
  src/relay_admission.rs     # shared bounded auth snapshot + RateLimiter adapters
  src/auth_state.rs          # session expiry/renewal-aware peer auth state
  src/reservation.rs         # product-safe reservation events/actions
  src/builder.rs             # role/mode-specific product protocol composition

apps/p2x-exchange/
  src/registry.rs            # atomic leased registry and exact index
  src/registry_handler.rs    # auth/session/scope checks and response mapping
  src/relay_owner.rs         # auth handoff, relay events, drain, registry removal
  src/main.rs                # one swarm owner; dispatch only

apps/p2x-server/
  src/lib.rs
  src/config.rs              # strict service advertisement file
  src/availability.rs        # pure auth/reservation/registration state machine
  src/main.rs                # execute actions against the single swarm

docs/protocol/registry-v1.md
docs/operations/server-availability.md
tests/registry/README.md
tests/registry/local.sh
```

Do not create a generic control-plane framework or a new shared “core” crate. Selector and wire types are shared protocol concerns; registry ownership remains exchange-specific; server availability ownership remains server-specific.

### 3.2 Canonical selector and service domain

Add validated, private-field domain types:

```text
ProtocolClass = Http | TlsPassthrough | Tcp

UnscopedSelector {
  protocol: ProtocolClass,
  metadata: BTreeMap<MetadataKey, MetadataValue>,
}

ScopedSelector {
  tenant: Tenant,
  selector: UnscopedSelector,
}

ServiceAdvertisementV1 {
  upstream_id: UpstreamId,
  selector: UnscopedSelector,
  health: Ready | Unavailable,
}
```

Validation and canonicalization are normative:

- `upstream_id` is 1–64 ASCII characters matching the existing bounded identifier alphabet;
- metadata contains 1–32 entries;
- keys match `^[a-z][a-z0-9_.-]{0,63}$` and reserved `p2x.` keys are rejected;
- values are valid UTF-8, 1–256 bytes, and are trimmed once by the constructor; an all-whitespace value is invalid;
- keys are unique after validation and retained in `BTreeMap` byte order;
- the canonical selector encoding is at most 4 KiB;
- two selectors are equal only when protocol and the complete canonical metadata map are equal; there is no subset, wildcard, or case-insensitive matching;
- a service set contains 1–128 services with unique `upstream_id` values and unique selectors;
- `Unavailable` keeps ownership of its selector but exact lookup returns an offline result. It does not allow another server to take the selector before withdrawal/expiry.

Compute the selector fingerprint as SHA-256 over:

```text
"p2x-selector-v1\0" |
tenant_len_u16_be | tenant |
protocol_u8 |
metadata_count_u8 |
repeated(key_len_u16_be | key | value_len_u16_be | value)
```

The tenant is included only after exchange auth scopes the selector. The committed vector must contain the complete canonical input and expected lowercase fingerprint. Ticket construction in Phase 3 must consume this function rather than recomputing bytes.

### 3.3 Server service configuration

Add required `--services-file <path>` in product server mode. Load it through `p2x_config::yaml::load`, use `deny_unknown_fields`, and validate the entire file before building/listening/dialing:

```yaml
schema_version: 1
registration:
  requested_lease_seconds: 30
  refresh_seconds: 10
services:
  - upstream_id: orders-production
    selector:
      protocol: http
      metadata:
        service: orders
        environment: production
        region: eu-west
    enabled: true
```

- Accept only `schema_version: 1` and 1–128 entries.
- `requested_lease_seconds` defaults to 30 when omitted, is 10–60, and is further capped by the credential quota policy.
- `refresh_seconds` defaults to 10, is at least 1, and must not exceed half the requested lease.
- Duplicate IDs/selectors, invalid metadata, an empty enabled set, non-strict booleans, aliases/tags, and unknown fields are fatal before networking.
- `enabled: true` projects to `health = Ready`; disabled entries are validated but omitted. In this phase `Ready` means “configured and accepted for registration,” not “an upstream probe succeeded.” Phase 4 must extend the same server-local entry with connect policy and replace this provisional health source with actual upstream availability before proxy readiness.
- The server sends only `upstream_id`, selector, protocol class, and health. The local file must gain no exchange-facing `connect`, host, port, URL, TLS secret, or credential field in this phase.
- Normal configuration diagnostics include only counts, durations, and a hash of the canonical public advertisement set. They do not print raw metadata.

Retain the current identity/trust/credential CLI while it is the established product boundary. A unified application YAML migration is not required for this phase.

### 3.4 Bounded `/p2x/registry/1` protocol

Add one protocol ID:

```text
/p2x/registry/1
```

The product exchange supports it inbound; the product server supports it outbound; the product client and every connectivity-lab peer have it disabled. Use libp2p request-response with a five-second request timeout and one request per substream.

Version 1 domain messages are:

```text
RegistryRequestV1::Register {
  request_id: [u8; 16],
  session_id: [u8; 16],
  instance_id: [u8; 16],
  requested_lease_seconds: u16,
  capabilities: u32,
  services: Vec<ServiceAdvertisementV1>,
}

RegistryRequestV1::Refresh {
  request_id,
  session_id,
  instance_id,
  expected_registration_revision: NonZeroU64,
  requested_lease_seconds: u16,
}

RegistryRequestV1::Withdraw {
  request_id,
  session_id,
  instance_id,
  expected_registration_revision: NonZeroU64,
}

RegistryResponseV1::Registered {
  request_id,
  instance_id,
  registration_revision,
  service_set_hash: [u8; 32],
  expires_at: i64,
  effective_lease_seconds: u16,
}

RegistryResponseV1::Refreshed { request_id, instance_id, registration_revision, expires_at }
RegistryResponseV1::Withdrawn { request_id, instance_id, registration_revision }
RegistryResponseV1::Rejected { request_id?, error: PublicError }
```

Do not put `server_peer_id`, tenant, role, authorization revision, quota profile, or relay address in a request. The transport event and active session are authoritative. The exchange derives all advertised relay addresses from its validated public advertise addresses:

```text
<exchange-direct-address>/p2p/<exchange>/p2p-circuit/p2p/<server>
```

Capabilities v1 use a closed `u32` bit set: `RELAY_V2`, `DIRECT_TCP`, `DIRECT_QUIC`, and `DCUTR`. A Phase 2 server requires `RELAY_V2` and at least one direct transport bit. Unknown bits return `protocol.capability_mismatch`. Product DCUtR remains disabled until Phase 3; advertising `DCUTR` is therefore also disabled in Phase 2.

Encoding rules:

- frame is `u32` big-endian length plus exactly one binary message;
- `MAX_REGISTRY_FRAME = 262_144` bytes and zero-length frames are invalid;
- integers are fixed-width big-endian, strings use `u16` byte lengths, counts use the declared fixed width, and enum discriminants are closed;
- requests encode services in increasing `upstream_id` order and metadata in increasing key order; the decoder rejects non-canonical order, duplicates, unknown required fields/bits, unsupported versions, truncation, and trailing bytes;
- private codec wire structs convert explicitly into validated public domain values; do not expose serde-derived network messages;
- encoding is bounded in a temporary buffer, size-checked, flushed, and write-half closed exactly like the auth codec;
- add `registry_frame_decode` fuzz coverage with valid Register, Refresh, Withdraw, response, oversized-length, truncation, duplicate, and non-canonical seeds.

The app owner enforces 128 global in-flight registry requests, one per peer, 30 accepted operations per server per minute, and at most 256 tracked server rate buckets. Admission rejection sends exactly one correlated stable response and releases the permit on `ResponseSent`, inbound failure, connection close, or shutdown.

### 3.5 Stable errors

Extend `PublicErrorCode` without renaming existing strings:

| Code | Meaning | Retryable |
| --- | --- | --- |
| `registry.invalid_advertisement` | invalid service set, lease, instance, or canonical domain value | no |
| `registry.conflict` | another current server owns at least one selector | no blind retry |
| `registry.reservation_required` | server has no current accepted relay reservation | yes after reservation recovery |
| `registry.stale_revision` | refresh/withdraw does not match the current instance and revision | yes by sending a full Register |
| `registry.not_found` | no current record; reserved now for Phase 3 exact lookup | bounded retry only |
| `registry.offline` | selector owner exists but is not currently eligible | bounded retry only |
| `relay.unauthorized` | local/audit classification for role/scope/session denial | no until authentication changes |
| `relay.quota` | local/audit classification for relay resource/rate denial | yes with backoff |
| `limit.services` | server or quota-profile service count exceeded | no until config/quota changes |
| `limit.registry_requests` | registry in-flight/rate admission rejected | yes with backoff |
| `exchange.draining` | new availability work is disabled during shutdown | yes against a healthy restarted exchange |

Circuit Relay v2 itself returns its standard protocol status; it cannot carry a P2X `PublicError`. Stable P2X relay codes are local structured classifications and test assertions, not a replacement wire protocol.

### 3.6 Registry ownership and transactions

`apps/p2x-exchange/src/registry.rs` owns:

```text
Registry {
  registrations: HashMap<PeerId, RegistrationRecord>,
  selector_owners: HashMap<ScopedSelector, OwnerRef>,
  idempotency: BoundedIdempotencyCache,
  revision_allocator: RegistrationRevisionAllocator,
}

RegistrationRecord {
  peer_id,
  instance_id,
  tenant,
  authorization_revision,
  quota_profile,
  registration_revision,
  capabilities,
  service_set_hash,
  relay_addresses,
  services,
  expires_at,
}
```

The initial configurable limits are:

| Limit | Default | Hard maximum |
| --- | ---: | ---: |
| Live registered servers | 64 | 256 |
| Services per server | 32 | 128 |
| Live selector owners | 4,096 | 32,768 |
| Requested/effective lease | 30 s | 60 s |
| Idempotency entries per peer | 8 | 16 |
| Idempotency entries global | 2,048 | 4,096 |
| Registry frame | 256 KiB | fixed for protocol v1 |
| Lease/idempotency sweep interval | 1 s | 1 s |

The v1 quota catalog recognizes the existing `standard` profile. For a server principal it permits at most 32 services, a 60-second lease, and one relay reservation; for a client principal it permits circuit source use but no registration. Authentication may still produce another syntactically valid profile, but registry/relay authorization fails closed with a local unsupported-profile audit classification. A configurable multi-profile catalog is deferred until an operator requirement justifies it.

`Register` handling is one prepare/commit transaction:

1. check the idempotency cache by `(peer_id, request_id)`; identical canonical request bytes return the stored response, while the same live key with different bytes is `protocol.malformed`;
2. authorize the session against authoritative peer, server role, `register_services`, current provider revision, and supported quota profile;
3. require an active accepted relay reservation for the same peer;
4. canonicalize the tenant-scoped selectors, derive fingerprints and exchange-owned relay addresses, and validate all count/byte/lease/capability limits;
5. reject duplicates and any selector owned by another current server; the current server may replace its own selectors;
6. prepare the complete new record/index entries and a nonzero registration revision before mutating either map;
7. remove the old record's index entries, insert the complete new index, and replace the record without an await or fallible step in between;
8. cache and return the response.

Generate each registration revision from an injected CSPRNG allocator, reject zero, and retry only against currently retained revisions. A random 64-bit equality token avoids reusing a monotonic counter after an in-memory exchange restart; collision failure returns `exchange.overloaded` before mutation. It is an opaque equality value, not an ordering claim.

`Refresh` extends only an exactly matching peer/instance/revision record after repeating current auth, quota, and reservation checks. It does not change the service set or revision. `Withdraw` removes only an exactly matching instance/revision, preventing a delayed shutdown request from an older process instance from withdrawing a newer registration.

The one-second sweep removes expired records and idempotency entries. `remove_peer(peer, reason)` is the single idempotent path used by reservation loss, final session loss, revocation, and shutdown; it removes the record and every owned selector exactly once.

Expose an exchange-internal `resolve_exact(&ScopedSelector, now)` that returns the current owner/service/revision/relay addresses or a typed not-found/offline outcome. Do not expose it as a network protocol in this phase. Phase 3 must perform lookup and ticket construction in one event-loop transition so ownership cannot change between them.

### 3.7 Authenticated relay admission and relay limits

Add a bounded `RelayAdmissionHandle` backed by a short-held `Arc<RwLock<RelayAdmissionSnapshot>>`. The snapshot stores at most 256 entries keyed by `PeerId`; each entry contains only role, scopes, quota profile, authorization revision, and a monotonic expiry deadline. It contains no token, digest, credential ID, selector, service, or ticket.

Owner operations are:

```text
install(AuthSession)
remove(peer_id, reason)
set_draining(bool)
sweep(now)
is_reservation_authorized(peer_id, now)
is_circuit_source_authorized(peer_id, now)
```

- Install/update the entry before sending `Authenticated` so the peer cannot receive success while relay authorization is absent.
- Remove the entry before executing session revocation/expiry/final-close connection actions.
- Lock contention or poisoning fails closed. Maintenance treats a poisoned snapshot as exchange-not-ready and begins bounded shutdown; no relay request is allowed through.
- Put the authorization limiter first so unauthenticated attempts do not consume legitimate peer/IP rate tokens.

Logical product relay defaults are:

| Limit | Default | Hard maximum |
| --- | ---: | ---: |
| Reservations global | 64 | 256 |
| Reservations per server peer | 1 | 1 |
| Reservation duration | 60 s | 300 s |
| Reservation attempts per peer/IP | 8 / 32 per min | 60 / 240 per min |
| Circuits global | 128 | 512 |
| Circuits per client peer | 32 | 128 |
| Circuit starts per peer/IP | 64 / 256 per min | 512 / 2,048 per min |
| Circuit duration | 3,600 s | 86,400 s |
| Circuit bytes | 1 GiB | 16 GiB |

Keep all values configurable through validated exchange CLI fields already grouped by `RelayProfile`; rename the product default away from `DefaultLab`. The `LimitTest` profile stays test-only. Do not claim bandwidth shaping: libp2p v0.56 supplies byte/duration/count/rate bounds, not a throughput governor.

Relay event handling maintains a peer-level reservation ledger:

- `ReservationReqAccepted` marks the authenticated server reserved; only then may registration succeed;
- renewal keeps readiness and the registry lease intact and increments a bounded counter;
- denied/failed requests never mark reserved;
- `ReservationClosed` or `ReservationTimedOut` clears reservation authority and immediately removes that peer's registration;
- circuit accepted/denied/closed events update bounded counts and lifecycle records without touching registry locks;
- revocation/session expiry removes relay admission and registry state first, then closes every exchange connection for that peer so built-in relay state/circuits are released.

### 3.8 Exchange public advertise addresses

Add repeatable required `--advertise <multiaddr>` for product exchange mode, at most four values. Validate before starting the swarm:

- each address is a non-circuit TCP or QUIC address suitable for peers, contains exactly one terminal `/p2p/<exchange-peer-id>`, and matches the loaded exchange identity;
- unspecified listen IPs are allowed for binding but are never synthesized into advertise addresses;
- product relay startup is not ready with an empty or invalid advertise set;
- add the validated direct addresses to the swarm external-address set before any reservation can be accepted;
- connectivity-lab mode retains its current listener-derived addresses and does not consume product registry or admission state.

Registration stores the derived circuit form of every configured advertise address. A server-supplied address cannot redirect resolution to another relay or peer.

### 3.9 Session renewal and Phase 2 handoffs

Extend peer auth ownership so `Authenticated.expires_at` is retained and reauthentication starts 60 seconds before expiry, or at half the remaining lifetime when the session has less than 120 seconds remaining.

Add an explicit `Reauthenticating` phase that retains the prior current session until one of these occurs:

- a correlated new `Authenticated` response replaces it atomically and a correlated Ping confirms continued readiness;
- the old session expires, the final exchange connection closes, or a terminal auth error clears it;
- a retryable timeout/overload backs off without discarding a still-valid prior session.

Expose `current_session(now) -> Option<SessionLease>` for reservation/registration actions. If exchange replaces the old session while a registry request using it races, `auth.session_required` causes the server to retry once with the new current session and a fresh request ID; changing the session while reusing the old idempotency key is forbidden. The rejected attempt does not mutate registration state.

Change exchange session maintenance to return explicit actions for expiry as it already does for revocation. The exchange owner consumes each transition in this order:

1. remove relay admission;
2. remove registration/index state;
3. emit one non-secret reason-classified lifecycle event;
4. close the peer's admitted exchange connection IDs;
5. release auth/registry admission permits exactly once.

Successful reauthentication updates relay admission in place and does not flap an active reservation or registration.

### 3.10 Server availability state machine

Move product availability logic into a pure state machine. One `p2x-server` task continues to own `Swarm`; the state machine returns actions and never performs I/O.

```text
Starting
  -> Authenticating
  -> AuthReady
  -> Reserving
  -> RelayReady
  -> Registering
  -> Ready

Auth/session/connection loss -> Degraded -> reauthenticate
Reservation loss             -> Degraded -> reacquire -> full Register
Registration rejection/loss  -> Degraded -> retry/full Register as classified
Shutdown                     -> Draining -> Withdrawn -> Stopped
```

Required ordering and state:

- generate one CSPRNG `instance_id` per process start; failure is fatal before networking;
- begin the circuit listener only after Auth+Ping proves a server session with `reserve_relay` and `register_services` scopes;
- bind reservation events to a monotonically increasing local generation so stale acceptance/listener/retry events cannot restore readiness;
- treat reservation acceptance and the canonical `NewListenAddr`/external-address confirmation as order-independent; both are required for `RelayReady`;
- send full Register only after `RelayReady`; keep at most one registry request in flight;
- retain the exact canonical request and request ID across a transport timeout retry so exchange idempotency can return the prior result;
- accept `Registered` only when libp2p outbound request ID, wire request ID, instance ID, service-set hash, and current generation all match;
- schedule Refresh at `refresh_seconds` with full-range ±10% jitter, but never later than five seconds before absolute lease expiry;
- Refresh reuses the current instance/revision and a fresh request ID. `registry.stale_revision` or `registry.not_found` triggers a full Register; conflict/invalid config is terminal until configuration changes; reservation-required waits for relay recovery; timeout/overload/limits retry with capped backoff;
- when the local lease deadline passes without a matching refresh response, publish readiness false immediately even if exchange has not yet swept the record;
- after exchange restart, retain the same process PID and PeerId, reauthenticate, create a new reservation generation, and perform full Register. Target restored readiness is within 60 seconds;
- a healthy future direct peer connection is not closed merely because exchange control is reconnecting. Close only connection IDs known to belong to the exchange/reservation generation.

Use jittered exponential retry starting at 250 ms and capped at 10 seconds for reservation/registration. One timer per supervisor is enough; duplicate loss events cannot schedule duplicate retries.

Server readiness is exactly:

```text
auth.current(now)
&& reservation.ready(current_generation)
&& registration.peer_and_instance_match
&& registration.expires_at > now
&& !draining
```

Emit separate subsystem transitions plus one `ServerReadiness { ready, generation, auth, reservation, registration }`. Readiness generation increments only on false-to-true transitions. The old `AuthReadiness` record remains an auth-subsystem signal and must not be treated as component readiness.

### 3.11 Shutdown and privacy-safe evidence

On server shutdown:

1. publish server readiness false and stop retry timers;
2. if auth and registration are current, send one Withdraw and wait at most five seconds for its correlated response;
3. close the circuit listener and exchange connections;
4. drain registry/auth pending ownership and emit one terminal result with zero logical resources.

On exchange shutdown:

1. publish exchange readiness false and set relay admission to draining;
2. reject new Register/Refresh and new reservations/circuit sources with stable local classifications;
3. continue polling existing work for a configurable five-second drain interval;
4. clear registry, admission snapshots, sessions, pending request permits, and then close the swarm.

Add lifecycle records for registry mutation/removal reason, relay admission outcome, reservation state, registration state, and component readiness. Records may contain peer ID according to the existing policy, opaque revision, counts, duration, stable code, and selector fingerprint. They must not contain credentials, session IDs, raw selectors, service metadata values, private connect targets, or full relay payload details.

## 4. Implementation Plan

### 4.1 Add failing domain and relay-boundary tests first

- Commit selector canonicalization/fingerprint vector tests, service-set validation tests, atomic registry transaction tests, relay gate scope/expiry tests, and a live logical-limit `N`/`N+1` relay test before enabling product relay.
- Confirm the custom `RateLimiter` is invoked before reservation/circuit state insertion with the pinned dependency. If the public hook does not behave as the inspected 0.21.1 source and live test specify, stop this phase and revise the design; do not fall back to accept-then-close.

### 4.2 Implement shared selector and registry domain values

- Add private-field constructors, canonical encoders, hashes, IDs, capability flags, service-set ordering, and new stable errors in `p2x-protocol`.
- Commit `selector-v1.json` and mutation tests before the network codec uses the types.

### 4.3 Implement and fuzz `/p2x/registry/1`

- Add `RegistryCodec`, typed decode errors, protocol-to-public-code mapping, strict frame/body bounds, role-specific protocol support, and request-response timeout.
- Add TCP and QUIC same-process round trips, inbound-negotiation rejection by client/lab peers, request ownership/release tests, and `registry_frame_decode` fuzz target/corpus.

### 4.4 Implement auth-to-relay admission

- Add `RelayAdmissionHandle`, monotonic session deadlines, fail-closed lock behavior, drain, and scope/role/profile checks.
- Wire successful auth, proactive reauth, session expiry, revocation, final close, and shutdown into install/remove operations.
- Replace raw relay config construction with logical `RelayLimits`, authorization limiters, version-specific per-peer translation, and exact live limit tests.

### 4.5 Implement the exchange registry transaction owner

- Add prepared full replacement, exact selector index, CSPRNG revisions, idempotency cache, refresh, guarded withdraw, lookup, sweep, and idempotent peer removal.
- Add property/state-sequence tests that continuously compare the selector index against records after replacements, conflicts, expiry, retry, and removal.

### 4.6 Integrate exchange registry, relay events, and drain

- Add validated public advertise addresses before relay startup.
- On registry requests, perform registry admission, session/scope/profile authorization, reservation check, state transition, one response, and exactly-once permit release.
- Consume relay loss and auth handoff events in the required removal order. Keep all operations on the single swarm owner.

### 4.7 Add server configuration and availability supervisor

- Parse/validate the service file before networking and project it to canonical advertisements.
- Promote `ReservationContext` into the product server path and add registration state/actions, request correlation, timers, retry classification, component readiness, and graceful withdraw.
- Keep lab probe workers and product registry/reservation owners structurally separate by `RuntimeMode` and peer role.

### 4.8 Complete executable verification and documentation

- Add the canonical live registry harness and machine-validated summaries.
- Run the required auth regression and complete connectivity regression caused by changing relay behavior composition.
- Finish protocol, operator, privacy, limits, restart, and test runbooks before marking the phase complete.

## 5. Verification

### 5.1 Local static and automated checks

Run from the repository root:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
cargo tree -e features
```

Run every fuzz target for the repository's bounded CI duration, including the new `registry_frame_decode`. A panic, unbounded allocation, non-canonical acceptance, leaked private value, or unstable error mapping fails the phase.

### 5.2 Required unit and state-machine coverage

Tests must cover at least:

- selector trim/order/equality, every key/value/count/size boundary, reserved keys, duplicate selectors/IDs, and the committed fingerprint vector;
- every registry request/response round trip plus unknown version/bit/discriminant, non-canonical ordering, duplicate, zero/oversized/truncated/trailing frame, and exact maximum frame;
- full replacement add/remove/change, self-replacement, cross-peer conflict, unavailable ownership, no-partial-mutation failure, random revision collision, and index consistency;
- identical idempotent retry, request-ID/body mismatch, cache bound/expiry, response replay after a lost response, and exactly-once mutation;
- refresh/withdraw with wrong peer, instance, revision, session, role, scope, auth revision, quota profile, reservation, and lease boundaries;
- lease expiry, reservation loss, final/non-final connection close, revocation, session expiry, duplicate removal, drain, and exchange shutdown;
- relay authorization before allocation, unauthorized attempts not consuming rate tokens/state, logical per-peer/global `N` and `N+1`, renewal at the one-reservation limit, and circuit close cleanup;
- reauth before expiry, stale auth/registry responses, old-session race, refresh timeout versus response, duplicate loss timers, jitter/cap boundaries, exchange restart generations, and readiness truth table;
- all configuration failures occur before listen/dial/credential transmission and diagnostics contain no raw metadata or secret material.

### 5.3 Same-process network integration

Add TCP and QUIC integration tests that build the real product behaviors and prove:

1. exchange advertises inbound auth/registry/relay while server advertises outbound auth/registry plus relay client; client has no registry protocol; lab mode retains its accepted probe/relay/DCUtR behavior and instantiates neither registry nor product availability owners;
2. an unauthenticated peer and an authenticated wrong-role/wrong-scope peer cannot acquire a reservation or source a circuit, and exchange relay state remains zero;
3. an authenticated server reserves, confirms its circuit address, registers multiple services atomically, refreshes the same revision, and withdraws;
4. an authenticated client sources a relay circuit to the registered server and completes libp2p Ping over that relayed connection without the spike protocol;
5. two servers in one tenant claiming the same selector produce one stable owner and one complete rejection; different tenants may use identical unscoped selectors;
6. reservation close, session expiry, revocation, and server connection loss remove the registration and index;
7. response loss followed by an identical retry returns the same revision without a second registry mutation.

### 5.4 Canonical live process cases

Create `tests/registry/local.sh --case <name>` with at least:

```text
valid-tcp
valid-quic
multi-service
selector-conflict
cross-tenant
register-without-reservation
unauthorized-reservation
lease-expiry
graceful-withdraw
reservation-renewal
revocation-restart
exchange-restart
registry-limit
service-limit
```

Each case uses run-scoped identities/config/ports/process groups, validates NDJSON schemas, scans artifacts for secrets/raw selectors/private targets, and proves final logical resource counts are zero. It must derive pass/fail from observed events rather than expected labels.

The exchange-restart case passes only when the original server PID and PeerId:

- emit component readiness true at generation 1;
- emit readiness false after exchange/reservation loss;
- authenticate to the restarted exchange, acquire a new reservation, full-register the same service-set hash with a new opaque revision, and emit readiness true at generation 2 within 60 seconds.

### 5.5 Scale and churn checks

- Run at least 10,000 pure registry replace/refresh/expire/withdraw operations with invariant checking and no stale selector owner.
- Exercise the initial 16-server × 16-service workload and the 32-server × 32-service headroom in-process; the latter is a validation target, not a configured production cap.
- Run a multi-hour or CI-bounded accelerated lease/renewal/restart soak and prove registrations, idempotency entries, sessions, relay admission entries, connections, listeners, requests, timers, and tasks return to baseline.
- Saturate relay reservation/circuit limits while registry refresh and auth Ping continue without starvation.

### 5.6 Required regression and owner-executed checks

Rerun every Plan 03 live auth case affected by session renewal and exchange event dispatch, especially valid client/server, revoked, expired, rotation-revoke-old, connection/request/session limits, and exchange restart.

Because this phase changes relay behavior composition and relay limits, rerun the complete accepted C01–C14 connectivity matrix rather than a subset:

- native local C01 and C05–C13;
- canonical Linux namespace C02–C13;
- two-host C14 across separate networks;
- TCP and QUIC variants where the existing runbooks require them.

Native Linux and macOS must both pass product auth → reservation → registration → relay-Ping → restart recovery. For macOS VM-backed containers, relay/registration are required while direct connectivity remains measured best effort. Environment-dependent two-host, container/firewall, packet inspection, and multi-hour soak results are owner-executed final-phase checks and may not be claimed by unit tests.

## 6. Documentation Updates

Add [`docs/protocol/registry-v1.md`](../docs/protocol/registry-v1.md) with:

- byte-exact request/response layouts, discriminants, capabilities, limits, canonical ordering, and error mapping;
- authoritative versus omitted fields, selector fingerprint vector, service-set hash, revision semantics, idempotency, and compatibility rules;
- explicit statement that `/p2x/registry/1` is server-to-exchange only and is not a resolution/enumeration API.

Add [`docs/operations/server-availability.md`](../docs/operations/server-availability.md) with:

- service file schema and the Phase 2 meaning of service health;
- exchange public advertise/port/firewall requirements;
- auth renewal, reservation renewal, registration lease, readiness, retry, exchange restart, revocation, and graceful shutdown behavior;
- single-exchange/in-memory-registry boundary and the 60-second recovery target;
- relay limits, the absence of throughput shaping, Linux/macOS/container expectations, and privacy-safe diagnostics.

Update [`docs/protocol/auth-v1.md`](../docs/protocol/auth-v1.md), [`docs/security/identity-and-credentials.md`](../docs/security/identity-and-credentials.md), and [`tests/README.md`](../tests/README.md) for proactive session renewal, Phase 2 revocation handoffs, authenticated relay admission, registry test entry points, and required regressions.

## 7. Definition of Done

- `/p2x/registry/1` is canonical, versioned, bounded, fuzzed, and available only on the intended product exchange/server roles.
- Tenant-scoped selectors and fingerprints have one implementation and a committed vector; no raw selector or private target appears in normal exchange diagnostics.
- Registry full replacement is atomic, conflicts are deterministic, retries are idempotent, refresh/withdraw are instance-and-revision guarded, and all removal causes leave no stale index entry.
- Product relay requests are denied before relay state allocation unless the transport `PeerId` has a current compatible auth session/scope/profile; logical relay limits pass exact boundary tests.
- Credential revocation, auth/session expiry, final exchange loss, reservation loss, lease expiry, and drain remove relay admission and registry state in the declared order.
- The server authenticates, reserves, registers, refreshes, renews auth, and reports component readiness only while all three gates are current.
- The same server process and identity restore reservation, registration, and readiness within 60 seconds after a healthy exchange restart.
- An authenticated product client reaches the registered server through Circuit Relay v2 and Ping without using `/p2x/spike/1`; unauthorized peers cannot reserve or source circuits.
- Static checks, unit/integration tests, registry fuzzing, live cases, scale/churn checks, Plan 03 regressions, and the full ADR 0001 connectivity rerun pass with bounded cleanup and no secret/private-data leak.
- Protocol and operations documentation describe the implemented behavior and single-exchange boundary.
- Only after all criteria above pass may Phase 3 planning begin for atomic resolve-and-authorize, ticket issuance, client resolution/cache/singleflight, selected direct/relay connection management, and the first authorized empty proxy substream.
