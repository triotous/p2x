# P2X authentication protocol v1

## Boundary

The authenticated control protocol is `/p2x/auth/1`. The exchange supports inbound requests; clients and servers support outbound requests. Request-response streams have a five-second deadline.

Frames contain a four-byte big-endian payload length followed by exactly that many bytes. Empty frames and frames larger than 4096 bytes are rejected before payload allocation. Version is one byte and is `1`; request kind follows it. Authenticate carries a 16-byte big-endian request ID, bounded credential ID, 32-byte token, one-byte role, and an eight-byte feature mask. Ping carries request ID, session ID, and nonce. Decode failures are local typed errors (`frame_too_large`, `malformed`, `unsupported_version`, or `capability_mismatch`) and attacker-controlled text is never returned.

Version 1 supports `Authenticate` and `Ping` requests, and `Authenticated`, `Pong`, and `Rejected` responses. The transport event's authenticated `PeerId` is authoritative; credentials are not allowed to carry a peer identity. One auth request is allowed per peer and 128 inbound requests are allowed globally; established connections, source-IP connections, sessions, and failure buckets are also bounded. Overload is rejected instead of queued.

The exchange runtime accepts `--credential-file <path>` for a validated digest-only fixed-token snapshot. Clients and servers accept `--credential-env <NAME>`; the environment value is parsed as `p2x1.<credential-id>.<base64url-no-pad-32-byte-secret>`. With a credential configured, an established pinned exchange connection starts Authenticate, then sends one correlated Ping after Authenticated. Request and response IDs are checked against the current state; stale responses are ignored. Transport timeout and disconnect paths use bounded exponential backoff, while invalid credentials and incompatible protocol capabilities are terminal. Readiness is emitted only after the matching Pong. The default product owner remains running after readiness; the explicit `--finite-auth-check` option is reserved for finite harness checks. Without these options, the existing explicit connectivity-lab probe flow remains available.

## Public errors

Stable codes are defined in `p2x_protocol::PublicErrorCode`, including `auth.invalid_credential`, `auth.exchange_identity_mismatch`, `auth.session_required`, `auth.session_expired`, `auth.role_forbidden`, `auth.ticket_invalid`, `auth.ticket_expired`, `exchange.overloaded`, `exchange.timeout`, the auth connection/request/session limits, and protocol framing/version errors.

Only the code and retryability cross the wire. Internal causes remain local diagnostics. Version 1 has no optional feature bits (`KNOWN_AUTH_FEATURES_V1 = 0`), so nonzero request or response feature masks are rejected as `protocol.capability_mismatch`. Correlation IDs are checked monotonic 128-bit big-endian values; session IDs remain CSPRNG-generated.

## Ticket boundary

Ticket claims and envelopes use canonical binary encoding and Ed25519 signatures. Claims are limited to 1024 bytes and envelopes to 2048 bytes. Tenant and upstream identifiers are bounded identifiers; v1 requires `OPEN_PROXY_STREAM` and `max_streams: 1`. The signing context is `p2x-ticket-v1\0`; the committed test vector is `crates/p2x-protocol/testdata/ticket-v1.json`. Verification rings accept only canonical lowercase key IDs whose public key hashes to that ID, and enforce activation/retirement windows.

## Current phase boundary

Registry admission, atomic resolve-and-authorize ticket issuance, replay consumption, proxy streams, dynamic configuration reload, and production identity CLI onboarding remain later-phase work. The lab seed option is not a production identity loader.
