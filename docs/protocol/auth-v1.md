# P2X authentication protocol v1

## Boundary

The authenticated control protocol is `/p2x/auth/1`. The exchange supports inbound requests; clients and servers support outbound requests. Request-response streams have a five-second deadline.

Frames contain a four-byte big-endian payload length followed by exactly that many bytes. Empty frames and frames larger than 4096 bytes are rejected before payload allocation. Decode failures are local errors and attacker-controlled text is never returned.

Version 1 supports `Authenticate` and `Ping` requests, and `Authenticated`, `Pong`, and `Rejected` responses. The transport event's authenticated `PeerId` is authoritative; credentials are not allowed to carry a peer identity.

The exchange runtime accepts `--credential-file <path>` for a validated digest-only fixed-token snapshot. Clients and servers accept `--credential-env <NAME>`; the environment value is parsed as `p2x1.<credential-id>.<base64url-no-pad-32-byte-secret>`. With a credential configured, an established pinned exchange connection starts Authenticate, then sends one correlated Ping after Authenticated. Without these options, the existing explicit connectivity-lab probe flow remains available.

## Public errors

Stable codes are defined in `p2x_protocol::PublicErrorCode`, including `auth.invalid_credential`, `auth.exchange_identity_mismatch`, `auth.session_required`, `auth.session_expired`, `auth.role_forbidden`, `auth.ticket_invalid`, `auth.ticket_expired`, `exchange.overloaded`, `exchange.timeout`, the auth connection/request/session limits, and protocol framing/version errors.

Only the code and retryability cross the wire. Internal causes remain local diagnostics.

## Ticket boundary

Ticket claims and envelopes use canonical binary encoding and Ed25519 signatures. Claims are limited to 1024 bytes and envelopes to 2048 bytes. The signing context is `p2x-ticket-v1\0`; the committed test vector is `crates/p2x-protocol/testdata/ticket-v1.json`.

## Current phase boundary

Registry admission, atomic resolve-and-authorize ticket issuance, replay consumption, proxy streams, dynamic configuration reload, and production identity CLI onboarding remain later-phase work. The lab seed option is not a production identity loader.
