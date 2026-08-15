# P2X authentication protocol v1

## Boundary

The authenticated control protocol is `/p2x/auth/1`. The exchange supports inbound requests; clients and servers support outbound requests. Request-response streams have a five-second deadline.

Frames contain a four-byte big-endian payload length followed by exactly that many bytes. Empty frames and frames larger than 4096 bytes are rejected before payload allocation. Decode failures are local errors and attacker-controlled text is never returned.

Version 1 supports `Authenticate` and `Ping` requests, and `Authenticated`, `Pong`, and `Rejected` responses. The transport event's authenticated `PeerId` is authoritative; credentials are not allowed to carry a peer identity.

## Public errors

Stable codes are defined in `p2x_protocol::PublicErrorCode`, including `auth.invalid_credential`, `auth.exchange_identity_mismatch`, `auth.session_required`, `auth.session_expired`, `auth.role_forbidden`, `auth.ticket_invalid`, `auth.ticket_expired`, `exchange.overloaded`, `exchange.timeout`, the auth connection/request/session limits, and protocol framing/version errors.

Only the code and retryability cross the wire. Internal causes remain local diagnostics.

## Ticket boundary

Ticket claims and envelopes use canonical binary encoding and Ed25519 signatures. Claims are limited to 1024 bytes and envelopes to 2048 bytes. The signing context is `p2x-ticket-v1\0`; the committed test vector is `crates/p2x-protocol/testdata/ticket-v1.json`.
