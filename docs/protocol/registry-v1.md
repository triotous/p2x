# P2X registry protocol v1

`/p2x/registry/1` is a bounded server-to-exchange control protocol. The exchange accepts inbound requests; a product server enables outbound support. Clients and connectivity-lab peers do not enable it. It is not a resolution or enumeration API.

## Frame and domain

A frame is a four-byte big-endian length followed by exactly one binary message. Empty, truncated, trailing, oversized (`262144` bytes), unknown-version, unknown-discriminant, non-canonical, duplicate, and unsupported-capability frames are rejected. Strings use `u16` byte lengths; integers use fixed-width big-endian encoding; service counts use `u16`. Each stream carries one request or response, is flushed, and has its write half closed. Request-response timeout is five seconds.

Version `1` request discriminants are `0 Register`, `1 Refresh`, and `2 Withdraw`. Register contains request ID, session ID, instance ID, lease seconds, closed capability bits (`RELAY_V2=1`, `DIRECT_TCP=2`, `DIRECT_QUIC=4`, `DCUTR=8`), and a service set. Refresh and Withdraw contain request/session/instance IDs and a nonzero registration revision; Refresh also contains a lease.

Response discriminants are `0 Registered`, `1 Refreshed`, `2 Withdrawn`, and `3 Rejected`. Registered returns request/instance IDs, opaque nonzero revision, service-set hash, expiry, and effective lease. Rejected returns an optional correlated request ID and a stable `PublicError` code/retryability. Tenant, role, scopes, quota profile, authorization revision, server PeerId, credential, and relay address are authoritative exchange state and never request fields.

## Canonical selectors

A selector is a protocol class (`http`, `tls_passthrough`, or `tcp`) and 1–32 metadata entries. Keys are lowercase bounded names and `p2x.` keys are reserved. Values are trimmed once, UTF-8, and 1–256 bytes. Metadata and service IDs are sorted in byte order. A service set has 1–128 unique IDs and selectors. `Unavailable` retains selector ownership but does not resolve as online.

The selector fingerprint is SHA-256 of `p2x-selector-v1\0`, tenant length/bytes, protocol byte, metadata count, and ordered key/value lengths/bytes. The committed vector is `crates/p2x-protocol/testdata/selector-v1.json`. Service-set hashes use the shared `p2x-service-set-v1\0` length-delimited encoding. Request replay digests use the shared `p2x-registry-request-v1\0` encoding and include the session ID for every operation.

## Admission and limits

The exchange scopes registry state to the authenticated transport peer and current session. A server must have role `Server`, `register_services`, the supported `standard` quota profile, current auth, and an accepted relay reservation. `RELAY_V2` plus at least one direct transport capability is required; `DCUTR` is rejected by the product registry path.

The default limits are 64 live servers, 32 services per server in the standard quota, 4096 selector owners, 30-second leases (10–60 seconds), eight idempotency entries per peer, 2048 global entries, 128 global in-flight requests, one registry request per peer, 30 accepted operations per peer per rolling minute, and 256 tracked rate buckets. Expired records are removed before Refresh/Withdraw decisions and cannot be resurrected. Identical request ID and canonical body replays the cached response; reusing the ID with different bytes is `protocol.malformed`. Product registry admission is enabled only for the product exchange/server surfaces; connectivity-lab and client surfaces leave it disabled.

Errors include `registry.invalid_advertisement`, `registry.conflict`, `registry.reservation_required`, `registry.stale_revision`, `registry.not_found`, `registry.offline`, `relay.unauthorized`, `relay.quota`, `limit.services`, `limit.registry_requests`, and `exchange.draining`. Raw selectors, metadata values, credentials, session IDs, private upstream targets, and relay payloads are not normal diagnostics.
