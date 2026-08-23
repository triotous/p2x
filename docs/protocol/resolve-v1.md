# P2X resolve protocol v1

`/p2x/resolve/1` is an authenticated client-to-exchange request-response protocol. Product exchange enables it inbound and product clients enable it outbound. Servers and connectivity-lab peers do not enable it. Request-response timeout is five seconds.

## Framing

Each stream contains a four-byte big-endian `u32` payload length and exactly one canonical payload. Empty, oversized, truncated, trailing, unsupported-version, unknown-discriminant, unknown-capability, invalid PeerId, non-canonical selector, and invalid address inputs are rejected. `MAX_RESOLVE_FRAME` is 16,384 bytes. Strings use `u16` byte lengths; IDs are fixed-width 16-byte values; integers are big-endian. Writers flush and close the write half.

A request begins with version `1` and discriminant `0`, then request ID, session ID, an unscoped exact selector, and a closed capability mask. Tenant, role, scopes, quota, and transport PeerId are intentionally absent: the authenticated exchange session supplies them. Selector metadata is sorted and uses the canonical Plan 04 selector encoding.

A successful response begins with version `1` and discriminant `0`, then request ID, canonical server PeerId bytes, opaque `upstream_id`, selector fingerprint, nonzero registration revision, one to four relay circuit addresses, compatible capability bits, registration expiry, ticket expiry, and a bounded `RawTicket`. Address bytes are at most 512 bytes. A rejection uses discriminant `1`, an optional request ID, and one stable public error. No response contains raw tenant, selector metadata, credential, session ID, server authorization revision, or private upstream target.

## Resolution and tickets

The exchange scopes the unscoped selector with the authenticated client tenant and performs an exact fingerprint lookup followed by complete selector comparison. Expired records and unavailable services do not resolve. The owner server must still have a current matching server session and accepted relay reservation. Compatible capabilities are the closed intersection; Relay v2 is required. Direct/DCUtR absence selects relay rather than reporting a false direct failure.

The exchange issues a fresh CSPRNG ticket ID and signs claims bound to issuer exchange, client, server, tenant, upstream, selector fingerprint, registration revision, server authorization revision, time, `OPEN_PROXY_STREAM`, and `max_streams=1`. Default lifetime is 30 seconds, allowed range is 5–60 seconds, and expiry is clipped to registration expiry. Less than five seconds remaining returns retryable `registry.offline`.

Idempotency is keyed by authenticated client PeerId and request ID, with a digest of the complete request body. Authorization happens before replay lookup. The same body returns byte-identical response and ticket without another issuance; a changed body returns `protocol.malformed`. Entries are bounded to eight per client and 2,048 globally, and retain through expiry plus five seconds. Raw ticket values and IDs are never normal diagnostics.

## Errors and compatibility

Stable errors include `registry.not_found`, `registry.offline`, `registry.stale_revision`, `limit.resolve_requests`, `exchange.overloaded`, `exchange.draining`, and protocol framing/capability errors. Malformed, unauthorized, and capability failures are not retried. A resolver may retransmit the exact request ID/body once within its one absolute setup deadline.
