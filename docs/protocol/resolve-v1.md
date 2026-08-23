# P2X resolve protocol v1

`/p2x/resolve/1` is an authenticated client-to-exchange request-response protocol. Product exchange enables it inbound and product clients enable it outbound. Servers and connectivity-lab peers do not enable it. Request-response timeout is five seconds.

## Framing

Each stream contains a four-byte big-endian `u32` payload length and exactly one canonical payload. Empty, oversized, truncated, trailing, unsupported-version, unknown-discriminant, unknown-capability, invalid PeerId, non-canonical selector, and invalid address inputs are rejected. `MAX_RESOLVE_FRAME` is 16,384 bytes. Strings use `u16` byte lengths; IDs are fixed-width 16-byte values; integers are big-endian. Writers flush and close the write half.

A request begins with version `1` and discriminant `0`, then request ID, session ID, an unscoped exact selector, and a closed capability mask. Tenant, role, scopes, quota, and transport PeerId are intentionally absent: the authenticated exchange session supplies them. Selector metadata is sorted and uses the canonical Plan 04 selector encoding.

A successful response begins with version `1` and discriminant `0`, then request ID, canonical server PeerId bytes, opaque `upstream_id`, selector fingerprint, nonzero registration revision, one to four relay circuit addresses, compatible capability bits, registration expiry, ticket expiry, and a bounded `RawTicket`. Address bytes are at most 512 bytes. A rejection uses discriminant `1`, an optional request ID, and one stable public error. No response contains raw tenant, selector metadata, credential, session ID, server authorization revision, or private upstream target.

Byte-exact non-production request/response and framed vectors are committed in [`crates/p2x-protocol/testdata/resolve-v1.json`](../../crates/p2x-protocol/testdata/resolve-v1.json). Protocol tests decode and re-encode every committed vector and reject trailing data and unknown discriminants.

## Resolution and tickets

The exchange scopes the unscoped selector with the authenticated client tenant and performs an exact fingerprint lookup followed by complete selector comparison. Expired records and unavailable services do not resolve. The owner server must still have a current matching server session and accepted relay reservation. Compatible capabilities are the closed intersection; Relay v2 is required. Direct/DCUtR absence selects relay rather than reporting a false direct failure.

The exchange issues a fresh CSPRNG ticket ID and signs claims bound to issuer exchange, client, server, tenant, upstream, selector fingerprint, registration revision, server authorization revision, time, `OPEN_PROXY_STREAM`, and `max_streams=1`. Default lifetime is 30 seconds, allowed range is 5–60 seconds, and expiry is clipped to registration expiry. Less than five seconds remaining returns retryable `registry.offline`.

Idempotency is keyed by authenticated client PeerId and request ID, with a SHA-256 digest of the complete canonical request body. Authorization happens before replay lookup. The same body returns byte-identical response and ticket without another issuance; a changed body returns `protocol.malformed`. Default resolve admission is 128 global, 16 per client, 120 accepted requests per minute, and 256 rate buckets. Configured values are bounded by hard maxima of 1,024, 128, 1,200, and 2,048. Idempotency entries retain through ticket expiry plus five seconds and live entries are never evicted to admit a caller. Raw ticket values and IDs are never normal diagnostics.

The exchange has guarded deterministic controls for dropping the first successful response after caching and holding a successful response. They require `P2X_ENABLE_TEST_HOOKS=1`; the drop control is exercised by the `idempotent-resolve` process case.

## Errors and compatibility

Stable errors include `registry.not_found`, `registry.offline`, `registry.stale_revision`, `limit.resolve_requests`, `exchange.overloaded`, `exchange.draining`, and protocol framing/capability errors. Malformed, unauthorized, and capability failures are not retried. A resolver may retransmit the exact request ID/body once within its one absolute setup deadline. Protocol vectors and the bounded framed fuzz target are covered by the workspace protocol tests and `fuzz/fuzz_targets/resolve_frame_decode.rs`.

The locally verified resolution cases are listed in [`tests/resolution/README.md`](../../tests/resolution/README.md). Registration replacement, low-limit saturation, restart recovery, graceful drain, and the complete binding matrix remain explicit Plan 05a blockers until their process orchestration and evidence are implemented.
