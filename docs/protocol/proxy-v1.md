# P2X proxy-open protocol v1

`/p2x/proxy/1` is an exact-connection product substream protocol. Product clients expose outbound opening only; product servers expose inbound opening only. The probe protocol `/p2x/spike/1` is not part of this surface.

## Framing

The opened stream carries a four-byte big-endian `u32` frame length followed by exactly one canonical frame. `MAX_PROXY_HANDSHAKE_FRAME` is 4,096 bytes. Empty, oversized, truncated, trailing, unsupported-version, unknown ingress/mode/error, and malformed canonical IDs are rejected. Strings use `u16` byte lengths and fixed integers are big-endian. The client flushes and closes its write half after the Open frame; the server rejects early application bytes before authorization.

Open version 1/discriminant 0 contains a request ID, bounded `RawTicket`, opaque upstream ID, nonzero registration revision, and closed ingress kind (`FixedTcp`, `HttpHost`, or `TlsSni`). The duplicated upstream and revision values are untrusted hints and must equal verified ticket claims and current server state.

The server response is `Authorized` (discriminant 0, request ID, stream ID), `Accepted` (discriminant 1, request ID, stream ID, `Tcp` mode; reserved for Phase 4), or `Rejected` (discriminant 2, optional request ID, stable public error). Plan 05 emits only Authorized or Rejected. Byte-exact non-production Open/Authorized/Accepted/Rejected vectors are committed in [`crates/p2x-protocol/testdata/proxy-v1.json`](../../crates/p2x-protocol/testdata/proxy-v1.json), and protocol tests reject trailing data and unknown discriminants. The framed proxy reader is exercised by the bounded `proxy_frame_decode` fuzz target.

## Authorization

The server worker reads exactly one Open, requires write-half closure, rejects early application data, and performs immutable ticket envelope/signature/time verification using the configured verification ring. The single server owner receives a validated candidate, rechecks current auth/session, tenant, enabled service, registration revision/expiry, authorization revision, and availability, then atomically consumes the ticket ID and allocates the stream decision. A consumed ticket stays consumed after write failure, cancellation, connection loss, or shutdown.

The server verifies issuer, transport client, local server, tenant, service/upstream, selector fingerprint, registration revision and expiry, server authorization revision, active verification key, permission, time skew, and one-use limit. Replay cache capacity defaults to 8,192 and retains entries through ticket expiry plus the five-second clock skew; live entries are never evicted to make a replay valid again. Replay is `auth.ticket_replayed`. Unit tests cover binding failure without replay consumption and expiry-plus-skew retention. Configured proxy worker/replay limits are validated against 2,048 workers, 256 workers per client, 65,536 replay entries, and 30 seconds skew.

`Authorized` means only that the transport and ticket authorization gate passed. It is not application or tunnel success. Phase 3's finite diagnostic observes a correlated Authorized and closes the empty stream; Phase 4 adds upstream connection and the final Accepted response.

Every client open is sent on the selected libp2p `ConnectionId`. Existing confirmed direct connections win; otherwise a validated relay is prepared, DCUtR may establish a direct connection within the shared setup budget, and relay is selected after direct preference expires or fails. A guarded direct-open control enters the same pre-handshake failure path and proves one exact relay fallback. Once Open bytes may have reached a server, retry requires a fresh resolve and ticket. No raw ticket, selector, private target, or session value is logged.

The complete binding mutation matrix, low proxy-limit saturation, restart recovery, and graceful-drain process cases are not yet locally certified; the canonical runner fails them with explicit missing-evidence errors rather than accepting a generic Authorized result.
