# ADR 0001: Rust libp2p connectivity foundation

- **Status:** Accepted — custom exact-connection handler required
- **Date:** 2026-08-15

## Decision

Accept `rust-libp2p` 0.56.0 as the P2X connectivity foundation. The accepted design includes the repository's custom bounded `ProbeStreamBehaviour`/connection handler because exact direct-versus-relay `ConnectionId` selection is a product invariant and is not delegated to a generic stream opener.

The accepted baseline includes the live relay/DCUtR lifecycle, fail-closed connection inventory, bounded exact-connection opening, bidirectional probe workers, typed terminal records, local fault matrix, Linux namespace runner, and two-host runner. Product plans may build on this foundation without reopening the architecture decision unless a libp2p/connectivity component changes or an accepted invariant regresses.

## Evidence

See [`plan/evidence/01-connectivity-spike-results.md`](../../plan/evidence/01-connectivity-spike-results.md). Native local C01 and C05–C13 passed, including both 256 MiB paths. Linux namespace C02–C13 passed with the required filters/faults and loads. C14 passed between native Linux and macOS hosts on separate networks with relay selected and observed by both endpoints.

## Consequences

- Product Plan 03 may proceed.
- The custom exact-connection behaviour/handler, bounded request lifecycle, connection ledger, reservation state, and path state machine are required architecture, not disposable spike code.
- Relay remains the availability floor; direct QUIC/TCP is preferred but topology-dependent.
- Active arbitrary TCP streams may reset when their selected P2P connection dies; transparent stream migration remains deferred.
- A change to `libp2p`, relay/DCUtR, the exact-open handler, transport composition, or the accepted limits invalidates the affected evidence and requires proportional C01–C14 reruns before release.

## Gate Closure

The Phase 0 architecture gate closed on 2026-08-15 after the canonical Linux C02–C13 summaries and C14 two-network summary reported `passed: true`. The product owner confirmed the complete Plan 02 test set and accepted this ADR.
