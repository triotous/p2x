# ADR 0001: Rust libp2p connectivity foundation

- **Status:** Deferred — architecture gate incomplete
- **Date:** 2026-08-14

## Decision

No acceptance decision is made by the connectivity spike yet. The repository pins `libp2p` 0.56.0 provisionally and records deterministic contracts for connection inventory, path timing, reservation event ordering, bounded probe headers, and exact-connection stream event identity.

## Evidence

See [`plan/evidence/01-connectivity-spike-results.md`](../../plan/evidence/01-connectivity-spike-results.md). The live relay lifecycle, payload exchange, executable harness, mandatory connectivity matrix, and C14 two-host run remain outstanding.

## Gate

Plans 02/03 must not begin until the live matrix proves relay reservation/renewal, direct TCP and QUIC, exact `ConnectionId` targeting when direct and relay coexist, bounded fallback, interruption behavior, and resource bounds.
