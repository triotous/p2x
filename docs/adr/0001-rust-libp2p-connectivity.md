# ADR 0001: Rust libp2p connectivity foundation

- **Status:** Deferred — external topology evidence pending
- **Date:** 2026-08-15

## Decision

No final acceptance decision is made yet. The repository pins `libp2p` 0.56.0 and now implements the live relay/DCUtR lifecycle, fail-closed connection inventory, bounded exact-connection opening, bidirectional probe workers, typed terminal records, local fault matrix, Linux namespace runner, and two-host runner.

## Evidence

See [`plan/evidence/01-connectivity-spike-results.md`](../../plan/evidence/01-connectivity-spike-results.md). Native local C01 and C05–C13, including both 256 MiB paths, passed. Linux namespace execution and the C14 two-network run remain outstanding because the current host is macOS and only one physical network is available.

## Gate

Corrective Plan 02 work is allowed. Product Plan 03 must not begin until:

1. `tests/connectivity/manual-gates.sh --linux` passes C02–C13 on a Linux host with root/CAP_NET_ADMIN.
2. C14 passes on two native hosts on separate networks and its artifacts pass the canonical validator.
3. This ADR is updated to `Accepted`, `Accepted with required custom handler`, or `Rejected` from those observed results.
