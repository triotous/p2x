# Connectivity spike harness

The local and Linux-namespace entry points write raw logs and JSON summaries below `target/p2x-spike/<run-id>/`. They fail non-zero for unsupported or unavailable cases; a disabled case is never treated as a pass.

```text
./tests/connectivity/local.sh --case C01
./tests/connectivity/netns.sh --case C02
```

`netns.sh` requires Linux, `iproute2`, and the privileges needed for namespace/network mutation. C14 is manual and is documented in [`two-host.md`](two-host.md). The live relay reservation, probe payload, and matrix execution remain outstanding, so no C01–C14 result is currently claimed.

The workspace builds exactly `p2x-exchange`, `p2x-server`, and `p2x-client`. Each binary constructs and polls one libp2p swarm, emits structured lifecycle lines, and supports deterministic lab-only Ed25519 identity derivation with `--identity-seed`.
