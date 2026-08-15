# Connectivity spike results

**Status:** implementation complete; external architecture gates pending

## Verified baseline

- Reviewed implementation: `e84df74adfe29c5a6690bb1f520ea2b060aa80c2` plus this evidence-only documentation commit.
- Toolchain: `rustc 1.96.0`, `cargo 1.96.0`, `cargo-deny 0.20.2`.
- Network baseline: `libp2p = 0.56.0`; exact resolved components are frozen in `Cargo.lock`.
- Platform observed here: native macOS (`Darwin`), same-host exchange/server/client processes.
- Static verification: formatting, workspace tests (42 library unit tests plus the exact-connection integration test), Clippy with warnings denied, and `cargo deny check` all passed.
- Dependency adjudication: Zlib is explicitly allowed; unpublished workspace packages are ignored until the repository SPDX choice is made. RUSTSEC-2026-0118 is unreachable because DNSSEC features are absent. RUSTSEC-2026-0119 and RUSTSEC-2024-0436 have narrow, removal-conditioned ignores in `deny.toml`; `cargo deny check` reports all four checks `ok`.

## Native local observations

All rows were produced by `tests/connectivity/local.sh`; raw NDJSON and resource samples remain ignored under `target/p2x-spike/<run-id>/`.

| Case | Run ID | Observed result |
| --- | --- | --- |
| C01 TCP | `20260815T091040Z-5196` | Relay became ready; DCUtR-selected exact direct probe passed. |
| C01 QUIC exchange | `20260815T093122Z-56652` | QUIC exchange entry, reservation, DCUtR, and exact direct probe passed. |
| C05 | `20260815T091535Z-6577` | One peer pair retained relay and direct simultaneously; receiver observed one exact probe on each path. |
| C06 | `20260815T091610Z-6936` | The DCUtR terminal result was suppressed; relay committed inside the 1.3–2.5 second tolerance window. |
| C07 | `20260815T091643Z-7469` | Exchange was interrupted during a 256 MiB direct half-close; both hashes matched, EOF was observed, and server became degraded. |
| C08 | `20260815T091851Z-13014` | The selected relay connection was fault-closed; the same client process reconnected and the next 1 MiB half-close passed. |
| C09 | `20260815T091940Z-13389` | Two low-profile reservations were admitted, the excess reservation was denied, and an existing relay probe completed. |
| C10 / 64 | `20260815T093041Z-56054` | 64 concurrent exact direct probes completed independently. |
| C10 / 128 | `20260815T093055Z-56324` | Two peers each admitted 64 concurrent direct probes; all 128 receiver observations completed. |
| C11 direct | `20260815T092853Z-49148` | 256 MiB bidirectional slow-reader hashes matched; concurrent nonce completed first; peak client RSS was 22,320 KiB. |
| C11 relay | `20260815T092933Z-52420` | 256 MiB bidirectional slow-reader hashes matched; concurrent nonce completed first; peak client RSS was 23,520 KiB. |
| C12 | `20260815T092027Z-13735` | Two real reservation renewals were observed while the original relay probe remained valid. |
| C13 | `20260815T092524Z-39212` | 100 relay connect/probe/close iterations completed after correcting all-path churn cleanup. |

These observations close the native local implementation findings. They do not substitute for Linux packet filtering or a real two-network topology.

## Remaining external evidence

- C02–C13 must be executed on Linux with root/CAP_NET_ADMIN using `tests/connectivity/manual-gates.sh --linux`. The runner creates three run-scoped namespaces, applies TCP/UDP peer filters for C02–C04, and reuses the same canonical fault matrix for C05–C13. This macOS host cannot execute or validate those mutations.
- C14 must be executed on two native hosts on separate networks using the three role scripts in `tests/two-host/C14-relay/`, followed by `tests/connectivity/manual-gates.sh --c14-validate <artifact-directory>`.

ADR 0001 therefore remains `Deferred`. Plan 02 corrective implementation is permitted and complete locally; product Plan 03 remains blocked until the Linux and C14 artifacts pass and the ADR is changed to an accepted or rejected decision.
