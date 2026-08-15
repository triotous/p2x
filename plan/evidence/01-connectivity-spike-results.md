# Connectivity spike results

**Status:** complete; ADR 0001 accepted

## Verified baseline

- Executed connectivity implementation: `389690c98aa6757732489974ac461758feb04cff`; later commits `508271d` and `51222c2` hardened C14 capture and provenance validation without changing the probed connectivity implementation.
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

These observations close the native local implementation findings.

## Linux namespace observations

The canonical Linux runner created isolated exchange/server/client namespaces. The committed topology artifacts show the named peer filters for C02–C04; every canonical summary below reports `passed: true` and `probe.ok`.

| Case | Run ID | Observed result |
| --- | --- | --- |
| C02 | `20260815T104620Z-71051` | TCP peer traffic was blocked; one receiver-observed direct probe passed over the allowed path. |
| C03 | `20260815T104620Z-71235` | UDP peer traffic was blocked; one receiver-observed direct probe passed over the allowed path. |
| C04 | `20260815T104621Z-71379` | Direct peer traffic was blocked; relay was selected and observed. |
| C05 | `20260815T104622Z-71525` | Two exact-connection probes completed with direct and relay coexisting. |
| C06 | `20260815T104623Z-71681` | Suppressed DCUtR terminal handling committed relay and completed the probe. |
| C07 | `20260815T104625Z-72010` | The interruption case completed on the selected direct path. |
| C08 | `20260815T104642Z-74425` | Relay failure/recovery case completed with the next relay probe. |
| C09 | `20260815T104643Z-74603` | Low relay limits rejected excess admission while the admitted relay probe passed. |
| C10 / 64 | `20260815T104646Z-74817` | All 64 concurrent direct probes completed. |
| C10 / 128 | `20260815T104647Z-74968` | All 128 concurrent direct probes completed. |
| C11 direct | `20260815T104647Z-75152` | 256 MiB direct slow-reader transfer and concurrent nonce probe passed. |
| C11 relay | `20260815T104719Z-80106` | 256 MiB relay slow-reader transfer and concurrent nonce probe passed. |
| C12 | `20260815T104755Z-85674` | Reservation renewal case stayed relay-reachable and passed. |
| C13 | `20260815T104926Z-96148` | All 100 relay churn probes completed. |

## Two-network C14 observation

The validated artifact root `target/p2x-spike/c14-20260815T114925Z/C14-relay/` records:

- Host A: native Linux, running exchange and server;
- Host B: native macOS, running client;
- distinct network/interface environments, with relay TCP/UDP permitted;
- identical tested implementation commit `389690c98aa6757732489974ac461758feb04cff` on both hosts;
- client selected relay, receiver reported relay, terminal code `probe.ok`, and setup completed in 580 ms;
- `summary.json` reports `passed: true` and the expected scrubbed artifacts.

## Gate outcome

The native, Linux namespace, and C14 evidence satisfy the Phase 0 connectivity gate. The product owner confirmed completion of the full Plan 02 test set on 2026-08-15. ADR 0001 is accepted with the custom exact-connection behaviour/handler as a required part of the architecture, and Product Plan 03 may proceed.
