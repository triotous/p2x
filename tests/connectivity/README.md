# Connectivity gate harness

The canonical runners write typed per-process NDJSON, summaries, topology, and resource samples below `target/p2x-spike/<run-id>/`. Missing prerequisites and unavailable environments exit non-zero; no unsupported case is reported as passed.

Native local coverage:

```text
./tests/connectivity/local.sh --case C01
./tests/connectivity/local.sh --case C05
./tests/connectivity/local.sh --case C06
./tests/connectivity/local.sh --case C07
./tests/connectivity/local.sh --case C08
./tests/connectivity/local.sh --case C09
./tests/connectivity/local.sh --case C10 --streams 64
./tests/connectivity/local.sh --case C10 --streams 128
./tests/connectivity/local.sh --case C11 --bytes 268435456 --path direct
./tests/connectivity/local.sh --case C11 --bytes 268435456 --path relay
./tests/connectivity/local.sh --case C12
./tests/connectivity/local.sh --case C13 --iterations 100
```

Add `--exchange-transport quic` to repeat an applicable local case through the exchange QUIC listener; TCP is the default.

External gates use one manual entry point:

```text
sudo ./tests/connectivity/manual-gates.sh --linux
./tests/connectivity/manual-gates.sh --c14-validate target/p2x-spike/<run-id>/C14-relay
```

The Linux mode requires `ip`, `iptables`, `tc`, `ps`, root/CAP_NET_ADMIN, and three run-scoped namespaces. It executes C02–C13, including the 64/128 concurrency and direct/relay 256 MiB variants. C14 role commands and firewall guidance are in [`two-host.md`](two-host.md).

Dependency verification is pinned to `cargo-deny 0.20.2`; run `cargo deny check` from the repository root.
