# C02 Linux namespace deployment

Requires Linux, root or `CAP_NET_ADMIN`, `ip`, `iptables`, `tc`, and `ps`. On Manjaro, install the dependencies with `./install-deps.sh`; it uses `pacman` and is safe to rerun. Run on a disposable host. The canonical runner creates three run-scoped namespaces and a bridge, captures namespace/interface/rule state, process NDJSON and resource samples, then removes only those names.

Run from this case directory (the scripts are Bash scripts; do not invoke them with `sh`):

```sh
cd /path/to/p2x/tests/linux/C02-netns
./install-deps.sh
sudo P2X_RUN_ID=c02-$(date -u +%Y%m%dT%H%M%SZ) ./run.sh
```

If invoking from the repository root:

```sh
./tests/linux/C02-netns/install-deps.sh
sudo P2X_RUN_ID=c02-$(date -u +%Y%m%dT%H%M%SZ) ./tests/linux/C02-netns/run.sh
```

If the user has the required capabilities without root, omit `sudo`. Verify with:

```sh
for c in jq ip tc iptables nft; do command -v "$c"; done
ip netns list
```

Artifacts include `topology.txt`, raw process NDJSON, resource samples, and `summary.json`. C02 blocks peer TCP in both directions, so a receiver-observed direct result proves the QUIC-only path. Run the complete Linux matrix with `sudo ./tests/connectivity/manual-gates.sh --linux`.
