# C02 Linux namespace deployment

Requires Linux, root or `CAP_NET_ADMIN`, `ip`, `jq`, `tc`, and `iptables` or `nft`. On Manjaro, install the dependencies with `./install-deps.sh`; it uses `pacman` and is safe to rerun. Run on a disposable host. The case creates only names prefixed by `P2X_RUN_ID`, captures namespace/interface/rule state, process NDJSON, resource samples, and cleanup status.

```sh
./install-deps.sh
sudo P2X_RUN_ID=c02-$(date -u +%Y%m%dT%H%M%SZ) ./run.sh
```

If the user has the required capabilities without root, omit `sudo`. Verify with:

```sh
for c in jq ip tc iptables nft; do command -v "$c"; done
ip netns list
```

Artifacts: topology, namespace/permission errors, raw process logs (once the matrix is wired), `resources.ndjson` (once sampling is wired), and `summary.json`. The current script is an honest namespace prerequisite smoke and exits 2 with `not_implemented`; it must not be read as a connectivity pass. A full run must fail on missing tools, leaked namespaces/interfaces/rules, invalid schema, duplicate terminal results, or non-zero final resources.
