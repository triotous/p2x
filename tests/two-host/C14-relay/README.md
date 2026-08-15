# C14 two-host relay deployment

Use two native hosts on separate networks: exchange on Host A, server on Host A or B, client on Host B. Open the configured TCP/QUIC relay listener ports and preserve UTC clocks. Build with the locked Rust toolchain on both hosts.

The default artifact directory is `target/p2x-spike/<P2X_RUN_ID>/C14-relay`. Setting `P2X_ARTIFACT_DIR=/absolute/base/path` changes it to `/absolute/base/path/C14-relay` for all three scripts. After the run, merge `exchange.ndjson`, `server.ndjson`, `client.ndjson`, and a manually prepared `environment.txt` into that one directory.

Host A:
```sh
P2X_RUN_ID=c14-... ./start-exchange.sh
```
Host B (server):
```sh
P2X_RUN_ID=c14-... P2X_EXCHANGE_ADDR='.../p2p/<exchange-peer>' ./start-server.sh
```
Other physical network (client):
```sh
P2X_RUN_ID=c14-... P2X_SERVER_CIRCUIT='.../p2p-circuit/p2p/<server-peer>' ./run-client.sh
```

Collect host OS/kernel, public addresses, firewall rules, binary revision, all three NDJSON logs, exact relay/circuit addresses, client/server observed paths, timings, payload/hash/half-close results, RSS/FD/process counts, and cleanup state. Validate the merged artifact directory with `tests/connectivity/manual-gates.sh --c14-validate <dir>`. Never commit raw public addresses or reusable identities.
