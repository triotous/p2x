# Two-host C14 runbook

C14 requires two native hosts on separate networks. Use one run ID and copy the three NDJSON files plus `environment.txt` into one `C14-relay` artifact directory before validation. By default that directory is `target/p2x-spike/<P2X_RUN_ID>/C14-relay`. If `P2X_ARTIFACT_DIR` is set, it replaces the `target/p2x-spike/<P2X_RUN_ID>` base, so the directory is `<P2X_ARTIFACT_DIR>/C14-relay`.

1. On both hosts, check out the same clean commit and record `uname -a`, `rustc --version`, `cargo --version`, `cargo deny --version`, `git rev-parse HEAD`, `git status --short`, public interface names, and relevant firewall/NAT notes in `environment.txt`. Do not record private keys or reusable identities.
2. Permit host A inbound TCP/4001 and UDP/4001. Permit host B inbound TCP/4002 and UDP/4002 only if testing direct reachability; relay success must not depend on those peer ports.
3. On host A, set `P2X_RUN_ID` and run `tests/two-host/C14-relay/start-exchange.sh`. Replace the emitted `0.0.0.0` component with host A's reachable address and export the complete `/p2p/<exchange-peer>` multiaddress as `P2X_EXCHANGE_ADDR` on host B.
4. On host B, set the same `P2X_RUN_ID` and `P2X_EXCHANGE_ADDR`, then run `tests/two-host/C14-relay/start-server.sh`. Export its typed `listener_ready` circuit address as `P2X_SERVER_CIRCUIT` on the client host.
5. From the other physical network, set the same `P2X_RUN_ID` and `P2X_SERVER_CIRCUIT`, then run `tests/two-host/C14-relay/run-client.sh`.
6. Stop exchange and server with SIGINT so each writes its terminal record. Copy `exchange.ndjson`, `server.ndjson`, `client.ndjson`, and `environment.txt` into one directory. `environment.txt` is assembled manually from the information recorded in step 1; the process scripts do not create it.
7. Run `tests/connectivity/manual-gates.sh --c14-validate <artifact-directory>`. It requires exactly one passing relay terminal and a matching server-observed relay probe. Record any direct path observation separately; direct success is topology-dependent.
8. Redact public IPs if required by project policy, seeds, private keys, and reusable identity material before committing the scrubbed summary. Preserve raw failures outside version control.

The validator creates `summary.json` only when the mandatory relay evidence is complete. Until that summary is reviewed with the Linux matrix, ADR 0001 stays `Deferred`.
