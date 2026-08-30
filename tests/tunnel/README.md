# Raw TCP tunnel gate

`./tests/tunnel/local.sh --case <name|all>` is the single local process entry point for Plan 06. It builds the workspace, creates run-scoped identities/credentials/configuration under a temporary directory, starts an exchange, server, fixed-loopback client listener, and an endpoint fixture, then validates opaque bytes or the expected upstream failure/idle close. Artifacts are written below `target/p2x-tunnel/`.

The exact case list is the one in `tests/tunnel/local.sh`:

- byte flow: `fixed-tcp-direct`, `fixed-tcp-relay`, `half-close-direct`, `half-close-relay`, `large-slow-direct`, `large-slow-relay`;
- upstream and path behavior: `upstream-refused`, `upstream-timeout`, `idle-timeout`, `control-loss-direct`, `path-loss-recovery`, `terminal-correlation`;
- recovery: `per-ingress-failure-recovery/resolve`, `per-ingress-failure-recovery/path-capacity`, `per-ingress-failure-recovery/upstream`, `per-ingress-failure-recovery/pre-accept-eof`;
- limits: `stream-limits`, `stream-limits/client-ingress`, `stream-limits/client-server`, `stream-limits/server-global`, `stream-limits/server-client`, `stream-limits/server-service`, `stream-limits/server-dial`;
- deadlines and shutdown: `deadline-stages`, `shutdown-cancellation`, `shutdown/client-setup`, `shutdown/client-active`, `shutdown/server-setup`, `shutdown/server-active`;
- concurrency and resources: `concurrent-streams`, `concurrent-streams/64-sustained`, `concurrent-streams/128-headroom`, `resource-baseline/128`.

Each case executes named assertions. Accepted streams require matching client/server `tunnel_accepted` records, exactly one correlated `tunnel_terminal` per Accepted on each side, frozen path/setup metadata, directional counters, and a mandatory final zero-valued resource record. Recovery, limit, deadline, shutdown, idle-isolation, correlation, and concurrency cases add their case-specific owner/endpoint assertions; `concurrent-streams/64-sustained` opens 64 streams and `concurrent-streams/128-headroom` plus `resource-baseline/128` open 128. Resource evidence records before/peak/after RSS and FD samples for both client and server and declares two client-pump plus two server-pump direction buffers and at most one client pre-Accept buffer per active setup. Privacy scans use each run's generated selector, upstream, credential, ticket/session, address, and payload values across process NDJSON. Every process log must contain exactly one process terminal, and the final scan requires no P2X process or run-owned fixture socket. Direct/relay firewall or namespace enforcement, cross-host networking, platform coverage, and long-running soak remain owner-executed follow-up gates.

Every run uses a fresh upstream port and scans process output for credentials, session/ticket markers, and the configured upstream address. The server's upstream `connect` value is never advertised or logged. Missing loopback listener permission is an incomplete environment, not a pass.
