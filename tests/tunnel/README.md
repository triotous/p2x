# Raw TCP tunnel gate

`./tests/tunnel/local.sh --case <name|all>` is the single local process entry point for Plan 06. It builds the workspace, creates run-scoped identities/credentials/configuration under a temporary directory, starts an exchange, server, fixed-loopback client listener, and an endpoint fixture, then validates opaque bytes or the expected upstream failure/idle close. Artifacts are written below `target/p2x-tunnel/`.

The implemented local cases are `fixed-tcp-direct`, `fixed-tcp-relay`, `upstream-refused`, `upstream-timeout`, `idle-timeout`, `half-close-direct`, `half-close-relay`, `large-slow-direct`, `large-slow-relay`, `concurrent-streams`, `stream-limits`, `control-loss-direct`, `path-loss-recovery`, and `shutdown-cancellation`. The runner currently provides the common real-process smoke path for each case name; topology-specific direct/relay loss, 256 MiB RSS evidence, 64-stream concurrency evidence, and shutdown fault orchestration remain owner-executed follow-up gates.

Every run uses a fresh upstream port and scans process output for credentials, session/ticket markers, and the configured upstream address. The server's upstream `connect` value is never advertised or logged. Missing loopback listener permission is an incomplete environment, not a pass.
