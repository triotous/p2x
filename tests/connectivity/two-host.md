# Two-host C14 runbook

C14 is a manual gate and cannot be claimed from this repository alone. Run on two native hosts on separate networks after the lab lifecycle is complete.

1. Capture `uname -a`, `rustc --version`, `cargo --version`, `git rev-parse HEAD`, and the public interface names. Do not record seeds or private keys.
2. Permit the exchange listener TCP and UDP ports in both host firewalls. Permit the client/server listener ports only as required by the chosen topology.
3. On host A, run `cargo run --release -p p2x-exchange -- --identity-seed 1 --tcp-listen /ip4/0.0.0.0/tcp/4001 --unsafe-lab-public-relay`, saving stdout/stderr below `target/p2x-spike/<run-id>/`.
4. On host B, run `cargo run --release -p p2x-server -- --identity-seed 2 --tcp-listen /ip4/0.0.0.0/tcp/4002`, saving logs and its structured readiness line.
5. On either host, run `cargo run --release -p p2x-client -- --identity-seed 3 --exchange <exchange-address> --path relay`, saving the structured terminal result.
6. Assert JSON contains `passed`, `terminal_code`, client-selected path, server-observed path, timing, and both local connection-ID hashes. The two peers' local connection IDs must not be compared for equality.
7. Record whether a direct path was observed. Relay success is required; direct success is topology-dependent and must be reported honestly.
8. Redact seeds, private keys, payloads, and reusable identities before committing summaries. Stop all three processes and remove only this run's firewall rules and processes.

This runbook is not evidence that C14 passed; the scrubbed raw result and environment capture are required before updating the ADR.
