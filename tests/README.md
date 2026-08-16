# Test runbooks

This directory contains the canonical verification entry points for the completed Plan 02 connectivity gate and Plan 03 identity/authentication gate. Run commands from the repository root unless a runbook says otherwise.

| Plan | Scope | Runbook |
|---|---|---|
| Plan 02 | Native connectivity, Linux namespaces, and two-host C14 | [`connectivity/README.md`](connectivity/README.md) |
| Plan 03 | Live auth, platform security, fuzzing, packet inspection, and connectivity regression | [`auth/README.md`](auth/README.md) |
| Plan 04 | Authenticated registry, relay admission, server availability, and restart recovery | [`registry/README.md`](registry/README.md) |

An unavailable required environment is incomplete verification, not a pass. Runners return exit code 2 for missing prerequisites and a non-zero code for failed assertions.

Generated test output belongs below `target/` and is ignored by Git. Preserve raw failing artifacts outside version control while debugging; commit only deliberately reviewed and scrubbed evidence. Never commit reusable identities, tokens, private keys, raw tickets, private upstream addresses, public-network details that policy treats as sensitive, or unreviewed packet captures.

`tests/registry/local.sh --case <name>` is the single registry harness entry point; it prepares a run-scoped artifact directory, returns 2 for invalid CLI usage, and exits nonzero when a prerequisite or observed assertion fails.

`Dockerfile.test` packages the complete non-interactive test toolchain. Its
default entry point runs all container-safe automated suites; the privileged
Linux namespace suite is selected with the `linux` argument. Build and run
commands are documented in [`registry/README.md`](registry/README.md#73-container-runtime).

`tests/local/run.sh` is only a compatibility redirect to the canonical connectivity runner. It does not define weaker case meanings or replace the Linux namespace and C14 gates.
