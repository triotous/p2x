# Test runbooks

This directory contains the canonical verification entry points for the completed Plan 02 connectivity gate and Plan 03 identity/authentication gate. Run commands from the repository root unless a runbook says otherwise.

| Plan | Scope | Runbook |
|---|---|---|
| Plan 02 | Native connectivity, Linux namespaces, and two-host C14 | [`connectivity/README.md`](connectivity/README.md) |
| Plan 03 | Live auth, platform security, fuzzing, packet inspection, and connectivity regression | [`auth/README.md`](auth/README.md) |
| Plan 04 | Authenticated registry, relay admission, server availability, and restart recovery | [`registry/README.md`](registry/README.md) |
| Plan 05 | Exact resolution, one-use tickets, proxy authorization, and bounded client connections | [`resolution/README.md`](resolution/README.md) |

An unavailable required environment is incomplete verification, not a pass. Runners return exit code 2 for invalid usage or missing prerequisites and a non-zero code for failed assertions. A named case that lacks its required orchestration/evidence fails; it is never certified by a generic success path.

Generated test output belongs below `target/` and is ignored by Git. Preserve raw failing artifacts outside version control while debugging; commit only deliberately reviewed and scrubbed evidence. Never commit reusable identities, tokens, private keys, raw tickets, private upstream addresses, public-network details that policy treats as sensitive, or unreviewed packet captures.

`tests/registry/local.sh --case <name>` is the single registry harness entry point; it prepares a run-scoped artifact directory, returns 2 for invalid CLI usage, and exits nonzero when a prerequisite or observed assertion fails. `tests/resolution/local.sh --case <name|all>` is the single Plan 05a entry point; it prepares run-scoped identities, credentials, ticket/signing files, routes, artifacts, and privacy cleanup. It executes the existing TCP/QUIC and rejection cases plus idempotency, direct fallback, replay, expiry, reuse, and 64-open evidence-backed cases. The remaining named cases fail explicitly until their complete binding/orchestration evidence exists; Ping, a case label, synthetic response, or server-only event is never proxy evidence. See [`resolution/README.md`](resolution/README.md) for the exact case matrix and owner-executed checks.

`Dockerfile.test` packages the complete non-interactive test toolchain. Its
default entry point runs all container-safe automated suites; the privileged
Linux namespace suite is selected with the `linux` argument. Build and run
commands are documented in [`registry/README.md`](registry/README.md#73-container-runtime).

`tests/local/run.sh` is only a compatibility redirect to the canonical connectivity runner. It does not define weaker case meanings or replace the Linux namespace and C14 gates.
