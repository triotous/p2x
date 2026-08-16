# Test runbooks

This directory contains the canonical verification entry points for the completed Plan 02 connectivity gate and Plan 03 identity/authentication gate. Run commands from the repository root unless a runbook says otherwise.

| Plan | Scope | Runbook |
|---|---|---|
| Plan 02 | Native connectivity, Linux namespaces, and two-host C14 | [`connectivity/README.md`](connectivity/README.md) |
| Plan 03 | Live auth, platform security, fuzzing, packet inspection, and connectivity regression | [`auth/README.md`](auth/README.md) |

An unavailable required environment is incomplete verification, not a pass. Runners return exit code 2 for missing prerequisites and a non-zero code for failed assertions.

Generated test output belongs below `target/` and is ignored by Git. Preserve raw failing artifacts outside version control while debugging; commit only deliberately reviewed and scrubbed evidence. Never commit reusable identities, tokens, private keys, raw tickets, private upstream addresses, public-network details that policy treats as sensitive, or unreviewed packet captures.

`tests/local/run.sh` is only a compatibility redirect to the canonical connectivity runner. It does not define weaker case meanings or replace the Linux namespace and C14 gates.
