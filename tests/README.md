# Connectivity test deployments

Each case is isolated in its own directory and contains its deployment/run script, required configuration, artifact contract, and collection instructions.

| Environment | Cases | Entry point |
|---|---|---|
| `local/` | C01, C05-C13 | `tests/local/<case>/run.sh` |
| `linux/` | C02-C13 | `tests/linux/C02-netns/run.sh` plus the case README/config |
| `two-host/` | C14 | `tests/two-host/C14-relay/start-exchange.sh`, `run-client.sh` |

Every run must record the run ID, git revision/dirty state, tool versions, raw per-process NDJSON, topology, resource samples, exactly one client terminal result, server-observed path, and cleanup status. Environment-unavailable cases fail with exit code 2 and are never reported as passed.
