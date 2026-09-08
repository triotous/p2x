# Domain ingress verification

The canonical manual entry point is:

This entry point intentionally exits 2 after deterministic checks until the owner supplies the live exchange, DNS, certificate, and direct/relay fixtures; exit 2 means incomplete, not passed.

```sh
./tests/ingress/local.sh --case <name|all>
```

The script is deliberately a prerequisite-aware entry point. It builds the workspace binaries and runs deterministic adapter tests when available. It does not change DNS, certificates, hosts files, firewall rules, or network namespaces. Direct/relay, certificate verification, cross-host, platform/container, and long-running owner checks must be run separately and remain incomplete when their environment is unavailable.

Required live case families for the completed feature are:

- `http-direct`, `http-relay`, `http-keepalive`, `http-pipeline-route-lock`, `http-streaming`, `http-websocket`
- `http-local-rejections`, `http-error-mapping`, `tls-direct`, `tls-relay`, `tls-fragmentation`, `tls-local-rejections`
- `parse-deadlines`, `setup-budget`, `mixed-limits`, `shutdown-parsing`, `shutdown-active`
- `mixed-concurrency/64`, `mixed-concurrency/128`

Parser and worker unit tests are not substitutes for these real-process cases. Every case must assert exact route selection, original-byte preservation, no resolution/upstream activity on local rejection, terminal/resource cleanup, and privacy constraints before reporting success.
