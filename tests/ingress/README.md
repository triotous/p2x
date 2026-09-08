# Domain ingress verification

The canonical local entry point is:

```sh
./tests/ingress/local.sh --case <name|all>
```

The script builds the client, runs the domain/HTTP/TLS parser and adapter tests, builds all three bounded fuzz targets, and emits an assertion-derived JSON result. It does not change DNS, certificates, hosts files, firewall rules, or network namespaces. Cross-host DNS and certificate distribution, platform/container, firewall, and long-running checks remain Phase 6 owner evidence.

Required live case families for the completed feature are:

- `http-direct`, `http-relay`, `http-keepalive`, `http-pipeline-route-lock`, `http-streaming`, `http-websocket`
- `http-local-rejections`, `http-error-mapping`, `tls-direct`, `tls-relay`, `tls-fragmentation`, `tls-local-rejections`
- `parse-deadlines`, `setup-budget`, `mixed-limits`, `shutdown-parsing`, `shutdown-active`
- `mixed-concurrency/64`, `mixed-concurrency/128`

Parser and worker unit tests are not substitutes for these real-process cases. Every case must assert exact route selection, original-byte preservation, no resolution/upstream activity on local rejection, terminal/resource cleanup, and privacy constraints before reporting success.
