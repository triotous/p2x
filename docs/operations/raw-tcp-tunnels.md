# Raw TCP tunnels

Plan 06 exposes fixed TCP listeners from the client configuration. Each `raw_tcp` entry names a loopback bind and references one `protocol: tcp` target; selectors remain defined only under `targets`.

```yaml
raw_tcp:
  - name: postgres-local
    bind: 127.0.0.1:15432
    route_id: postgres
limits:
  max_ingress_connections: 512
  max_streams_per_server: 128
  copy_buffer_bytes: 32768
```

The client binds all validated listeners before dialing the exchange. A local accept starts one absolute setup deadline. Bytes read before Accepted are held in a fixed prebuffer and are sent first after the correlated exchange-issued ticket, exact P2P path, and server Accepted response. A full buffer applies normal kernel backpressure. Local setup failure closes only that socket.

The server service entry combines public advertisement with private policy. `connect` must be one nonzero IP-literal TCP `SocketAddr`; it is not sent in registry, resolve, ticket, or lifecycle data. `enabled: false` is unavailable and is never dialed.

```yaml
services:
  - upstream_id: postgres
    selector:
      protocol: tcp
      metadata: {service: postgres}
    enabled: true
    connect: 127.0.0.1:5432
    connect_timeout_ms: 3000
    idle_timeout_ms: 300000
    concurrency_limit: 64
proxy:
  max_workers: 256
  max_workers_per_client: 32
  max_upstream_dials: 64
  copy_buffer_bytes: 32768
```

The stream carries opaque bytes only. It has independent directions, propagates half-close, applies backpressure per direction, and uses the server service idle timeout. A P2P connection loss resets the active stream; a later local connection resolves and selects a new path. Exchange control loss does not interrupt an already accepted stream.

`upstream.connect_timeout` and `upstream.connect_failed` occur before Accepted and consume the ticket. `upstream.idle_timeout` is a post-Accepted terminal. There is no transparent retry or migration of an active TCP stream. Use `./tests/tunnel/local.sh --case <name|all>` for the automated local gate. Direct/relay topology loss, soak, and platform evidence remain separate owner-executed checks.
