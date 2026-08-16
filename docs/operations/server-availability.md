# Server availability operations

Product mode requires `--services-file`. The file is strict bounded YAML:

```yaml
schema_version: 1
registration:
  requested_lease_seconds: 30
  refresh_seconds: 10
services:
  - upstream_id: orders-production
    selector:
      protocol: http
      metadata: {service: orders, environment: production, region: eu-west}
    enabled: true
```

Schema version is `1`; lease is 10–60 seconds and defaults to 30; refresh defaults to 10, is at least one second, and is at most half the lease. Unknown fields, aliases, duplicate IDs/selectors, invalid metadata, non-strict booleans, and an empty enabled set fail before networking. Disabled entries are validated then omitted. Phase 2 `Ready` means configured and accepted for registration, not upstream probe health.

## Readiness and recovery

The server has one swarm owner and a pure availability state machine. It authenticates and confirms Ping, acquires an authorized Circuit Relay v2 reservation, confirms the canonical circuit address, then registers the complete service set. Readiness is true only when current auth, the current reservation generation, an instance/revision-matching unexpired registration, and non-draining state are all true. `server_readiness` lifecycle records report each gate separately. Auth renewal retains the old valid session while a replacement is authenticated and Ping-confirmed; reservation and registry state are not flapped by a successful renewal.

Reservation and registration retries use jittered exponential backoff from 250ms to 10s. Registration refresh retains the instance and revision but uses a fresh request ID; timeout retries retain the canonical request ID for idempotent replay. A lease deadline immediately clears readiness. Reservation loss, session expiry, revocation, final exchange disconnect, and exchange restart remove exchange-side registration and relay authority. A healthy restarted exchange is repopulated by the same server process and PeerId; the target recovery window is 60 seconds.

On graceful shutdown, readiness becomes false, one current registration is withdrawn with a five-second bound, the circuit listener and exchange connections close, and timers/resources drain. The registry is in-memory and single-exchange in this phase; exchange restart empties it.

## Exchange and relay requirements

Product exchange startup requires repeatable validated public `--advertise` addresses containing the exchange PeerId; listener-derived unspecified addresses are never advertised. Firewall and port policy must allow peers to reach these direct TCP/QUIC addresses. Relay admission is installed only after current authenticated role/scope/profile checks: servers require `reserve_relay`; clients require `open_proxy_stream`. Product relay uses one reservation per server and 32 logical circuits per client (the pinned libp2p adapter passes the required per-peer boundary values); `DefaultLab` remains the compatibility lab profile and `LimitTest` is test-only. Relay limits bound reservations, circuits, bytes, durations, counts, and rates, but do not provide throughput shaping.

Diagnostics use counts, durations, reason codes, opaque revisions, and selector fingerprints. They do not log service metadata, selectors, credentials, session IDs, relay payloads, or private connect targets. Native Linux and macOS are expected to run product auth/reservation/registration/relay-Ping; container and two-host results remain owner-executed environment checks.
