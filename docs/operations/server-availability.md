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
proxy:
  max_workers: 256
  max_workers_per_client: 32
  max_replay_entries: 8192
  ticket_clock_skew: 5
```

Schema version is `1`; lease is 10–60 seconds and refresh is at least one second and at most half the lease. The complete file contains 1–128 entries. Unknown fields, aliases, duplicate IDs/selectors, invalid metadata, non-strict booleans, and an empty service set fail before networking. Disabled entries remain validated and unavailable. Proxy limits default to 256 workers, 32 workers per client, 8,192 replay entries, and five seconds skew; hard maxima are 2,048, 256, 65,536, and 30.

## Readiness and recovery

The server has one swarm owner and a pure availability state owner. It authenticates and confirms Ping, acquires an authorized Circuit Relay v2 reservation, confirms the canonical circuit address, then registers the complete service set. Readiness is true only when current auth, the current reservation generation, an instance/revision-matching unexpired registration, and non-draining state are all true. `server_readiness` records report each gate separately, including still-current component gates while the overall server is draining.

Reservation and registration retries use jittered exponential backoff from 250ms to 10s. Refresh scheduling uses configured `refresh_seconds` and is clamped before lease expiry. Registration refresh retains the instance and revision but uses a fresh request ID; a timeout retry retains the exact canonical request body and request ID for idempotent replay. If the session or body changes, a fresh request ID is required. A lease deadline immediately clears readiness. Reservation loss, session expiry, revocation, final exchange disconnect, and exchange restart remove exchange-side registration and relay authority.

## Proxy admission and drain

For each inbound product proxy stream, the bounded worker reads exactly one flushed Open frame without requiring write-half closure and verifies immutable envelope/signature/time structure outside the swarm owner. The owner rechecks current auth, tenant, enabled TCP service, registration revision/expiry, authorization revision, and current ticket time; it preflights global/per-client/per-service/dial capacity, reserves stream admission, and only then consumes replay state and allocates a stream ID. The worker then dials the immutable configured IP-literal upstream and emits `Accepted` only after connect success. `upstream.connect_timeout` and `upstream.connect_failed` are bounded pre-Accepted failures; consumed tickets remain consumed. After Accepted, the worker owns both sockets and the fixed-buffer duplex pump; `upstream.idle_timeout`, cancellation, half-close, connection loss, and shutdown release admission exactly once.

On graceful shutdown, proxy admission rejects new Opens, readiness becomes false, the current registration is withdrawn with a five-second bound, handshake workers/dials/accepted pumps drain with cancellation, the circuit listener and exchange connections close, and timers/resources drain. Workers are owner-tracked by task ID and immutable worker record; normal return, panic, channel loss, abort, and shutdown all converge on owner completion rather than best-effort release delivery. Candidate, promotion, acknowledgement, and Accepted evidence transitions share the worker deadline. Final tunnel records retain explicit terminal classes; final resource samples must contain one mandatory zero-valued record for logical workers, tasks, dials, active admissions, and service entries. The local resolution runner certifies restart and held-resource drain behavior with persisted identities and bounded process subcases. Deployment/platform behavior remains a separate owner-executed gate.

`tests/registry/local.sh --case all` remains the registry availability entry point. `tests/resolution/local.sh` additionally proves ticket expiry, worker verification binding rejection, direct fallback, replay rejection, repeated independent tickets, 64 concurrent empty authorization gates, low-limit saturation, registration replacement, restart recovery, and complete drain subcases.

Diagnostics use counts, durations, reason codes, opaque revisions, and selector fingerprints. They do not log service metadata, selectors, credentials, session IDs, relay payloads, or private connect targets. Native Linux and macOS are expected to run product auth/reservation/registration/relay-Ping; container and two-host results remain owner-executed environment checks.
