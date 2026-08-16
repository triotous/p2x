# Registry, relay admission, and server availability tests

Run commands from the repository root. The live runner creates temporary identities,
credentials, ticket keys, service files, and loopback ports. Evidence is written to
`target/p2x-registry/<run-id>/<case>/`; secrets are removed when the case exits.

## Prerequisites

- The repository-pinned Rust toolchain and `python3` are installed.
- TCP and UDP loopback listeners are allowed.
- No application images are needed. `Dockerfile.test` contains this runner and all
  other test suites; the three application images remain a later deployment task.

Run one case or the complete local suite:

```text
./tests/registry/local.sh --case <name>
./tests/registry/local.sh --case all
```

Every case starts real `p2x-exchange` and `p2x-server` processes; cases that need
a relay consumer also start the real `p2x-client`. A pass requires exit status 0,
`"passed":true` in `summary.json`, observed lifecycle assertions, a clean privacy
scan, and final logical resource counts. A requested case label is never treated as
evidence.

## Live case procedures

### `valid-tcp`

1. Start product exchange on its advertised TCP address.
2. Start an authorized server; wait for auth, one reservation, atomic Register, and
   `server_readiness.ready=true`.
3. Run an authorized client Ping through the server's relay circuit.
4. Wait for Refresh with the original registration revision.
5. Stop server and require Withdraw; stop exchange and require all counts to be zero.

```text
./tests/registry/local.sh --case valid-tcp
```

### `valid-quic`

Repeat the `valid-tcp` steps using only the advertised QUIC-v1/UDP exchange address.
The case fails if registration, relay Ping, Refresh, Withdraw, or zero cleanup is not
observed.

```text
./tests/registry/local.sh --case valid-quic
```

### `exchange-restart`

1. Complete the TCP register, relay Ping, and Refresh flow.
2. Stop exchange and require the still-running server to publish readiness false.
3. Restart exchange with the same identity and address without restarting server.
4. Require the same server PID and PeerId to reauthenticate, reserve, register, and
   publish readiness at generation 2 or later within 60 seconds.
5. Gracefully stop both processes and require zero final counts.

```text
./tests/registry/local.sh --case exchange-restart
```

### `multi-service`

1. Start one authorized server with two distinct services.
2. Require one Register mutation with one registration and two selector owners.
3. Require Refresh to retain the same revision and both selectors.
4. Stop server and require Withdraw to remove the complete set atomically.

```text
./tests/registry/local.sh --case multi-service
```

### `selector-conflict`

1. Start two authorized servers in the same tenant with the same complete selector.
2. Require the first registration to remain the sole registration and selector owner.
3. Require the second request to return `registry.conflict` without changing counts.
4. Stop both actors and require zero final counts.

```text
./tests/registry/local.sh --case selector-conflict
```

### `cross-tenant`

1. Start two authorized servers in different tenants with identical unscoped selectors.
2. Require both registrations and two tenant-scoped selector owners.
3. Stop both servers and require both tenant-owned entries to be removed.

```text
./tests/registry/local.sh --case cross-tenant
```

### `register-without-reservation`

1. Enable the guarded test hook and authenticate a server without requesting a relay
   reservation.
2. Send Register and require `registry.reservation_required`.
3. Require registration and selector-owner counts to remain zero.

```text
./tests/registry/local.sh --case register-without-reservation
```

### `unauthorized`

1. Attempt product startup with an unauthenticated token and require
   `auth.invalid_credential`.
2. Attempt server auth using a client-role credential and require
   `auth.role_forbidden`.
3. Authenticate a server without `reserve_relay`; require `ReservationReqDenied` and
   zero reservation/registry allocation.
4. Authenticate a server without `register_services`; require registry denial.
5. Terminate every actor and require sessions, relay authority, reservations, circuits,
   registrations, selectors, and pending requests all to be zero.

```text
./tests/registry/local.sh --case unauthorized
```

### `lease-expiry`

1. Register with the minimum ten-second lease and suppress the scheduled Refresh.
2. Require readiness false and removal of the registration and selector owner at expiry.
3. Send the old late Refresh; require `registry.not_found`, never `registry.refreshed`.
4. Require recovery to use a full Register with a new revision.

```text
./tests/registry/local.sh --case lease-expiry
```

### `reservation-loss`

1. Reach registered readiness, then remove the relay listener and close its exchange
   connection through the guarded test hook.
2. Require readiness false and immediate reservation/registration removal.
3. Require selector ownership and final resource counts to return to zero.

```text
./tests/registry/local.sh --case reservation-loss
```

### `final-disconnect`

1. Reach registered readiness.
2. Kill the server without Withdraw to simulate final connection loss.
3. Require exchange to remove the session, relay authority, reservation, registration,
   and selector owner idempotently.

```text
./tests/registry/local.sh --case final-disconnect
```

### `revocation-restart`

1. Register a server, stop exchange, and restart it with that credential marked revoked.
2. Require the unchanged server identity/token to receive terminal auth rejection and
   allocate no relay or registry state.
3. Restart with the credential allowed, start the same server identity again, and require
   a fresh auth/reservation/registration generation.
4. Stop everything and require zero final counts.

```text
./tests/registry/local.sh --case revocation-restart
```

### `idempotent-replay`

1. Drop the first successful Register response at the server test hook.
2. Replay the exact request ID and bytes; require the same revision and mutation count 1.
3. Reuse that request ID with a changed lease; require `protocol.malformed` and mutation
   count to remain 1.

```text
./tests/registry/local.sh --case idempotent-replay
```

### `registry-inflight-limit`

1. After reservation readiness, send two concurrent Register requests from one server.
2. Require one request to be admitted and the per-peer N+1 request to return
   `limit.registry_requests`.
3. Close the server and require the registry in-flight permit count to return to zero.

```text
./tests/registry/local.sh --case registry-inflight-limit
```

### `registry-limit`

1. Register once and refresh once per second with a ten-second lease.
2. Require exactly 30 accepted registry operations in the rolling minute.
3. Require operation 31 to return `limit.registry_requests` without losing the current
   record.
4. Stop server and require every permit and logical resource to be released.

The 128-global admission boundary and every release terminal are additionally covered by
`cargo test -p p2x-exchange registry_admission::tests`; the local product process case
uses the production rolling-rate boundary and the separate per-peer concurrent case.

```text
./tests/registry/local.sh --case registry-limit
```

### `service-limit`

1. Register one server with exactly 32 enabled services and require 32 selector owners.
2. Start another server with 33 services and require `limit.services`.
3. Require the accepted server's registration/index to remain unchanged.
4. Stop both servers and require zero final counts.

```text
./tests/registry/local.sh --case service-limit
```

### `relay-limit`

1. Raise only the local harness's auth per-IP capacity, then start 32 authorized servers;
   each must own exactly one reservation.
2. Start a second server process with the first PeerId and require its N+1 reservation to
   be denied without additional reservation state.
3. Use one authorized client PeerId to pace 33 circuit requests across the 32 servers.
4. Require exactly 32 active circuits and verify the 33rd never allocates state.
5. Close all actors and require reservation/circuit/session/registry counts to be zero.

```text
./tests/registry/local.sh --case relay-limit
```

### `graceful-drain`

1. Reach registered readiness with work active.
2. Send SIGINT to server; require readiness false, correlated Withdraw, and one shutdown
   terminal.
3. Send SIGINT to exchange; require its bounded drain and one shutdown terminal.
4. Require sessions, relay admissions, reservations, circuits, registrations, selectors,
   auth requests, and registry requests all to be zero.

```text
./tests/registry/local.sh --case graceful-drain
```

### `all`

Run every case above sequentially under one run ID. The command stops at the first failed
assertion and exits nonzero; it succeeds only after every case writes a passing summary.

```text
./tests/registry/local.sh --case all
```

## Evidence inspection

```text
latest=$(ls -1dt target/p2x-registry/* | head -1)
find "$latest" -name summary.json -print -exec sed -n '1p' {} \;
```

Each summary contains `observed_assertions` and `final_resources`. Lifecycle privacy scans
fail on the generated tokens, token digests, session fields, raw selector values, and
upstream IDs.

## Source-level and repository gates

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
cargo tree -e features
```

Focused registry checks are useful while diagnosing a failure:

```text
cargo test -p p2x-exchange registry::tests
cargo test -p p2x-exchange registry_admission::tests
cargo test -p p2x-net relay_admission::tests
cargo test -p p2x-net registry_codec::tests
cargo test -p p2x-server availability::tests
```

## Fuzz test

```text
cargo +nightly fuzz run registry_frame_decode -- -max_total_time=30
```

Pass only when there is no panic, sanitizer report, timeout artifact, excessive allocation,
or accepted malformed/non-canonical frame.

## Required regressions

```text
./tests/auth/local.sh --case all
./tests/connectivity/local.sh --case all
./tests/platform-security/local.sh
```

Linux namespace and separate-host C14 procedures remain in
`tests/connectivity/manual-gates.sh` and `tests/connectivity/two-host.md`.

## Container test runtime

```text
docker build -f Dockerfile.test -t p2x-tests .
mkdir -p target/container-tests
docker run --rm -v "$PWD/target/container-tests:/workspace/target/container-tests" \
  p2x-tests ./tests/container/run.sh --suite all
```

The image is test-only and already contains all test runners. No application image is
needed for these local live cases.

## Deferred final-stage deployment validation

The user-directed final deployment stage owns checks that require a deployed topology or
long observation window: native macOS/Linux evidence capture, privileged namespaces,
two-host C14, packet capture, 32-server x 32-service deployment headroom, 10,000-operation
deployment churn, and the multi-hour restart/renewal soak. These are not reported as passed
by the local live suite.
