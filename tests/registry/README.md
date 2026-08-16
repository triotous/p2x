# Registry, relay admission, and server availability verification

Run every command from the repository root. Generated evidence is written below
`target/p2x-registry/<run-id>/`; it may contain network metadata and must not be
committed without review.

## 1. Prerequisites

- Rust and the repository-pinned toolchain are installed.
- TCP and UDP loopback listeners are permitted.
- `python3` is available (the live harness uses it to inspect NDJSON).
- No reusable credentials or identities are supplied: the harness creates and
  removes run-scoped secrets itself.

Start with the repository-wide gate:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
cargo tree -e features
```

Pass criteria: every command exits with status 0. `cargo deny check` may print
the repository's acknowledged duplicate-dependency warnings, but it must not
report a denied advisory, license, source, or ban.

## 2. Product-process registry cases

The only currently executable case names are `valid-tcp`, `valid-quic`,
`exchange-restart`, and `all`. Run one case with:

```text
./tests/registry/local.sh --case <name>
```

The harness performs the common steps below for every concrete case:

1. Build the real `p2x-exchange`, `p2x-server`, and `p2x-client` binaries.
2. Create isolated exchange/server/client identities, a ticket key, two fixed
   token credentials, a one-service YAML file, and free TCP/UDP ports.
3. Start exchange and wait for its `listener_ready` lifecycle event.
4. Start server, authenticate it, acquire the authorized relay reservation,
   register its service set, and wait for `server_readiness` with `ready=true`.
5. Start an authenticated product client against the server circuit address and
   require a terminal `relay.ping` event. This is libp2p Ping over Circuit Relay
   v2, not the connectivity spike protocol.
6. Keep the server alive until a second `ready=true` observation proves that a
   registration refresh completed.
7. Send SIGINT to server and require terminal code `shutdown`; then stop exchange.
8. Scan lifecycle artifacts for tokens, token digests, session IDs, raw selector
   metadata, and private service values. Any match fails the case.
9. Write `summary.json` only after all observed assertions pass and clean up all
   processes and temporary secret files.

### 2.1 `valid-tcp`

```text
./tests/registry/local.sh --case valid-tcp
```

This runs the common flow through the exchange TCP address. It passes when the
printed JSON has `"passed":true`, all assertions except restart recovery are
true, and the command exits 0. Restart recovery is false because this case does
not restart exchange.

### 2.2 `valid-quic`

```text
./tests/registry/local.sh --case valid-quic
```

This repeats the common flow through the exchange QUIC-v1/UDP address. Use the
same pass criteria as `valid-tcp`; a TCP fallback is not accepted because the
configured exchange address is QUIC.

### 2.3 `exchange-restart`

```text
./tests/registry/local.sh --case exchange-restart
```

After the first successful relay Ping and registration refresh, the harness:

1. Records the original server PID and PeerId.
2. Stops exchange and requires server readiness to become false.
3. Starts a fresh exchange process with the same exchange identity and address.
4. Leaves the original server process running while it reauthenticates,
   reacquires a relay reservation, and full-registers its services.
5. Requires `ready=true` at generation 2 or later within 60 seconds.

It passes only if `same_process_exchange_restart_recovery` is true and the PID
and PeerId in `summary.json` belong to that original server process.

### 2.4 `all`

```text
./tests/registry/local.sh --case all
```

This runs `valid-tcp`, `valid-quic`, and `exchange-restart` sequentially with one
run ID. It passes only if all three summaries are printed and the command exits
0. `all` does not imply any of the missing live cases in section 6.

### 2.5 Inspecting evidence

Locate the newest run and review all summaries:

```text
ls -1dt target/p2x-registry/* | head -1
find target/p2x-registry/<run-id> -name summary.json -print -exec sed -n '1p' {} \;
```

Each case directory contains `exchange.ndjson`, `server.ndjson`,
`client.ndjson`, and `summary.json`; the restart case also contains
`exchange-restart.ndjson`. A missing summary, nonzero exit, timeout, leaked
private marker, or process left running is a failure.

## 3. Focused behavior tests

These tests verify edge cases that do not yet have a three-process case:

```text
cargo test -p p2x-exchange registry::tests
cargo test -p p2x-exchange registry_admission::tests
cargo test -p p2x-net relay_admission::tests
cargo test -p p2x-net registry_codec::tests
cargo test -p p2x-net auth_state::tests
cargo test -p p2x-net reservation::tests
cargo test -p p2x-server availability::tests
```

They cover atomic replacement and selector conflict, tenant-scoped lookup,
expiry and stale revision behavior, idempotency/revision failure, request
admission bounds, authorization-before-allocation, relay limit translation,
codec canonicalization, auth renewal races, reservation recovery, and readiness
generation/drain transitions. Every command must exit 0; these are source-level
state and integration tests, not substitutes for the missing live cases.

## 4. Registry fuzz check

Install the runner and nightly toolchain once:

```text
cargo install cargo-fuzz
rustup toolchain install nightly --profile minimal
```

Run the committed valid and malformed registry corpus for a bounded smoke test:

```text
cargo +nightly fuzz run registry_frame_decode -- -max_total_time=30
```

Pass criteria: no panic, sanitizer report, timeout artifact, excessive
allocation, or accepted malformed/non-canonical frame. Inspect
`fuzz/artifacts/registry_frame_decode/`; any new reproducer is a failure until it
is understood and fixed. Do not commit incidental corpus growth.

## 5. Required regressions

Run the complete authentication regression:

```text
./tests/auth/local.sh --case all
```

Then run native connectivity:

```text
./tests/connectivity/local.sh
```

On a disposable Linux host with root or `CAP_NET_ADMIN`, run the namespace
matrix and confirm no run-scoped namespace remains afterward:

```text
sudo ./tests/connectivity/manual-gates.sh --linux
ip netns list
```

For the separate-network C14 relay test, follow
[`../connectivity/two-host.md`](../connectivity/two-host.md) exactly and validate
the merged artifact directory:

```text
./tests/connectivity/manual-gates.sh --c14-validate <artifact-directory>
```

These connectivity cases protect the shared libp2p relay/transport behavior;
C14 currently exercises the connectivity lab, not the product registry flow.

## 6. Live-case coverage still missing

The following Plan 04 product-process cases do not have an executable case name
yet. They cannot be truthfully signed off by passing `--case all` or by manually
editing NDJSON. Add a harness case that creates the stated actors/fault, derives
the result from lifecycle events and final resource counts, and writes a
machine-readable summary before recording them as passed.

| Required live case | Test procedure and pass criteria |
| --- | --- |
| Multi-service atomic registration | Start one authorized server with at least two services; require one revision/hash containing the full set, refresh the same revision, then withdraw. Reject any partial registered state. |
| Selector conflict | Start two authorized servers in the same tenant with the same complete selector; require exactly one stable owner and one `registry.conflict`, with the rejected server contributing no selector/index state. |
| Cross-tenant isolation | Start two authorized servers in different tenants with identical unscoped selectors; require both registrations to succeed and each tenant-scoped exact lookup to return only its own owner. |
| Register without reservation | Authenticate a server but prevent/remove its relay reservation before Register; require `registry.reservation_required` and zero registration/index state. |
| Unauthorized relay/registry | Try unauthenticated, client-role, server-without-`reserve_relay`, and server-without-`register_services` peers; require denial before allocation and zero relay/registry state for each attempt. |
| Lease expiry | Register with the minimum lease, suppress Refresh past the exact deadline, and require readiness false plus removal of registration and selector ownership; a late Refresh must not resurrect it. |
| Reservation loss/final disconnect | Close the active reservation or final exchange connection while registered; require readiness false and idempotent removal of relay admission, registration, and selector index. |
| Revocation and restart | Revoke the live server credential by replacing exchange authorization state, require cleanup/connection close, then restart with an allowed credential and require a fresh auth/reservation/registration generation. |
| Idempotent response replay | Drop a successful Register response, replay the byte-identical request ID/body, and require the same revision with exactly one registry mutation. Reuse with a changed body/session must be malformed. |
| Registry request boundary | Hold/admit exactly the configured global and per-peer request limit, require the next request to return `limit.registry_requests`, then release each permit once and return counts to zero. |
| Service boundary | Register exactly the effective service limit successfully; try limit + 1 and require `limit.services` with the previous registration/index unchanged. |
| Relay boundary | Admit exactly one reservation per server and 32 circuits per client; require N + 1 to fail without extra state, close all resources, and require counts to return to zero. |
| Graceful drain | SIGINT server and exchange while work is active; require readiness false, bounded Withdraw/response drain, terminal shutdown events, and zero sessions, admissions, registrations, selectors, reservations, circuits, requests, timers, and tasks. |
| Scale/churn/soak | Exercise 16 servers x 16 services, then 32 x 32 validation headroom, plus at least 10,000 replace/refresh/expire/withdraw operations and a multi-hour or CI-bounded restart/renewal soak; require invariant checks throughout and all final counts at baseline. |

Until these cases are added, record their status as **not yet live-verified** even
when the corresponding focused Rust test passes.

## 7. Owner-executed environment checks

### 7.1 Native macOS and Linux

On each native platform, record OS/kernel, Rust versions, Git commit, UTC time,
and working-tree status. Run sections 1 and 2.4. Preserve the three summaries
and confirm the native flow reaches auth -> reservation -> registration ->
refresh -> relay Ping -> graceful shutdown, plus same-process restart recovery.

### 7.2 Packet and privacy inspection

1. Start Wireshark or `tcpdump` on `lo0` (macOS) or `lo` (Linux).
2. Run `./tests/registry/local.sh --case all`.
3. Stop capture only after all processes exit.
4. Inspect the capture and artifacts for `p2x1.`, token/digest values,
   `session_id`, raw selectors/metadata, private upstream targets, ticket/private
   key material, and relay payload plaintext.
5. Pass only if none appears. PeerIds, addresses, protocol negotiation, packet
   sizes, and encrypted transport bytes are expected.

Keep raw PCAPs outside Git unless explicitly scrubbed and approved.

### 7.3 Container runtime

`Dockerfile.test` is the test-only image. It contains the pinned stable compiler,
nightly fuzz compiler, `cargo-deny`, `cargo-fuzz`, Linux networking tools, the
repository source, prebuilt test targets, and every test runner. It is not an
application or production image.

Build it from the repository root:

```text
docker build -f Dockerfile.test -t p2x-tests .
```

Run every non-privileged automated suite and retain artifacts on the host:

```text
mkdir -p target/container-tests
docker run --rm --init \
  -v "$PWD/target/container-tests:/artifacts" \
  p2x-tests
```

The default `all` suite runs format, Clippy, workspace tests, dependency policy,
dependency tree, all registry/auth/native-connectivity live cases, the platform
identity check, and all five fuzz targets. Set the per-target fuzz duration when
needed:

```text
docker run --rm --init \
  -e P2X_FUZZ_SECONDS=30 \
  -v "$PWD/target/container-tests:/artifacts" \
  p2x-tests all
```

Individual suites are `static`, `live`, and `fuzz`:

```text
docker run --rm --init p2x-tests static
docker run --rm --init -v "$PWD/target/container-tests:/artifacts" p2x-tests live
docker run --rm --init -e P2X_FUZZ_SECONDS=30 p2x-tests fuzz
```

The Linux namespace C02-C13 matrix requires root plus `CAP_NET_ADMIN` and is
therefore intentionally separate from default `all`:

```text
docker run --rm --init --privileged \
  -v "$PWD/target/container-tests-linux:/artifacts" \
  p2x-tests linux
```

Prefer a disposable native Linux Docker host for that command. VM-backed macOS
runtimes may not expose every namespace, firewall, traffic-control, or direct
connectivity feature even with `--privileged`; an unavailable kernel feature is
incomplete verification, not a pass.

Packet capture and C14 still require external operator interaction or separate
physical networks and cannot be included in an unattended image run. The three
application images remain deferred to the production packaging task.

### 7.4 Two-host product registry

The existing C14 scripts do not configure product credentials/services and
therefore do not prove Plan 04. A future product two-host runner must place
exchange on host A, server on host B, and an authenticated client on a separate
network; use the same commit/run ID, open exchange TCP/UDP ports, complete the
TCP and QUIC flows, collect all lifecycle logs/environment metadata, validate
restart recovery, and scrub reusable identities, tokens, and public-network
details before retaining evidence.

## 8. Completion record

For every executed command or environment check, record the Git commit, host or
container runtime, OS/kernel, UTC time, exact command, exit status, and relevant
`summary.json`/PCAP path. Keep unsupported live cases explicitly marked
`not yet live-verified`; an unavailable environment or missing runner is
incomplete verification, not a pass.
