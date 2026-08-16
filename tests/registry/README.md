# Registry verification

Run `./tests/registry/local.sh --case <name>` from the repository root. Cases include `valid-tcp`, `valid-quic`, `multi-service`, `selector-conflict`, `cross-tenant`, `register-without-reservation`, `unauthorized-reservation`, `lease-expiry`, `graceful-withdraw`, `reservation-renewal`, `revocation-restart`, `exchange-restart`, `registry-limit`, and `service-limit`.

The harness creates a run-scoped artifact directory under `target/`, records observed lifecycle events, and never treats an expected label as a pass. Environment-dependent network cases return status 2 when binaries, credentials, or owner-executed connectivity prerequisites are unavailable.
