# Plan: Exact Domain Routing and HTTP Host / TLS SNI Ingress

- **Document status:** implementation-ready
- **Date:** 2026-09-07
- **Scope:** Phase 5 from [`00-product-analysis.md`](00-product-analysis.md) §24
- **Depends on:** completed Plans 01–06, including their corrective plans, accepted [`ADR 0001`](../docs/adr/0001-rust-libp2p-connectivity.md), and the tunnel baseline at `abb63a9`
- **Required outcome:** configured loopback HTTP and TLS listeners select an exact local domain route, obtain an independent ticket and tunnel through the existing connection owner, and preserve allowed application bytes; unknown, malformed, oversized, timed-out, or cross-route ingress fails locally with bounded resource release

The work-package filenames in product analysis §25 predate the implemented sequence. Plans 04–06 delivered registry, resolution, and raw TCP tunnels. Plan 07 therefore delivers §24 **Phase 5 — Domain ingress adapters**. Final observability, deployment, network-matrix certification, and resilience tuning remain Phase 6 work.

## 1. Goal and Scope

Implement:

1. an immutable exact-domain router referencing the existing `targets` and selectors;
2. bounded HTTP/1.1 Host routing with original-byte forwarding, streaming bodies, persistent connections, pipelining, and WebSocket upgrade;
3. route locking that checks every HTTP request boundary before forwarding that request;
4. bounded TLS ClientHello/SNI inspection followed by opaque TLS passthrough;
5. one ingress concurrency budget and one accept-to-Accepted setup deadline across raw TCP, HTTP, and TLS listeners;
6. protocol-appropriate local errors, correlated diagnostics, and exact ownership through parsing, resolution, setup, streaming, and shutdown;
7. executable domain-ingress tests plus DNS and certificate documentation.

Retain exactly three binaries. Do not add TLS termination, HTTP/2 termination, plaintext HTTP/2/h2c, CONNECT, arbitrary upstream destinations, header rewriting, request replay/pooling, wildcard routes, DNS configuration changes, certificate installation, dynamic reload, or active-stream migration. HTTP/2 and gRPC can pass through the TLS adapter as encrypted bytes. Server upstreams remain immutable IP-literal TCP destinations; `protocol: http` and `tls_passthrough` describe selector classes, not new server-side transport modes.

## 2. Current State and Confirmed Integration Points

### 2.1 Accepted baseline

The final append in [`Plan 06b's run log`](../rlogs/06b-raw-tcp-tunnel-phase-gate-closure__20260829T130431Z.rlog) records the corrected QUIC test driver, a passing clean workspace test/Clippy chain, and restored Plan 07 eligibility. This plan accepts that completed baseline; historical blocked statements earlier in Plans 06b and its append-only log are superseded by the final closure. Those tests were not rerun while writing this planning document.

The same log still separates Linux namespace/firewall tests, cross-host NAT tests, the platform/container matrix, and long-running 64/128-stream soak from local certification. Preserve those owner-executed items for the Phase 6 launch gate; they do not block this plan.

### 2.2 Source findings

| Existing path / symbol | Confirmed behavior and required seam |
| --- | --- |
| `apps/p2x-client/src/config.rs`, `ClientConfig::load` | Strict schema v1 has `targets`, optional `raw_tcp`, network settings, and limits. Targets already support `http`, `tls_passthrough`, and `tcp`; actual listeners currently require TCP targets. No domain table or parser limits exist. |
| `apps/p2x-client/src/ingress.rs`, `bind_all`, `spawn_all`, `run_connection` | One shared semaphore bounds raw listeners. `IngressEvent::Accepted` already contains a known route. One copy buffer holds local bytes until `StartTunnel`; `PrefixedIo` then replays them through the pump. Parsing requires an earlier, route-unknown state. |
| `apps/p2x-client/src/main.rs` | `product_ingress` depends only on nonempty `raw_tcp`. `reject_ingress` and `complete_route_actions` send a code-less `Reject`. Listener, owner, and completion handling must support all adapters. |
| `apps/p2x-client/src/ingress_owner.rs`, `IngressOwnerBook` | Setup and active ownership, reverse Open indexing, proxy tasks, and immutable Accepted correlation already exist. Extend this owner; do not create parallel maps with independent cleanup. |
| `apps/p2x-client/src/route_open.rs`, `RouteOpenSupervisor`, `make_open` | The route owner preserves the absolute deadline and retry ownership, but `make_open` hardcodes `IngressKind::FixedTcp`. |
| `crates/p2x-protocol/src/proxy.rs` | `FixedTcp`, `HttpHost`, and `TlsSni` already have committed wire discriminants `0`, `1`, and `2`. `Accepted` selects `UpstreamMode::Tcp`. No new proxy frame shape is needed. |
| `apps/p2x-server/src/config.rs`, `ticket_admission.rs` | Server configuration accepts all three selector classes and maps each to local TCP. Live ticket validation binds the service fingerprint but does not check `open.ingress_kind` against the selected service's protocol. |
| `crates/p2x-proxy/src/lib.rs` | Generic `PrefixedIo` and the bounded duplex pump already handle backpressure, half-close, cancellation, and counters without peer/ticket/config dependencies. |
| `crates/p2x-net/src/lifecycle.rs` | Ingress events currently require a route hash; no representation exists for an admitted socket still parsing an unknown domain. |
| `tests/tunnel/`, `fuzz/` | Strict process evidence and bounded protocol fuzzing exist. There are no Host, ClientHello, or domain-parser targets. |

`Cargo.lock` already resolves `httparse 1.10.1` and `idna 1.1.0` transitively. Declare these versions as direct workspace dependencies for `p2x-proxy` without upgrading libp2p; reuse the existing workspace `base64` dependency for WebSocket key syntax. Use [`httparse`](https://docs.rs/httparse/1.10.1/httparse/) for bounded request/response head parsing and [`idna::domain_to_ascii_strict`](https://docs.rs/idna/1.1.0/idna/fn.domain_to_ascii_strict.html) for domain validation. P2X still owns strict forwarding policy, incremental framing, allocation bounds, and route decisions.

## 3. Required Design

### 3.1 Compatible configuration and exact routing

Extend the current route-file schema additively. Keep existing raw TCP and target-only diagnostic files valid. New fields are optional and still use `deny_unknown_fields`:

```yaml
schema_version: 1
network:
  direct_preference_ms: 1500
  connection_setup_timeout_ms: 20000
targets:
  - route_id: orders
    selector:
      protocol: http
      metadata: {service: orders, environment: production}
  - route_id: secure
    selector:
      protocol: tls_passthrough
      metadata: {service: secure, environment: production}
ingress:
  http:
    - name: local-http
      bind: 127.0.0.1:8080
  tls_sni:
    - name: local-tls
      bind: 127.0.0.1:8443
domain_routes:
  - listener: local-http
    domain: orders.prod.p2x.local
    route_id: orders
  - listener: local-tls
    domain: secure.prod.p2x.local
    route_id: secure
limits:
  max_ingress_connections: 512
  copy_buffer_bytes: 32768
  ingress_parse_timeout_ms: 5000
  max_http_header_bytes: 16384
  max_tls_client_hello_bytes: 65536
```

The example is a route file passed through the existing `--routes-file` option; identity/exchange configuration stays on its current CLI/config path. Existing `raw_tcp` entries may coexist unchanged.

Validation and router rules:

- Listener names follow the existing 1–64 ASCII identifier rule and are unique across all three adapter lists. Binds are unique loopback IP-literal socket addresses with nonzero ports. Cap the combined listener count at 256 and domain-route count at 1,024; retain the existing 256-target cap.
- Every domain entry names one HTTP/TLS listener and one existing target. An HTTP listener requires `ProtocolClass::Http`; TLS requires `TlsPassthrough`; raw TCP retains `Tcp`. Reject unused HTTP/TLS listeners with no domain entries and references to raw listeners in `domain_routes`.
- Build an immutable `DomainRouter` in new `apps/p2x-client/src/router.rs`, keyed by `(ListenerId, CanonicalDomain)`. Values reference validated target indices and adapter kind. No runtime DNS lookup, inferred metadata, suffix matching, default route, or exchange lookup occurs on a local miss.
- Duplicate canonical domains within one listener are configuration errors even if they reference the same target. The same domain may appear on separate listeners. Different domains may deliberately reference one target, but remain distinct HTTP connection authorities.
- Validate the entire configuration before creating listeners or starting networking. Collect independent validation errors with field locations and fixed reasons; do not echo metadata, raw domains, or parser input. If binding any listener fails, drop all listeners bound by that startup attempt before exchange dialing.

Define a shared bounded `CanonicalDomain` in `crates/p2x-proxy/src/domain.rs`:

1. Configuration may use Unicode names, with a 1,024-byte input cap. Convert through the strict IDNA API; HTTP Host and SNI inputs must already be ASCII, including A-labels for internationalized names.
2. Lowercase the ASCII result, strip at most one terminal ASCII dot where the input policy allows it, and require 1–253 bytes overall and 1–63 bytes per nonempty label. Reject leading/trailing label hyphens, non-DNS punctuation, whitespace, controls, invalid A-labels, wildcards, IP literals, and empty labels. Do not trim arbitrary whitespace or decode percent escapes.
3. Configured domains contain no port. HTTP authority accepts a DNS name plus an optional decimal port in `1..=65535`, after removing field-value outer SP/HTAB only. Reject userinfo, paths, commas, brackets, multiple colons, and empty ports. Default the effective HTTP port to 80 when absent; the listener's local bind port does not replace it.
4. HTTP/config inputs may have one trailing dot in the hostname; malformed repeated dots fail. SNI rejects a trailing dot at its protocol boundary. Both feed the same canonical-domain representation after these input-specific checks.
5. HTTP locks `(canonical_domain, effective_port)` and target for the lifetime of the TCP connection. Thus case/trailing-dot variants and absent/explicit port 80 agree, while another domain alias or another effective port is a route change even when it maps to the same selector. Route lookup itself uses the domain only; a Host port never changes the server upstream.

### 3.2 Admission, timing, buffers, and ownership

Use the same bounded owner pipeline for every adapter:

```text
TCP accepted -> ingress admitted / parsing -> route selected
  -> resolve / path / Open -> Accepted -> stream -> terminal
```

- Record `started_at` immediately on successful local TCP accept. Acquire the common ingress permit before allocating a parser buffer or spawning a worker. Saturation closes the socket immediately and emits the existing `limit.proxy_streams` diagnostic; do not read an unadmitted connection merely to construct an HTTP response.
- Set `setup_deadline = started_at + connection_setup_timeout`. First-head/ClientHello parsing uses `min(setup_deadline, started_at + ingress_parse_timeout)`. Neither byte arrivals nor route selection restart these clocks. Arrival at the absolute setup deadline is failure, including an already queued late Accepted.
- Introduce `IngressEvent::Admitted` to transfer the socket, owned ingress permit, ID, listener ID, kind, and accept/deadline timestamps from the listener to the main owner. On receipt, create the command/cancellation handles, insert the setup owner, and spawn its worker in a main-loop-owned `JoinSet`. The worker emits `RouteSelected` carrying the validated target. Replace the current route-known `Accepted` event at its callers. Raw TCP follows the same transitions with immediate selection. If admission transfer fails/expires, the listener drops its still-owned socket/permit; no admitted owner has been created.
- Extend `IngressSetupOwner` to represent `Parsing` and `Opening`, with optional selected target/Open ID. Register ownership before a worker can issue `RouteSelected`; reject late/duplicate transitions by ingress ID and state. Resolution starts only after selection and current authentication checks.
- Parser rejection, EOF, read failure, timeout, shutdown, and command loss all terminate one admitted ingress. Before selection there must be no resolver, ticket, or peer-manager entry. After selection use the existing `reject_ingress` / `complete_route_actions` transaction, waiter promotion, and active handoff.
- Have each ingress worker return an `IngressOutcome` through that `JoinSet`, replacing terminal `PreAcceptClosed`/`TunnelFinished` channel sends. Extend `IngressOwnerBook` with checked task-ID ownership so normal return, panic, and abort all reach the same completion transaction; keep this lifetime record until join even after setup rejection or active removal. Poll joins during normal operation and join/abort-and-await them during bounded shutdown. Do not let completed handles accumulate until process exit or reserve all event-channel slots for future terminals. Admission/selection sends remain bounded by the original deadline and shutdown; shutdown also drains queued socket transfers and joins listener tasks.
- A complete preface followed by write-half EOF can still be valid: retain the prefix and EOF flag, finish setup, replay the prefix, and propagate half-close through the pump. EOF before a complete HTTP head/ClientHello is a parse failure. Preserve existing raw-TCP pre-Accept EOF behavior.

Use these configurable bounds; reject zero/out-of-range values at startup:

| Setting | Default | Allowed range / meaning |
| --- | --- | --- |
| `ingress_parse_timeout_ms` | 5,000 | 100–5,000 ms, further clipped by setup deadline |
| `max_http_header_bytes` (`H`) | 16 KiB | 1–64 KiB; each request/response head and each trailer block, including delimiters |
| `max_tls_client_hello_bytes` (`T`) | 64 KiB | 4–256 KiB; total retained TLS wire prefix, including record headers |

Keep parser field count at 128, chunk-size/extension line at 1,024 bytes, outstanding HTTP request metadata at 32 entries of at most 256 bytes each, and consecutive informational responses at eight per request. These are fixed implementation limits, not more configuration knobs.

The HTTP worker needs at most one `H` request buffer and one `H` response buffer, the fixed metadata queue, and the existing copy-buffer-sized lookahead (`B`). Reuse/move the initial prefix into this storage instead of retaining another copy. TLS retains one `T` wire buffer and parses it using bounded record spans/cursors, without a second whole-ClientHello allocation. Both adapters then use two pump direction buffers of size `B`. Release consumed TLS/raw prefixes; HTTP keeps its reusable head buffers while active.

Document and checked-multiply a conservative client application-buffer bound:

```text
max_ingress_connections * (3*B + max(T, 2*H + 32*256))
```

Add bounded parser bookkeeping to the measured allowance and report it separately from transport/kernel buffers. Clamp reads to remaining capacity, check declared lengths before reserving, and make incremental scanning linear in bytes rather than reparsing a growing prefix on every byte. Use the pump's existing scheduling budget as the pattern for parser polling fairness.

### 3.3 HTTP framing and connection route locking

The protocol basis is HTTP message framing, Host validation, and response association from [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html). The rules below select P2X's deliberately strict forwarding subset. The adapter parses boundaries and forwards admitted bytes unchanged; it does not serialize replacement HTTP messages or buffer whole bodies.

Add pure bounded machines in `crates/p2x-proxy/src/http.rs` and an I/O adapter in `http_io.rs`:

- `HttpRequestGate`: head, fixed-length body, chunk line, chunk data, chunk CRLF, trailers, next head, waiting-for-upgrade, opaque, and failed states.
- `HttpResponseGate`: response boundaries and compact request metadata needed for HEAD, informational/final responses, close-delimited bodies, and upgrade decisions.
- `HttpGuardedIo<T>`: wraps the prefixed local I/O, exposes futures `AsyncRead`/`AsyncWrite` to the existing pump, and owns both gates plus their bounded queue. Preserve poll wakeups across the two directions; neither direction may hold a blocking lock while awaiting the other.

Request policy:

1. Accept HTTP/1.1 only, exactly one valid Host, strict CRLF delimiters, valid field names, and no whitespace before the colon, obsolete folding, embedded controls, or ambiguous request-line whitespace. Reject duplicate Host even if values agree.
2. Accept origin-form targets and `OPTIONS *`. Reject CONNECT, absolute-form URLs, authority-form targets, HTTP/1.0, the HTTP/2 preface, and h2c/unsupported upgrades locally. This listener is a reverse-tunnel ingress, not a forward-proxy endpoint.
3. Hold every complete request head until its syntax/framing and locked authority pass. Do this for the first request and all later requests, including several delivered in one read. Never hand unvalidated lookahead to a plain `PrefixedIo` that bypasses the gate. If request B changes Host, **zero bytes of B's request head or body reach the upstream**, even when A and B arrived together.
4. Accept either one decimal Content-Length, exactly one `Transfer-Encoding: chunked`, or no body framing. Reject duplicate/list Content-Length, TE plus CL, repeated/nonfinal chunked, other transfer codings, signs, and checked-integer overflow. This stricter policy avoids rewriting ambiguous lengths.
5. Stream fixed-length and chunk data without interpreting payload. Validate chunk-size/extension syntax, per-line bounds, data CRLF, and bounded trailers before moving to another request. Reject Host, framing fields, and connection-control fields in trailers. Do not scan arbitrary body bytes for Host text. Large body length is a checked counter, not an allocation size.
6. Subsequent partial heads, chunk lines, and trailer blocks receive an absolute parse deadline starting with their first byte and never extended by trickle input. Waiting for a new request with no bytes is governed by the server's existing tunnel idle policy. Body streaming remains backpressured and uses that idle policy rather than a total body-duration cap.
7. `Expect: 100-continue` forwards the validated request head and continues reading responses while awaiting the body; P2X does not synthesize 100. Headers, path/query, cookies, authorization fields, chunk syntax, and trailers remain byte-identical on allowed traffic.

Response tracking exists only to keep the request-boundary gate correct through upgrades and persistence. Queue bounded metadata before releasing a request head upstream. At 32 outstanding requests, stop reading the next request while continuing responses; queue saturation must not block the reverse pump. Track informational responses without popping a request, HEAD/204/304 no-body responses, fixed/chunked response bodies, and close-delimited final responses. Reject ambiguous/invalid response framing; stop further requests on a close-delimited or `Connection: close` response. On an early final response before a request body is complete, abandon that remaining upload, finish forwarding the final response, and close instead of guessing the next request boundary. Request `Connection: close` similarly prevents forwarding a later pipelined request. Response-head/trailer parsing uses the same bounds; ordinary response bodies are streamed unchanged.

WebSocket policy follows the HTTP upgrade boundary in [RFC 9110 §7.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8) and the opening handshake in [RFC 6455 §4](https://www.rfc-editor.org/rfc/rfc6455.html#section-4):

- Recognize a bodyless GET offering `Upgrade: websocket` with `Connection: upgrade`. Validate the bounded handshake field syntax, version 13, and a single base64 key decoding to 16 bytes. Leave extension/subprotocol negotiation and the endpoint's cryptographic handshake validation to the actual WebSocket peers.
- Allow an upgrade after earlier same-authority requests. Hold its head until earlier responses drain, making it the only outstanding request. Stop consuming subsequent local bytes until the response decision; retain any already-read lookahead within `B`.
- Switch both gates to opaque only after a complete associated 101 response with matching WebSocket/Connection tokens. An Upgrade request alone, an unrelated informational response, or an unsolicited 101 never disables Host checking.
- A declined upgrade remains HTTP: forward the response unchanged, complete its body, and resume the request gate. Subsequent different-Host HTTP must still be rejected. Do not add an application protocol switch after h2c or an unknown upgrade.
- Bound the upgrade decision by five seconds from forwarding its request, plus normal cancellation; this is an active protocol transition, not a new resolve/setup budget. After success, release HTTP parser buffers/queue and forward opaque bytes with the existing pump and half-close semantics.

Expose a small shared diagnostic handle from `HttpGuardedIo` so `run_connection` can recover a typed guard failure after the pump returns `LocalIo`. Preserve `PumpResult` directional counters and terminal data; account explicitly for response bytes accepted into a guard buffer but not actually written to the local socket at failure. The current pump does not flush after each write: the write that completes a response head/trailer must remain pending until its validated buffered block drains to the local socket, then acknowledge only the input it consumed. Stream body writes directly, preserve partial-write state/wakeups, and flush/drain on close. Prove that a complete short response reaches the caller without another remote byte or an extra pump flush call. A route change becomes a classified ingress terminal, not an unexplained I/O error or a new resolve attempt.

### 3.4 TLS ClientHello inspection and passthrough

Add `crates/p2x-proxy/src/tls.rs` with a pure incremental `ClientHelloInspector` returning `NeedMore`, `Selected { domain, prefix_len }`, or a typed failure. Inspect the TLS wire prefix without constructing a TLS client/server or loading keys.

TLS handshake messages can span records, and SNI carries an ASCII DNS hostname. Use the record/ClientHello structures in [RFC 8446 §§4.1.2 and 5.1](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2) and the server-name encoding in [RFC 6066 §3](https://www.rfc-editor.org/rfc/rfc6066.html#section-3).

Implementation policy:

- Support TLS 1.2 and TLS 1.3 ClientHello wire layouts, including initial legacy record versions `0x0301`–`0x0303`. Validate the initial ClientHello legacy version and structural vectors; this inspector does not negotiate or certify the peer's eventual TLS version.
- Require the first handshake message to be ClientHello. Handle TCP splits at every offset, the four-byte handshake header split across records, and the ClientHello spanning multiple handshake records. Reject a non-handshake/interleaved record before completion, empty handshake records, and a plaintext record payload over 16,384 bytes.
- Bound the accumulated raw prefix by `T`, record/span count by `T/5`, and every read by remaining capacity. A declared handshake length cannot allocate beyond `T`; wire record overhead also counts toward the cap.
- Validate session-ID, cipher-suite, compression, extensions, and server-name vector bounds with checked arithmetic. Reject duplicate extension types, duplicate/empty host_name entries, truncated or contradictory nested lengths, malformed DNS/A-labels, ports, IP literals, and missing SNI. Unknown well-formed extensions and GREASE values are skipped by length.
- Finish structural inspection of the complete first ClientHello before selecting a route; finding the first SNI early is insufficient because a later duplicate or malformed extension must fail locally.
- Move all bytes already read, including record headers and any bounded read-ahead, into `PrefixedIo`. Send none before server Accepted. Replay exactly once, then discard inspector state and use opaque forwarding; do not modify SNI, ALPN, random/session fields, records, or application bytes.
- There is no no-SNI/default-route fallback in this plan. A syntactically valid unknown SNI also closes locally before resolution.

ECH encrypts the inner ClientHello and leaves an outer ClientHello for routing; it may also appear as GREASE. P2X can select only the visible outer SNI. Permit a structurally valid ECH extension when that outer name has an exact configured route, preserve it unchanged, and reject an unknown/missing outer SNI. Do not claim access to the inner name or silently infer it. This policy follows the visibility boundary described by [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html), without implementing ECH decryption.

TLS application HTTP Host/`:authority`, later TLS handshakes, and HTTP/2 connection coalescing are opaque to P2X. The initial route/ticket and upstream remain fixed; upstream TLS/application configuration must restrict which names that service serves. The plaintext HTTP cross-request gate must not be advertised as encrypted-HTTP enforcement.

### 3.5 Tunnel protocol and service binding

Thread the selected `IngressKind` through `IngressSetupOwner`, `RouteOpenSupervisor::admit`, stored `RouteOpen`, and every `make_open` call, including pre-handshake fallback and fresh-ticket retries. Never infer it from untrusted Host text after route selection. Preserve it in the active lifecycle context.

At `TicketAdmissionLedger::validate_candidate` in `apps/p2x-server/src/ticket_admission.rs`, require:

| Open ingress kind | Selected local service protocol | Upstream connection / Accepted mode |
| --- | --- | --- |
| `FixedTcp` | `Tcp` | TCP / `Tcp` |
| `HttpHost` | `Http` | TCP / `Tcp` |
| `TlsSni` | `TlsPassthrough` | TCP / `Tcp` |

Perform this consistency check with the live immutable service binding before replay consumption, stream/dial/service admission, or upstream dialing; use existing `protocol.malformed` on mismatch. Existing bounded inbound behavior/verification-worker admission still precedes ticket validation. The signed service fingerprint remains the authorization source. The server must not interpret `ingress_kind` as a client-supplied dial policy.

Update synthetic diagnostics/tests that currently combine an HTTP selector with `FixedTcp` to construct the corresponding kind explicitly. Keep committed old frame/ticket vectors unchanged and append fixed vectors for both domain kinds. `/p2x/proxy/1`, capabilities, ticket fields, response variants, and `UpstreamMode` do not change. Existing real raw-TCP peers remain compatible; no capability negotiation for TLS termination or application HTTP parsing is introduced.

### 3.6 Errors, lifecycle, and privacy

Add a typed local `IngressError` in `apps/p2x-client/src/ingress_error.rs`, wrapping existing `PublicErrorCode` for setup failures and mapping parser/router failures to fixed local strings. Domain failures never need a new exchange/proxy wire error. Extend `IngressCommand::Reject` to carry this code; keep cleanup centralized and keep main-loop I/O free of local socket writes.

| Local condition | Stable diagnostic | HTTP status before application forwarding |
| --- | --- | --- |
| Malformed authority/request/ClientHello | `route.malformed` | 400 |
| Missing HTTP Host / TLS SNI | `route.host_required` / `route.sni_required` | 400 / close |
| No exact listener/domain route | `route.not_found` | 404 |
| Changed locked HTTP authority | `route.mismatch` | close after forwarding has begun |
| Unsupported HTTP version/form/upgrade | `route.unsupported_protocol` | 400 |
| Header/ClientHello/field-count bound | `limit.ingress_preface` | 431 for HTTP head limits |
| Ingress parse deadline | `route.parse_timeout` | 408 |
| Whole setup deadline | existing `peer.setup_timeout` | 504 |
| Service/upstream connect timeout or failure | existing `upstream.connect_*` | 502 |
| Auth/ticket refusal | existing `auth.*` | 403 |
| Offline, unavailable exchange/path, drain, or capacity | corresponding existing code | 503 |
| Malformed/incompatible remote setup response | corresponding existing `protocol.*` | 502 |

Use an explicit exhaustive mapping for current public codes; ordinary unmatched setup failures default to 502. Do not send 401 with an invented HTTP authentication mechanism: enrollment is configured in P2X, so 403 is the local authorization response.

Before any application request byte has been forwarded, the HTTP worker may send one fixed response with status, `Connection: close`, explicit Content-Length, `Content-Type: text/plain`, the stable code, and an opaque local trace ID. Never reflect Host, request target, payload, credentials, internal cause, or upstream address. Bound error writes to at most 100 ms and the remaining original setup budget; at expiry use only an immediate nonblocking write attempt and close. Failure to write an error must still release the socket and permit. A saturated, unadmitted socket simply closes as specified in §3.2.

Once forwarding starts, any local parse/route violation closes the stream and records the code; do not splice a synthetic HTTP response into outstanding upstream responses or upgraded traffic. TLS/raw failures always close/reset with diagnostics only. Carry a rejection decision to the ingress worker without racing it against cancellation of resolve/proxy work: separate setup-work cancellation from the socket's bounded error-write lifetime, while process shutdown cancels both.

Add additive lifecycle records for admitted/parsing state and a terminal for **every admitted local ingress**, including successful EOF and all failures. Include ingress ID, listener fingerprint, adapter kind, optional selected route fingerprint, phase, stable code, and parse duration. Keep the existing route-selected ingress/tunnel records usable by Plan 06 tooling. No fake hash for an unknown route and no raw/unbounded domain-derived metric labels. Every Accepted tunnel still has exactly one tunnel terminal per component with frozen path/setup metadata; an HTTP guard failure adds its classified code to that terminal.

Report live/high-water/final parser owners, ingress workers, retained parser bytes, and HTTP queue entries alongside existing client resource evidence. Emit these from actual owned counts. Logs and summaries must not contain raw domains/SNI, request lines/headers, TLS prefaces, payload, selector metadata, tickets, sessions, credentials, or upstream addresses. Known configured route IDs may be fingerprinted; unknown input is represented only by the opaque ingress ID and fixed error class.

## 4. Ordered Implementation Plan

### 4.1 Phase A — Domain types and strict route configuration

Files: workspace `Cargo.toml`, `crates/p2x-proxy/Cargo.toml`, new `domain.rs`, `crates/p2x-proxy/src/lib.rs`, client `config.rs`, new client `router.rs`.

1. Declare the already-locked `idna`/`httparse` versions and expose the shared bounded domain type without peer or selector dependencies.
2. Implement the configuration/authority/SNI normalization entry points and exact listener router.
3. Add optional config sections, the three parser limits, cross-adapter listener checks, target-class checks, and checked buffer arithmetic.
4. Validate old raw/target-only files and the new mixed example through the production loader; collect independent errors before startup.

Phase gate: normalization collision/invalid-input tables and strict configuration tests pass; old configuration semantics remain unchanged and all route lookups are local deterministic values.

### 4.2 Phase B — Common ingress ownership and kind propagation

Files: client `ingress.rs`, `ingress_owner.rs`, `main.rs`, `route_open.rs`, `proxy_open.rs`; protocol `proxy.rs`; server `ticket_admission.rs`; `crates/p2x-net/src/lifecycle.rs` and affected owner/vector tests.

1. Generalize binding/product-mode detection and implement admitted/parsing/selected owner transitions with the existing raw adapter first.
2. Bound and own worker/event lifetimes, continuously reap children, and preserve centralized completion, waiter promotion, and frozen Accepted state.
3. Thread adapter kind through every open/retry path and add the live server consistency check.
4. Add route-unknown lifecycle/resource evidence and preserve existing tunnel summaries.

Phase gate: raw TCP process regressions pass; kind mismatches consume no ticket and cause no upstream connection; duplicate/late selection, full channels, EOF, abort, and shutdown drain every owner exactly once.

### 4.3 Phase C — HTTP framing gate and error delivery

Files: new shared `http.rs` and `http_io.rs`; client `ingress.rs`, `ingress_error.rs`, `main.rs`; focused shared/client tests.

1. Implement pure request/response machines, bounded queues and incremental scans, then `HttpGuardedIo` over the existing pump.
2. Connect first-head selection to the common owner and replay retained bytes exclusively through the request gate.
3. Implement repeated-request locking, body/chunk/trailer handling, response-boundary tracking, and coordinated WebSocket transition.
4. Add typed guard diagnostics, bounded pre-forward error responses, post-forward closure, and byte-accounting checks.

Phase gate: no part of an invalid/cross-authority request reaches either upstream fixture, including same-read pipelining and malformed chunk boundaries; large streaming bodies and 100-continue progress concurrently; an Upgrade header alone never disables the gate.

### 4.4 Phase D — TLS inspector and opaque handoff

Files: new shared `tls.rs`; client `ingress.rs`; TLS fixture/corpus tests.

1. Implement checked record traversal and ClientHello/SNI parsing with arbitrary fragmentation.
2. Enforce complete structural validation, first-preface deadline, exact local lookup, and no-SNI/ECH policies.
3. Move the retained wire prefix into the generic pump only after Accepted; discard the inspector after handoff.
4. Exercise real TLS 1.2/1.3 clients and local TLS upstreams using run-scoped certificates trusted explicitly by the test caller.

Phase gate: byte-identical upstream ClientHello capture and endpoint TLS certificate verification succeed over direct and relay; malformed/unknown SNI cases cause no resolve or upstream connection.

### 4.5 Phase E — Process evidence, fuzzing, regression, and documentation

Files: new `tests/ingress/{local.sh,live.py,test_live.py,README.md}` and fixtures; `fuzz/Cargo.toml`, new targets/corpora; new `docs/operations/domain-ingress.md`; existing `docs/operations/client-connections.md`, `docs/operations/raw-tcp-tunnels.md`, `docs/protocol/proxy-v1.md`, `docs/security/identity-and-credentials.md`, and `tests/README.md`.

1. Add the exact local matrix in §5. Reuse the small process/strict-JSON/privacy/resource helpers in `tests/tunnel/live.py` where practical; if extraction is needed, preserve the existing case names and assertions and test both runners. Do not copy its entire runner or turn the lab into a new framework.
2. Add `p2x-proxy` to the separate fuzz workspace dependencies and bounded domain/HTTP/TLS fuzz targets with checked-in valid, malformed, fragmented, oversized, and cross-route seeds; include stateful bidirectional HTTP scripts and arbitrary input chunk boundaries. Keep router policy in the client and parser APIs independently fuzzable in the shared crate.
3. Document the implemented schema, supported HTTP subset, parser limits, mixed-listener budget, statuses, ECH visibility, fixed-route semantics, upstream virtual-host responsibility, and certificate ownership.
4. Provide manual local examples using `curl --resolve` for HTTP/HTTPS with an explicit test CA, and `openssl s_client -servername` with caller-side verification. Local DNS or an owner-managed hosts entry must point domains at the client machine; do not automate either. Explain that HTTP bind ports belong in URLs and that TLS certificates must cover the caller's name.
5. Run §5 gates, inspect the final diff against each invariant, and create an append-only `rlogs/07-domain-ingress-adapters__<timestamp>.rlog` recording commands, exit statuses, versions, evidence paths, and the separately incomplete owner matrix. Do not rewrite prior plans/logs as completed evidence for new adapters.

Phase gate: strict assertion-derived domain-ingress summaries pass on the implementation revision; operations examples match the actual loader and executable behavior.

## 5. Locally Executable Verification

### 5.1 Deterministic parser, adapter, and owner tests

Use table-driven tests and controlled I/O/time, with these required observations:

| Area | Required cases and pass conditions |
| --- | --- |
| Domain/config | ASCII case/dot/port equivalence; Unicode config and valid A-label equivalence; invalid A-label/IP/port/label/length/wildcard/whitespace; canonical collisions; cross-listener isolation; unknown fields; target-class mismatch; bind rollback; old config accepted. |
| HTTP heads | Every split offset, byte-at-a-time input, head+body+next-head in one read, 128/129 fields, byte limit exactly/plus-one, duplicate/missing Host, invalid syntax/TE/CL, CONNECT/absolute-form/h2c/version rejection. |
| HTTP bodies/locking | Fixed-length and chunked bodies containing fake Host/request text; chunk extensions/trailers; integer overflow/truncation; equal canonical authority succeeds; domain alias or port switch fails; second/third pipelined request is gated before its first byte is released. |
| Duplex HTTP | 100/103 then final; HEAD/204/304; close-delimited response; early rejection during upload; queue at 32/33 with reverse progress; same-host reuse; fragmented response bounds; `Connection: close`; successful WebSocket after prior requests; declined/unsolicited/malformed 101; client bytes held until valid upgrade response; opaque post-upgrade bytes. |
| TLS | TLS 1.2/1.3 seeds, all TCP/record split offsets, record/handshake headers split, length overflow, duplicate SNI/extensions, absent/empty SNI, non-handshake/interleaved/oversized records, unknown/GREASE/ECH extension, outer-route miss, malformed suffix after a valid SNI, original-prefix replay including lookahead. |
| Time/ownership | Trickle input cannot reset parse time; parsing consumes original setup time; no-byte next-request idle differs from partial-head timeout; complete-prefix half-close; command/event saturation; cancellation during parse/open/upgrade; listener/worker abort; exactly one terminal and no residual parser/route/manager/task/queue state. |

Exercise the actual router, gates, ingress worker, and owner transitions rather than duplicating their logic in test-only pipelines. Parser tests must prove bounded output release, not just the final parse enum. Fuzz split schedules must produce the same decision and released bytes as contiguous input, never panic or exceed configured storage.

### 5.2 Real-process local matrix

Create `./tests/ingress/local.sh --case <name|all>`. Each named family below must expand to explicit independently asserted cases. Use unique run directories under `target/p2x-ingress/`, two distinguishable upstream fixtures for route isolation, run-random domains/metadata/payload markers, and the existing authenticated exchange/server/client setup.

| Case family | Required live evidence |
| --- | --- |
| `http-direct`, `http-relay` | Exact target selected; request/response bytes preserved; actual selected path, successful response, one ticket and one upstream connection per ingress. |
| `http-keepalive`, `http-pipeline-route-lock` | Same-authority reuse works; domain/alias/port change is closed; changed request bytes reach neither upstream; no second resolve/ticket/open is issued. Test both paths. |
| `http-streaming` | Large fixed/chunked upload and download, a slow reader beside a fast peer, trailers, and 100-continue. Bodies exceed all parser caps without body-sized allocation. Test both paths. |
| `http-websocket` | Actual upgrade and bidirectional WebSocket payload, upgrade after ordinary requests, same-read early data retention, declined upgrade followed by cross-Host HTTP, and unsupported h2c. Test both paths. |
| `http-local-rejections`, `http-error-mapping` | Initial malformed/missing/unknown/oversized/unsupported input has no resolution or upstream dial; authenticated setup failures return exact status/code and close; no fabricated 401 challenge. |
| `tls-direct`, `tls-relay` | Real certificate-verified TLS 1.2/1.3 round trips; SNI chooses the intended TLS upstream; captured client/server wire prefixes match exactly. |
| `tls-fragmentation`, `tls-local-rejections` | Multi-record/split ClientHello works; wrong/missing/malformed/oversized SNI does not resolve/dial; ECH/GREASE fixture preserves bytes and uses only explicit visible outer routes. |
| `parse-deadlines`, `setup-budget` | HTTP/TLS slowloris closes within its original parse budget; parse plus held setup cannot exceed the original Accepted deadline; later partial HTTP heads also time out; later valid ingress recovers. |
| `mixed-limits`, `shutdown-parsing`, `shutdown-active` | One shared N/N+1 limit across raw/HTTP/TLS listeners; cancellation at parsing/open/active/upgrade stages; recovery and final zero owners, workers, buffers, queues, and existing resource counters. |
| `mixed-concurrency/64`, `mixed-concurrency/128` | Simultaneously sustained streams from all adapters, with actual 64/128 Accepted high-water evidence, a slow HTTP/parser stream beside fast raw/TLS traffic, and before/peak/after RSS/FD plus application-buffer accounting. |

Observe zero *ingress-triggered* resolve/ticket/open deltas for local rejection, not the absence of unrelated authentication/registration traffic. Use explicit barriers and correlated owner events instead of sleeps to infer high-water counts. Synthetic ClientHello capture cases supplement real TLS handshake cases; a fake TLS prefix echoed by a TCP fixture is not proof of TLS compatibility. Add a local ALPN `h2` agreement/opaque-data check without claiming application HTTP/2 termination or gRPC conformance.

Every admitted ingress needs exactly one local terminal. Every Accepted stream needs the inherited client/server terminal correlation, unchanged selected path/setup time, checked directional counters, and zero final logical resources. During errors, distinguish bytes successfully forwarded from bytes inspected or retained and dropped. Each process needs one terminal and verified cleanup. Privacy scans must detect deliberately injected copies of exact run-random sensitive values; packet fixtures containing expected test bytes live only in the run's private temporary area and are removed on cleanup. Summaries contain fingerprints/counts and booleans derived only from executed named assertions. Missing cases, fields, rows, or environmental prerequisites fail or report incomplete; none imply success.

### 5.3 Required local commands

After focused phase tests pass, run:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
cargo tree -e features
python3 -B -m unittest discover -s tests/ingress -p 'test_*.py'
python3 -B -m unittest tests/tunnel/test_live.py
./tests/ingress/local.sh --case all
./tests/tunnel/local.sh --case all
./tests/resolution/local.sh --case all
./tests/auth/local.sh --case all
./tests/registry/local.sh --case all
./tests/connectivity/local.sh --case all
git diff --check
```

Run the new ingress suite three consecutive times on one unchanged implementation revision. Record failures and restart that count after a correction; do not substitute an isolated rerun for the full gate. Run bounded fuzzing for new `domain_authority`, `http_ingress`, and `tls_client_hello` targets and the changed `proxy_frame_decode` target, using the installed nightly/cargo-fuzz workflow, at least 60 seconds per new target with a documented memory/max-input bound. Give stateful HTTP fuzzing a bounded script size exceeding the maximum head plus a second request and both-direction upgrade events. Keep deliberately added regression seeds; do not commit random fuzz execution debris.

For this planning-only change, validate document paths, numbering, and whitespace. Implementation tests above are future phase gates and must not be reported as already passed.

## 6. Final Phase — Owner-Executed Environment Validation

After all local implementation phases and §5 pass, provide the owner a runbook to repeat HTTP/TLS routing, certificate verification, streaming, and rejection checks in direct-capable and forced-relay two-host environments, native Linux/macOS, and the required container topology. Use the established network-matrix scripts and keep environment-specific DNS/firewall/certificate changes explicit and owner-executed.

Carry forward the Plan 06 §5.5 namespace/firewall, cross-host, platform/container, and long-running loss/reconnect/churn/RSS/FD soak requirements. Add domain-adapter coverage to those runs; local loopback evidence must not relabel them passed. An unavailable environment remains incomplete and visible for Phase 6 launch certification, while locally completed Plan 07 may hand off to Phase 6 planning.

## 7. Definition of Done

- Strict mixed-adapter configuration and canonical exact routing execute through the production loader; old raw-TCP configurations still work.
- Every socket is bounded before parsing, the original setup deadline includes parsing, and unknown/malformed first-preface traffic creates no resolve, ticket, or upstream connection.
- HTTP keeps original admitted bytes, validates every request boundary, blocks cross-authority bytes, streams bodies, and enters opaque WebSocket mode only at a verified associated upgrade boundary.
- TLS fragmented ClientHello/SNI parsing is bounded and complete before selection; original bytes and certificate verification work end-to-end; visible-SNI/ECH limitations are documented accurately.
- The adapter kind survives retries and is checked against the ticket-bound local service before consume/dial; old protocol vectors and raw TCP behavior remain compatible.
- Errors are appropriate to the adapter and forwarding phase; one ingress/tunnel terminal and exact resource release hold across success, failures, overload, cancellation, panic, and shutdown.
- Deterministic, process, fuzz, regression, and privacy gates pass with assertion-derived evidence; DNS/certificate instructions and the execution log match the implemented product.
- External owner-executed evidence remains separately tracked, and no Phase 6 launch claim is inferred from completion of this local feature phase.

Suggested implementation commits follow Phases A–E, separating the HTTP framing core from WebSocket integration if needed. This plan itself adds documentation only.
