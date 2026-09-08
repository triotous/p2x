# Domain ingress adapters

The client supports additive loopback listeners for exact HTTP Host and TLS SNI routing. Existing `raw_tcp` listeners remain unchanged and share the same ingress connection budget.

```yaml
ingress:
  http:
    - name: orders-http
      bind: 127.0.0.1:8080
  tls_sni:
    - name: secure-tls
      bind: 127.0.0.1:8443
domain_routes:
  - listener: orders-http
    domain: orders.example.test
    route_id: orders
  - listener: secure-tls
    domain: secure.example.test
    route_id: secure
limits:
  max_ingress_connections: 512
  copy_buffer_bytes: 32768
  ingress_parse_timeout_ms: 5000
  max_http_header_bytes: 16384
  max_tls_client_hello_bytes: 65536
```

Listener binds must be unique loopback IP-literal addresses with nonzero ports. HTTP listeners can reference only `protocol: http` targets; TLS listeners can reference only `tls_passthrough` targets. Routes are immutable and exact: there is no wildcard, suffix, default, DNS, or exchange lookup. Domains are canonicalized case-insensitively; configuration may use Unicode, while HTTP Host and TLS SNI use ASCII DNS names. HTTP accepts an optional port for authority locking, but the port does not alter the selected route or server upstream.

## HTTP behavior

The adapter accepts a bounded HTTP/1.1 subset: origin-form requests and `OPTIONS *`, one valid Host field, strict framing, fixed-length or chunked bodies, persistent same-authority requests, and bounded trailers. CONNECT, absolute-form URLs, HTTP/1.0, ambiguous framing, unsupported upgrades, malformed requests, and changed authority are rejected or closed. Application bytes are forwarded unchanged after the first request selects an exact route.

Response framing is tracked alongside a bounded queue of request metadata. Informational and final responses, HEAD/204/304, fixed and chunked bodies, close-delimited responses, and `Connection: close` preserve request boundaries. A valid WebSocket request holds early data until its associated `101` response is complete; a declined upgrade returns to HTTP validation. Partial later heads, chunk lines, and trailers use one absolute parse timeout, and a five-second upgrade decision timeout prevents a held transition from remaining active indefinitely.

## TLS behavior

The adapter incrementally inspects the bounded first ClientHello, requires a structurally valid visible SNI, and then forwards the retained TLS bytes opaquely. It does not terminate TLS, inspect later application names, or decrypt ECH. Certificates belong to the TLS endpoint/upstream and must cover the name used by the caller. A visible outer SNI must have an exact configured route.

Example manual checks (owner supplies a test CA and DNS/hosts mapping):

```sh
curl --resolve orders.example.test:8080:127.0.0.1 http://orders.example.test:8080/
curl --resolve secure.example.test:8443:127.0.0.1 --cacert ./test-ca.pem https://secure.example.test:8443/
openssl s_client -connect 127.0.0.1:8443 -servername secure.example.test -CAfile ./test-ca.pem
```

The URL/bind port is explicit for HTTP and HTTPS. Do not add public DNS, certificates, or hosts-file entries automatically in tests.

## Bounds and diagnostics

A permit is acquired before adapter parsing. Parsing uses the absolute accept setup deadline and the configured parse timeout; a valid route is handed to the existing owner, ticket, path, and tunnel lifecycle with `HttpHost` or `TlsSni` preserved. Unknown, malformed, oversized, and timed-out prefices are rejected before resolution or upstream setup. Raw domains, SNI, request lines, headers, payloads, tickets, credentials, and upstream addresses must not be written to lifecycle output.

The verification entry point is `./tests/ingress/local.sh --case <name|all>`. Cross-host DNS, certificate distribution, platform/container, firewall, and long-running network validation remain owner-executed Phase 6 evidence; the test runner never modifies DNS, certificate stores, hosts files, or firewall rules.
