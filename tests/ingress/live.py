from __future__ import annotations

import importlib.util
import concurrent.futures
import json
import pathlib
import socket
import ssl
import subprocess
import sys
import threading
import time


SPEC = importlib.util.spec_from_file_location(
    "tunnel_live", pathlib.Path(__file__).parents[1] / "tunnel" / "live.py"
)
assert SPEC is not None and SPEC.loader is not None
tunnel = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tunnel)


class HttpFixture:
    def __init__(self, port: int, marker: bytes):
        self.port = port
        self.marker = marker
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.requests: list[bytes] = []
        self.accepted_connections = 0
        self.listener: socket.socket | None = None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(3):
            raise tunnel.Failure("HTTP fixture did not become ready")

    def run(self) -> None:
        with socket.socket() as listener:
            self.listener = listener
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", self.port))
            listener.listen()
            listener.settimeout(0.2)
            self.ready.set()
            while not self.stop.is_set():
                try:
                    client, _ = listener.accept()
                except (socket.timeout, OSError):
                    continue
                self.accepted_connections += 1
                threading.Thread(target=self.handle, args=(client,), daemon=True).start()

    def handle(self, client: socket.socket) -> None:
        buffered = bytearray()
        with client:
            client.settimeout(10)
            while not self.stop.is_set():
                while b"\r\n\r\n" not in buffered:
                    chunk = client.recv(65536)
                    if not chunk:
                        return
                    buffered.extend(chunk)
                end = buffered.index(b"\r\n\r\n") + 4
                head = bytes(buffered[:end])
                length = 0
                chunked = False
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1].strip())
                    if line.lower() == b"transfer-encoding: chunked":
                        chunked = True
                if b"Expect: 100-continue" in head:
                    client.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                if chunked:
                    while b"\r\n0\r\n" not in buffered and b"\r\n0\r\n\r\n" not in buffered:
                        chunk = client.recv(65536)
                        if not chunk:
                            return
                        buffered.extend(chunk)
                    trailer_end = buffered.find(b"\r\n\r\n", end)
                    message_end = trailer_end + 4 if trailer_end >= 0 else len(buffered)
                    request = bytes(buffered[:message_end])
                    del buffered[:message_end]
                else:
                    while len(buffered) < end + length:
                        chunk = client.recv(65536)
                        if not chunk:
                            return
                        buffered.extend(chunk)
                    request = bytes(buffered[: end + length])
                    del buffered[: end + length]
                self.requests.append(request)
                if b"Upgrade: websocket" in head:
                    client.sendall(
                        b"HTTP/1.1 101 Switching Protocols\r\n"
                        b"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                    )
                    if buffered:
                        client.sendall(buffered)
                        buffered.clear()
                    while True:
                        data = client.recv(65536)
                        if not data:
                            return
                        client.sendall(data)
                body = (b"d" * (1024 * 1024)) if b" /large " in head else self.marker + b":" + str(len(request)).encode()
                client.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: "
                    + str(len(body)).encode()
                    + b"\r\n\r\n"
                    + body
                )

    def close(self) -> None:
        self.stop.set()
        if self.listener is not None:
            self.listener.close()
        self.thread.join(timeout=3)


class TlsFixture(HttpFixture):
    def __init__(self, port: int, marker: bytes, cert: pathlib.Path, key: pathlib.Path):
        super().__init__(port, marker)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)

    def handle(self, client: socket.socket) -> None:
        try:
            with self.context.wrap_socket(client, server_side=True) as secured:
                while data := secured.recv(65536):
                    self.requests.append(data)
                    secured.sendall(self.marker + b":" + data)
        except (OSError, ssl.SSLError):
            client.close()


class Run(tunnel.Run):
    def start_exchange(self, name: str = "exchange") -> pathlib.Path:
        base = f"/ip4/127.0.0.1/tcp/{self.exchange_tcp}"
        advertised = base + f"/p2p/{self.exchange_peer}"
        args = [
            str(self.root / "target/debug/p2x-exchange"),
            "--identity-file", str(self.secret / "exchange.key"),
            "--credential-file", str(self.credentials),
            "--ticket-key-file", str(self.ticket_key),
            "--tcp-listen", base,
            "--quic-listen", f"/ip4/127.0.0.1/udp/{self.exchange_quic}/quic-v1",
            "--advertise", advertised,
            "--case-id", self.case,
            "--test-private-markers-file", str(self.test_private_markers),
        ]
        if self.case.startswith("mixed-concurrency/"):
            args += [
                "--resolve-limit-global", "256",
                "--resolve-limit-per-client", "128",
                "--resolve-limit-per-minute", "256",
            ]
        return self.start(name, args, {"P2X_ENABLE_TEST_HOOKS": "1"})

    def write_configs(self) -> None:
        concurrency_cap = 256 if self.case.startswith("mixed-concurrency/") else 128
        self.domain = "a" + self.route_id.removeprefix("r_") + ".example.test"
        self.domain2 = "b" + self.route_id2.removeprefix("r_") + ".example.test"
        self.upstream_port2 = tunnel.free_port(socket.SOCK_STREAM)
        self.tls_upstream_port = tunnel.free_port(socket.SOCK_STREAM)
        self.tls_upstream_port2 = tunnel.free_port(socket.SOCK_STREAM)
        self.raw_upstream_port = tunnel.free_port(socket.SOCK_STREAM)
        self.raw_local_port = tunnel.free_port(socket.SOCK_STREAM)
        self.cert = self.secret / "ingress-cert.pem"
        self.cert_key = self.secret / "ingress-cert.key"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(self.cert_key), "-out", str(self.cert), "-days", "1",
                "-subj", f"/CN={self.domain}",
                "-addext", f"subjectAltName=DNS:{self.domain},DNS:{self.domain2}",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.services = self.secret / "services.yaml"
        self.services.write_text(
            f"""schema_version: 1
registration:
  requested_lease_seconds: 30
  refresh_seconds: 10
services:
  - upstream_id: {self.upstream_id}
    selector:
      protocol: http
      metadata: {{{self.selector_key}: {self.selector_value}}}
    enabled: true
    connect: 127.0.0.1:{self.upstream_port}
    connect_timeout_ms: 3000
    idle_timeout_ms: 300000
    concurrency_limit: {concurrency_cap}
  - upstream_id: {self.upstream_id2}
    selector:
      protocol: http
      metadata: {{{self.selector_key}: {self.selector_value2}}}
    enabled: true
    connect: 127.0.0.1:{self.upstream_port2}
    connect_timeout_ms: 3000
    idle_timeout_ms: 300000
    concurrency_limit: {concurrency_cap}
  - upstream_id: tls-{self.upstream_id}
    selector:
      protocol: tls_passthrough
      metadata: {{{self.selector_key}: {self.selector_value}}}
    enabled: true
    connect: 127.0.0.1:{self.tls_upstream_port}
    connect_timeout_ms: 3000
    idle_timeout_ms: 300000
    concurrency_limit: {concurrency_cap}
  - upstream_id: tls-{self.upstream_id2}
    selector:
      protocol: tls_passthrough
      metadata: {{{self.selector_key}: {self.selector_value2}}}
    enabled: true
    connect: 127.0.0.1:{self.tls_upstream_port2}
    connect_timeout_ms: 3000
    idle_timeout_ms: 300000
    concurrency_limit: {concurrency_cap}
  - upstream_id: raw-{self.upstream_id}
    selector:
      protocol: tcp
      metadata: {{{self.selector_key}: raw-{self.selector_value}}}
    enabled: true
    connect: 127.0.0.1:{self.raw_upstream_port}
    connect_timeout_ms: 3000
    idle_timeout_ms: 300000
    concurrency_limit: {concurrency_cap}
proxy:
  max_workers: 256
  max_workers_per_client: {concurrency_cap}
  max_upstream_dials: {concurrency_cap}
  copy_buffer_bytes: 32768
  max_replay_entries: 8192
  ticket_clock_skew: 5
"""
        )
        direct = 0 if self.case.endswith("relay") else 500 if self.case == "setup-budget" else 1500
        parse_timeout = 200 if self.case == "parse-deadlines" else 5000
        setup_timeout = 2000 if self.case == "setup-budget" else 20000
        ingress_limit = 4 if self.case == "mixed-limits" else 512 if self.case.startswith("mixed-concurrency/") else 128
        self.routes = self.secret / "routes.yaml"
        self.routes.write_text(
            f"""schema_version: 1
network:
  direct_preference_ms: {direct}
  connection_setup_timeout_ms: {setup_timeout}
targets:
  - route_id: {self.route_id}
    selector:
      protocol: http
      metadata: {{{self.selector_key}: {self.selector_value}}}
  - route_id: {self.route_id2}
    selector:
      protocol: http
      metadata: {{{self.selector_key}: {self.selector_value2}}}
  - route_id: tls-{self.route_id}
    selector:
      protocol: tls_passthrough
      metadata: {{{self.selector_key}: {self.selector_value}}}
  - route_id: tls-{self.route_id2}
    selector:
      protocol: tls_passthrough
      metadata: {{{self.selector_key}: {self.selector_value2}}}
  - route_id: raw-{self.route_id}
    selector:
      protocol: tcp
      metadata: {{{self.selector_key}: raw-{self.selector_value}}}
raw_tcp:
  - name: local-raw
    bind: 127.0.0.1:{self.raw_local_port}
    route_id: raw-{self.route_id}
ingress:
  http:
    - name: local-http
      bind: 127.0.0.1:{self.local_port}
  tls_sni:
    - name: local-tls
      bind: 127.0.0.1:{self.local_port2}
domain_routes:
  - listener: local-http
    domain: {self.domain}
    route_id: {self.route_id}
  - listener: local-http
    domain: {self.domain2}
    route_id: {self.route_id2}
  - listener: local-tls
    domain: {self.domain}
    route_id: tls-{self.route_id}
  - listener: local-tls
    domain: {self.domain2}
    route_id: tls-{self.route_id2}
limits:
  max_peer_states: 64
  max_pending_setups: 256
  max_pending_per_server: 128
  max_ingress_connections: {ingress_limit}
  max_streams_per_server: 128
  copy_buffer_bytes: 32768
  ingress_parse_timeout_ms: {parse_timeout}
  max_http_header_bytes: 16384
  max_tls_client_hello_bytes: 65536
"""
        )
        self.routes2 = self.routes


def read_response(peer: socket.socket) -> tuple[bytes, bytes]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        data.extend(peer.recv(65536))
    end = data.index(b"\r\n\r\n") + 4
    head = bytes(data[:end])
    length = next(
        int(line.split(b":", 1)[1].strip())
        for line in head.split(b"\r\n")
        if line.lower().startswith(b"content-length:")
    )
    while len(data) < end + length:
        data.extend(peer.recv(65536))
    return head, bytes(data[end : end + length])


def http_exchange(port: int, request: bytes) -> tuple[bytes, bytes]:
    with socket.create_connection(("127.0.0.1", port), timeout=20) as peer:
        peer.settimeout(30)
        peer.sendall(request)
        return read_response(peer)


def tls_round_trip(
    run: Run,
    domain: str | None,
    version: ssl.TLSVersion,
    fragmented: bool = False,
    expected: bytes = b"tls-first:round-trip",
) -> None:
    context = ssl.create_default_context(cafile=str(run.cert)) if domain else ssl._create_unverified_context()
    context.minimum_version = version
    context.maximum_version = version
    with socket.create_connection(("127.0.0.1", run.local_port2), timeout=20) as raw:
        raw.settimeout(30)
        if not fragmented:
            with context.wrap_socket(raw, server_hostname=domain) as secured:
                secured.sendall(b"round-trip")
                if secured.recv(64) != expected:
                    raise tunnel.Failure("certificate-verified TLS payload was not preserved")
            return

        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        secured = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=domain)

        def flush() -> None:
            wire = outgoing.read()
            for offset in range(0, len(wire), 3):
                raw.sendall(wire[offset : offset + 3])

        while True:
            try:
                secured.do_handshake()
                flush()
                break
            except ssl.SSLWantReadError:
                flush()
                wire = raw.recv(65536)
                if not wire:
                    raise tunnel.Failure("fragmented TLS handshake closed early")
                incoming.write(wire)
        secured.write(b"round-trip")
        flush()
        while True:
            try:
                reply = secured.read(64)
                break
            except ssl.SSLWantReadError:
                incoming.write(raw.recv(65536))
        if reply != expected:
            raise tunnel.Failure("fragmented TLS payload was not preserved")


def wait_count(path: pathlib.Path, event: str, count: int, timeout: float = 45) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if sum(row.get("event") == event for row in tunnel.read_rows(path)) >= count:
            return
        time.sleep(0.05)
    raise tunnel.Failure(f"expected {count} {event} records")


def assert_ingress_privacy(run: Run, paths: list[pathlib.Path]) -> bool:
    accepted = any(
        row.get("event") == "tunnel_accepted"
        for path in paths
        for row in tunnel.read_rows(path)
    )
    if accepted:
        return tunnel.assert_privacy(run, paths)
    markers = [
        run.client_token,
        run.server_token,
        *run.private,
        run.ticket_key_marker,
        run.payload_sentinel,
        f"127.0.0.1:{run.upstream_port}",
    ]
    output = "\n".join(path.read_text(errors="replace") for path in paths)
    if leaked := tunnel.private_markers_in(output, markers):
        raise tunnel.Failure(f"privacy scan found exact run marker {leaked[0]}")
    return True


def start_product(run: Run):
    exchange_log = run.start_exchange()
    listen = tunnel.wait_for(
        exchange_log,
        lambda row: row.get("event") == "listener_ready" and "/tcp/" in row.get("address", ""),
    )
    exchange = listen["address"]
    server_log = run.start_server(exchange)
    tunnel.wait_for(server_log, lambda row: row.get("event") == "server_readiness" and row.get("ready") is True, 45)
    tunnel.wait_for(exchange_log, lambda row: row.get("event") == "registry_transition" and row.get("code") == "registry.registered", 45)
    client_log = run.start_client(exchange)
    tunnel.wait_for(client_log, lambda row: row.get("event") == "auth_readiness" and row.get("ready") is True, 45)
    return exchange_log, server_log, client_log


def run_case(root: pathlib.Path, case: str) -> dict:
    run = Run(root, case)
    first = HttpFixture(run.upstream_port, b"first")
    second = HttpFixture(run.upstream_port2, b"second")
    tls_first = TlsFixture(run.tls_upstream_port, b"tls-first", run.cert, run.cert_key)
    tls_second = TlsFixture(run.tls_upstream_port2, b"tls-second", run.cert, run.cert_key)
    raw = tunnel.Upstream(run.raw_upstream_port, "echo")
    first.start()
    second.start()
    tls_first.start()
    tls_second.start()
    raw.start()
    try:
        exchange_log, server_log, client_log = start_product(run)
        before = (first.accepted_connections, second.accepted_connections)
        if case == "tls-local-rejections":
            for payload in (b"not tls", b"\x16\x03\x03\xff\xff"):
                with socket.create_connection(("127.0.0.1", run.local_port2), timeout=20) as peer:
                    peer.sendall(payload)
                    tunnel.wait_for_eof(peer, 5)
            for domain in ("unknown.example.test", None):
                try:
                    tls_round_trip(run, domain, ssl.TLSVersion.TLSv1_2)
                    raise tunnel.Failure("missing or unknown SNI was accepted")
                except (ssl.SSLError, OSError):
                    pass
            if tls_first.accepted_connections or tls_second.accepted_connections:
                raise tunnel.Failure("rejected TLS reached an upstream")
        elif case.startswith("tls-"):
            fragmented = case == "tls-fragmentation"
            tls_round_trip(run, run.domain, ssl.TLSVersion.TLSv1_2, fragmented)
            tls_round_trip(run, run.domain, ssl.TLSVersion.TLSv1_3, fragmented)
            tls_round_trip(
                run,
                run.domain2,
                ssl.TLSVersion.TLSv1_3,
                fragmented,
                b"tls-second:round-trip",
            )
        elif case in {"http-local-rejections", "http-error-mapping"}:
            checks = [
                (b"BROKEN\r\n\r\n", b"400", b"route.malformed"),
                (b"GET / HTTP/1.1\r\n\r\n", b"400", b"route.host_required"),
                (b"GET / HTTP/1.1\r\nHost: unknown.example.test\r\n\r\n", b"404", b"route.not_found"),
                (b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n", b"400", b"route.unsupported_protocol"),
                (b"GET / HTTP/1.1\r\nHost: " + b"a" * 17000 + b"\r\n\r\n", b"431", b"limit.ingress_preface"),
            ]
            for request, status, code in checks:
                head, body = http_exchange(run.local_port, request)
                if not head.startswith(b"HTTP/1.1 " + status) or code not in body or b"WWW-Authenticate" in head:
                    raise tunnel.Failure(f"HTTP local mapping failed for {code!r}: {head!r} {body!r}")
        elif case in {"parse-deadlines", "setup-budget"}:
            with socket.create_connection(("127.0.0.1", run.local_port), timeout=20) as peer:
                peer.settimeout(5)
                started = time.monotonic()
                peer.sendall(b"GET / HTTP/1.1\r\nHost:")
                tunnel.wait_for_eof(peer, 3)
                ceiling = 3 if case == "setup-budget" else 1
                if time.monotonic() - started > ceiling:
                    raise tunnel.Failure("partial HTTP head exceeded its original deadline")
            request = f"GET /recover HTTP/1.1\r\nHost: {run.domain}\r\n\r\n".encode()
            if not http_exchange(run.local_port, request)[1].startswith(b"first:"):
                raise tunnel.Failure("valid ingress did not recover after deadline")
        elif case == "http-pipeline-route-lock":
            with socket.create_connection(("127.0.0.1", run.local_port), timeout=20) as peer:
                peer.settimeout(30)
                first_request = f"GET / HTTP/1.1\r\nHost: {run.domain}\r\n\r\n".encode()
                second_request = f"GET /secret HTTP/1.1\r\nHost: {run.domain2}\r\n\r\n".encode()
                peer.sendall(first_request + second_request)
                tunnel.wait_for_eof(peer, 10)
                deadline = time.monotonic() + 3
                while not first.requests and time.monotonic() < deadline:
                    time.sleep(0.02)
                if not first.requests or first.requests[0] != first_request:
                    raise tunnel.Failure("validated first pipelined request did not reach its route")
                if any(second_request in request for request in first.requests + second.requests):
                    raise tunnel.Failure("cross-route pipelined request reached an upstream")
        elif case == "http-websocket":
            with socket.create_connection(("127.0.0.1", run.local_port), timeout=20) as peer:
                peer.settimeout(30)
                peer.sendall(f"GET /before HTTP/1.1\r\nHost: {run.domain}\r\n\r\n".encode())
                read_response(peer)
                request = f"GET /chat HTTP/1.1\r\nHost: {run.domain}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\nearly".encode()
                peer.sendall(request)
                data = b""
                while b"101 Switching Protocols" not in data or b"early" not in data:
                    data += peer.recv(4096)
                if b"101 Switching Protocols" not in data or b"early" not in data:
                    raise tunnel.Failure("WebSocket transition did not release held early data")
                peer.sendall(b"opaque")
                if tunnel.recv_exact(peer, 6) != b"opaque":
                    raise tunnel.Failure("WebSocket opaque payload was not bidirectional")
            unsupported = f"GET / HTTP/1.1\r\nHost: {run.domain}\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n".encode()
            head, body = http_exchange(run.local_port, unsupported)
            if not head.startswith(b"HTTP/1.1 400") or b"route.unsupported_protocol" not in body:
                raise tunnel.Failure("h2c was not rejected locally")
        elif case == "http-streaming":
            fixed = b"x" * (1024 * 1024)
            request = f"POST / HTTP/1.1\r\nHost: {run.domain}\r\nContent-Length: {len(fixed)}\r\n\r\n".encode() + fixed
            if not http_exchange(run.local_port, request)[1].startswith(b"first:"):
                raise tunnel.Failure("large fixed upload failed")
            chunked = f"POST / HTTP/1.1\r\nHost: {run.domain}\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n".encode() + b"10000\r\n" + b"z" * 65536 + b"\r\n0\r\nX-End: yes\r\n\r\n"
            if not http_exchange(run.local_port, chunked)[1].startswith(b"first:"):
                raise tunnel.Failure("chunked upload with trailers failed")
            if len(http_exchange(run.local_port, f"GET /large HTTP/1.1\r\nHost: {run.domain}\r\n\r\n".encode())[1]) != 1024 * 1024:
                raise tunnel.Failure("large streaming download failed")
            with socket.create_connection(("127.0.0.1", run.local_port), timeout=20) as peer:
                peer.sendall(f"POST /continue HTTP/1.1\r\nHost: {run.domain}\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n".encode())
                if b"100 Continue" not in peer.recv(4096):
                    raise tunnel.Failure("100-continue did not make forward progress")
                peer.sendall(b"data")
                read_response(peer)
        elif case == "mixed-limits":
            held = []
            for _ in range(4):
                peer = socket.create_connection(("127.0.0.1", run.local_port), timeout=20)
                peer.sendall(b"GET / HTTP/1.1\r\nHost:")
                held.append(peer)
            with socket.create_connection(("127.0.0.1", run.local_port2), timeout=20) as extra:
                tunnel.wait_for_eof(extra, 3)
            for peer in held:
                peer.close()
            request = f"GET /recover HTTP/1.1\r\nHost: {run.domain}\r\n\r\n".encode()
            if not http_exchange(run.local_port, request)[1].startswith(b"first:"):
                raise tunnel.Failure("shared ingress limit did not recover")
        elif case == "shutdown-parsing":
            peer = socket.create_connection(("127.0.0.1", run.local_port), timeout=20)
            peer.sendall(b"GET / HTTP/1.1\r\nHost:")
            run.stop(client_log)
            tunnel.wait_for_eof(peer, 5)
            peer.close()
            tunnel.assert_final_resources(client_log)
        elif case == "shutdown-active":
            peer = socket.create_connection(("127.0.0.1", run.raw_local_port), timeout=20)
            peer.sendall(b"active")
            if tunnel.recv_exact(peer, 6) != b"active":
                raise tunnel.Failure("raw stream did not become active")
            run.stop(client_log)
            tunnel.wait_for_eof(peer, 5)
            peer.close()
            tunnel.assert_final_resources(client_log)
        elif case.startswith("mixed-concurrency/"):
            target = int(case.rsplit("/", 1)[1])

            def open_one(index: int) -> socket.socket:
                if index % 3 == 0:
                    peer = socket.create_connection(("127.0.0.1", run.raw_local_port), timeout=20)
                    peer.sendall(b"r")
                    if tunnel.recv_exact(peer, 1) != b"r":
                        raise tunnel.Failure("raw concurrent stream failed")
                    return peer
                if index % 3 == 1:
                    peer = socket.create_connection(("127.0.0.1", run.local_port), timeout=20)
                    peer.sendall(f"GET /hold HTTP/1.1\r\nHost: {run.domain}\r\n\r\n".encode())
                    read_response(peer)
                    return peer
                context = ssl.create_default_context(cafile=str(run.cert))
                peer = context.wrap_socket(socket.create_connection(("127.0.0.1", run.local_port2), timeout=20), server_hostname=run.domain)
                peer.sendall(b"t")
                if peer.recv(32) != b"tls-first:t":
                    raise tunnel.Failure("TLS concurrent stream failed")
                return peer

            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
                peers = list(pool.map(open_one, range(target)))
            wait_count(client_log, "tunnel_accepted", target)
            tunnel.wait_for(
                client_log,
                lambda row: row.get("event") == "resources" and row.get("workers", 0) >= target,
                10,
            )
            tunnel.wait_for(
                client_log,
                lambda row: row.get("event") == "client_tunnel_resources"
                and row.get("active_owners", 0) >= target,
                10,
            )
            for peer in peers:
                peer.close()
        else:
            with socket.create_connection(("127.0.0.1", run.local_port), timeout=20) as peer:
                peer.settimeout(30)
                body = b"x" * (1024 * 1024 if case == "http-streaming" else 0)
                request = f"POST / HTTP/1.1\r\nHost: {run.domain}\r\nContent-Length: {len(body)}\r\n\r\n".encode() + body
                peer.sendall(request)
                _, response = read_response(peer)
                if not response.startswith(b"first:"):
                    raise tunnel.Failure("HTTP route did not reach the selected fixture")
                if case == "http-keepalive":
                    peer.sendall(f"GET /two HTTP/1.1\r\nHost: {run.domain}\r\n\r\n".encode())
                    read_response(peer)
        if case in {"http-local-rejections", "http-error-mapping", "tls-local-rejections"}:
            if (first.accepted_connections, second.accepted_connections) != before:
                raise tunnel.Failure("local rejection opened an upstream connection")
        elif case not in {"shutdown-parsing", "shutdown-active"}:
            tunnel.wait_for(client_log, lambda row: row.get("event") == "tunnel_accepted", 45)
        paths = [row.get("selected_path") for row in tunnel.read_rows(client_log) if row.get("event") == "path_selected"]
        expected = "relay" if case.endswith("relay") else "direct"
        if case in {"http-direct", "http-relay", "tls-direct", "tls-relay"} and expected not in paths:
            raise tunnel.Failure(f"expected {expected} path, saw {paths}")
        if case in {"http-direct", "http-relay"}:
            request = f"GET /second HTTP/1.1\r\nHost: {run.domain2}\r\n\r\n".encode()
            if not http_exchange(run.local_port, request)[1].startswith(b"second:"):
                raise tunnel.Failure("second exact Host route selected the wrong upstream")
        process_logs = [exchange_log, server_log, client_log]
        privacy_clean = assert_ingress_privacy(run, process_logs)
        run.stop(client_log)
        run.stop(server_log)
        run.stop(exchange_log)
        run.cleanup()
        terminals = tunnel.assert_process_terminals(process_logs)
        resources = (
            tunnel.assert_final_exchange_resources(exchange_log)
            and tunnel.assert_final_resources(server_log)
            and tunnel.assert_final_resources(client_log)
        )
        return {
            "case": case,
            "processes": 3,
            "http_fixture_connections": first.accepted_connections,
            "asserted": True,
            "privacy_clean": privacy_clean,
            "one_terminal_each": terminals,
            "resources_drained": resources,
        }
    finally:
        run.cleanup()
        first.close()
        second.close()
        tls_first.close()
        tls_second.close()
        raw.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: live.py ROOT CASE")
    print(json.dumps(run_case(pathlib.Path(sys.argv[1]).resolve(), sys.argv[2]), sort_keys=True))
