from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing


class Failure(RuntimeError):
    pass


def free_port(kind: int) -> int:
    with closing(socket.socket(socket.AF_INET, kind)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def token(name: str) -> tuple[str, str]:
    raw = secrets.token_bytes(32)
    value = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    digest = hashlib.sha256(b"p2x-fixed-token-v1\0" + raw).digest()
    return f"p2x1.{name}.{value}", base64.urlsafe_b64encode(digest).decode().rstrip("=")


def read_rows(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise Failure(f"invalid NDJSON in {path}: {error}") from error
    return rows


def wait_for(path: pathlib.Path, predicate, timeout: float = 30.0) -> dict:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        for row in read_rows(path):
            if predicate(row):
                return row
        time.sleep(0.05)
    tail = "\n".join(path.read_text(errors="replace").splitlines()[-20:]) if path.exists() else "<missing>"
    raise Failure(f"timed out waiting for {path.name}\n{tail}")


class Upstream:
    def __init__(self, port: int, mode: str):
        self.port = port
        self.mode = mode
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.listener: socket.socket | None = None
        self.accepted_connections = 0

    def start(self) -> None:
        self.thread.start()

    def run(self) -> None:
        with socket.socket() as listener:
            self.listener = listener
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", self.port))
            listener.listen()
            listener.settimeout(0.2)
            while not self.stop.is_set():
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                self.accepted_connections += 1
                threading.Thread(target=self.handle, args=(client, self.accepted_connections), daemon=True).start()

    def handle(self, client: socket.socket, connection_number: int) -> None:
        with client:
            if self.mode == "hold":
                while True:
                    data = client.recv(65536)
                    if not data:
                        return
                    time.sleep(0.5)
                    client.sendall(data)
            if self.mode == "slow" or (self.mode == "slow-first" and connection_number == 1):
                while True:
                    data = client.recv(65536)
                    if not data:
                        return
                    time.sleep(0.001)
                    client.sendall(data)
            if self.mode == "idle-first" and connection_number == 1:
                while not self.stop.wait(0.1):
                    pass
                return
            if self.mode == "idle":
                while not self.stop.wait(0.1):
                    pass
                return
            if self.mode == "half-close":
                data = bytearray()
                while True:
                    chunk = client.recv(65536)
                    if not chunk:
                        break
                    data.extend(chunk)
                client.sendall(b"half-close-response:" + data)
                client.shutdown(socket.SHUT_WR)
                return
            while True:
                data = client.recv(65536)
                if not data:
                    return
                client.sendall(data)

    def close(self) -> None:
        self.stop.set()
        if self.listener is not None:
            self.listener.close()
        self.thread.join(timeout=2)


class Run:
    def __init__(self, root: pathlib.Path, case: str):
        run_id = os.environ.get("P2X_RUN_ID", time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
        self.root = root
        self.case = case
        self.out = root / "target" / "p2x-tunnel" / run_id / case
        self.out.mkdir(parents=True, exist_ok=True)
        self.secret = pathlib.Path(__import__("tempfile").mkdtemp(prefix="p2x-tunnel-"))
        self.processes: list[tuple[subprocess.Popen, pathlib.Path, object]] = []
        self.samples: list[dict] = []
        self.sample_stop = threading.Event()
        self.sample_thread: threading.Thread | None = None
        self.resource_marks: dict[str, dict] = {}
        self.upstream_port = free_port(socket.SOCK_STREAM)
        self.local_port = free_port(socket.SOCK_STREAM)
        self.exchange_tcp = free_port(socket.SOCK_STREAM)
        self.exchange_quic = free_port(socket.SOCK_DGRAM)
        self.upstream: Upstream | None = None
        self.upstream_connections = 0
        self.selector_key = "k_" + secrets.token_hex(8)
        self.selector_value = "v_" + secrets.token_hex(8)
        self.route_id = "r_" + secrets.token_hex(8)
        self.upstream_id = "u_" + secrets.token_hex(8)
        self.client_credential_id = "client_" + secrets.token_hex(4)
        self.server_credential_id = "server_" + secrets.token_hex(4)
        self.private = [self.selector_key, self.selector_value, self.route_id, self.upstream_id, self.client_credential_id, self.server_credential_id]
        self.client_token, client_digest = token(self.client_credential_id)
        self.server_token, server_digest = token(self.server_credential_id)
        self.payload_sentinel = "p2x-" + secrets.token_urlsafe(16)
        self.exchange_peer = self.identity("exchange")
        self.server_peer = self.identity("server")
        self.client_peer = self.identity("client")
        now = int(time.time())
        self.ticket_key = self.secret / "ticket.key"
        self.ticket_key.write_bytes(b"\x01" + secrets.token_bytes(32))
        self.ticket_key.chmod(0o600)
        self.verification_keys = self.secret / "verification-keys.yaml"
        subprocess.run(
            [str(root / "target/debug/examples/ticket-verification"), str(self.ticket_key), str(self.verification_keys)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        self.credentials = self.secret / "credentials.yaml"
        self.credentials.write_text(
            f"""schema_version: 1
authorization_revision: 1
credentials:
  - credential_id: {self.client_credential_id}
    token_sha256: \"{client_digest}\"
    peer_id: \"{self.client_peer}\"
    tenant: test
    role: client
    scopes: [open_proxy_stream]
    quota_profile: standard
    not_before: {now - 60}
    expires_at: {now + 3600}
    revoked: false
  - credential_id: {self.server_credential_id}
    token_sha256: \"{server_digest}\"
    peer_id: \"{self.server_peer}\"
    tenant: test
    role: server
    scopes: [register_services, reserve_relay]
    quota_profile: standard
    not_before: {now - 60}
    expires_at: {now + 3600}
    revoked: false
"""
        )
        self.credentials.chmod(0o600)
        self.write_configs()

    def identity(self, name: str) -> str:
        return subprocess.check_output(
            [str(self.root / "target/debug/examples/identity-id"), str(self.secret / f"{name}.key"), "--generate"],
            text=True,
        ).strip()

    def write_configs(self) -> None:
        base_case = self.case.split("/", 1)[0]
        idle = 1_000 if base_case == "idle-timeout" else 3_600_000 if base_case.startswith("large-slow") else 300_000
        connect = self.upstream_port
        if base_case == "upstream-refused":
            connect = free_port(socket.SOCK_STREAM)
            self.upstream_port = connect
        self.services = self.secret / "services.yaml"
        base_case = self.case.split("/", 1)[0]
        concurrent = base_case == "concurrent-streams" or base_case == "resource-baseline"
        max_workers = 2 if base_case == "stream-limits" else 256
        max_workers_per_client = 2 if base_case == "stream-limits" else 128 if concurrent else 32
        max_upstream_dials = 2 if base_case == "stream-limits" else 128 if concurrent else 64
        concurrency_limit = 1 if base_case == "stream-limits" else 128 if concurrent else 64
        self.services.write_text(
            f"""schema_version: 1
registration:
  requested_lease_seconds: 30
  refresh_seconds: 10
services:
  - upstream_id: {self.upstream_id}
    selector:
      protocol: tcp
      metadata: {{{self.selector_key}: {self.selector_value}}}
    enabled: true
    connect: 127.0.0.1:{connect}
    connect_timeout_ms: 3000
    idle_timeout_ms: {idle}
    concurrency_limit: {concurrency_limit}
proxy:
  max_workers: {max_workers}
  max_workers_per_client: {max_workers_per_client}
  max_upstream_dials: {max_upstream_dials}
  copy_buffer_bytes: 32768
  max_replay_entries: 8192
  ticket_clock_skew: 5
"""
        )
        direct = 0 if base_case.endswith("-relay") else 5000 if base_case == "control-loss-direct" else 1500
        self.routes = self.secret / "routes.yaml"
        self.routes.write_text(
            f"""schema_version: 1
network:
  direct_preference_ms: {direct}
  connection_setup_timeout_ms: 20000
targets:
  - route_id: {self.route_id}
    selector:
      protocol: tcp
      metadata: {{{self.selector_key}: {self.selector_value}}}
raw_tcp:
  - name: {self.route_id}-local
    bind: 127.0.0.1:{self.local_port}
    route_id: {self.route_id}
limits:
  max_peer_states: 64
  max_pending_setups: 256
  max_pending_per_server: 128
  max_ingress_connections: 512
  max_streams_per_server: 128
  copy_buffer_bytes: 32768
"""
        )

    def start_sampler(self) -> None:
        def sample() -> None:
            while not self.sample_stop.wait(0.2):
                row = {"time": time.monotonic()}
                for process, _, _ in self.processes:
                    if process.poll() is not None:
                        continue
                    try:
                        name = pathlib.Path(process.args[0]).name
                        rss = subprocess.check_output(
                            ["ps", "-o", "rss=", "-p", str(process.pid)],
                            text=True,
                        ).strip()
                        fds = subprocess.check_output(
                            ["lsof", "-p", str(process.pid)],
                            text=True,
                            stderr=subprocess.DEVNULL,
                        ).count("\n")
                    except subprocess.CalledProcessError:
                        continue
                    row[f"rss_{name}"] = int(rss or 0) * 1024
                    row[f"fds_{name}"] = fds
                self.samples.append(row)

        self.sample_thread = threading.Thread(target=sample, daemon=True)
        self.sample_thread.start()

    def sample_snapshot(self) -> dict:
        row = {"time": time.monotonic()}
        for process, _, _ in self.processes:
            if process.poll() is not None:
                continue
            try:
                name = pathlib.Path(process.args[0]).name
                rss = subprocess.check_output(["ps", "-o", "rss=", "-p", str(process.pid)], text=True).strip()
                fds = subprocess.check_output(["lsof", "-p", str(process.pid)], text=True, stderr=subprocess.DEVNULL).count("\n")
            except (subprocess.CalledProcessError, FileNotFoundError):
                continue
            row[f"rss_{name}"] = int(rss or 0) * 1024
            row[f"fds_{name}"] = fds
        return row

    def mark_resources(self, name: str) -> None:
        self.resource_marks[name] = self.sample_snapshot()

    def stop_sampler(self) -> None:
        self.sample_stop.set()
        if self.sample_thread is not None:
            self.sample_thread.join(timeout=3)

    def start(self, name: str, argv: list[str], env: dict[str, str]) -> pathlib.Path:
        log = self.out / f"{name}.ndjson"
        handle = log.open("w")
        child_env = os.environ.copy()
        child_env.update(env)
        child_env["P2X_RUN_ID"] = f"tunnel-{self.case}"
        process = subprocess.Popen(argv, cwd=self.root, env=child_env, stdout=handle, stderr=subprocess.STDOUT)
        self.processes.append((process, log, handle))
        return log

    def start_exchange(self, name: str = "exchange") -> pathlib.Path:
        base = f"/ip4/127.0.0.1/tcp/{self.exchange_tcp}"
        advertised = base + f"/p2p/{self.exchange_peer}"
        args = [str(self.root / "target/debug/p2x-exchange"), "--identity-file", str(self.secret / "exchange.key"), "--credential-file", str(self.credentials), "--ticket-key-file", str(self.ticket_key), "--tcp-listen", base, "--quic-listen", f"/ip4/127.0.0.1/udp/{self.exchange_quic}/quic-v1", "--advertise", advertised, "--case-id", self.case]
        env = {}
        if self.case.split("/", 1)[0] in {"concurrent-streams", "resource-baseline"}:
            args += ["--resolve-limit-global", "256", "--resolve-limit-per-client", "128", "--resolve-limit-per-minute", "256"]
            env["P2X_ENABLE_TEST_HOOKS"] = "1"
        return self.start(name, args, env)

    def start_server(self, exchange: str, name: str = "server") -> pathlib.Path:
        args = [str(self.root / "target/debug/p2x-server"), "--identity-file", str(self.secret / "server.key"), "--exchange", exchange, "--exchange-peer-id", self.exchange_peer, "--credential-env", "P2X_TOKEN", "--ticket-verification-keys-file", str(self.verification_keys), "--services-file", str(self.services), "--case-id", self.case]
        env = {"P2X_TOKEN": self.server_token}
        if self.case.split("/", 1)[0] == "upstream-timeout":
            args += ["--test-hold-upstream-dial-ms", "4000"]
            env["P2X_ENABLE_TEST_HOOKS"] = "1"
        elif self.case.split("/", 1)[0] == "stream-limits":
            args += ["--test-hold-proxy-handshake-ms", "1000"]
            env["P2X_ENABLE_TEST_HOOKS"] = "1"
        return self.start(name, args, env)

    def start_client(self, exchange: str, name: str = "client") -> pathlib.Path:
        args = [str(self.root / "target/debug/p2x-client"), "--identity-file", str(self.secret / "client.key"), "--exchange", exchange, "--exchange-peer-id", self.exchange_peer, "--credential-env", "P2X_TOKEN", "--routes-file", str(self.routes), "--case-id", self.case]
        env = {"P2X_TOKEN": self.client_token}
        if self.case.split("/", 1)[0] == "path-loss-recovery":
            args += ["--test-close-proxy-after-accept-ms", "100"]
            env["P2X_ENABLE_TEST_HOOKS"] = "1"
        return self.start(name, args, env)

    def stop(self, path: pathlib.Path, force: bool = False) -> None:
        for process, log, handle in self.processes:
            if log != path or process.poll() is not None:
                continue
            process.send_signal(signal.SIGKILL if force else signal.SIGINT)
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            handle.close()
            return

    def cleanup(self) -> None:
        for process, _, _ in reversed(self.processes):
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
        for process, _, handle in reversed(self.processes):
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            if not handle.closed:
                handle.close()
        self.stop_sampler()
        if self.upstream is not None:
            self.upstream.close()
        import shutil
        shutil.rmtree(self.secret, ignore_errors=True)


def one_terminal(path: pathlib.Path) -> dict:
    terminals = [row for row in read_rows(path) if row.get("event") == "terminal"]
    if len(terminals) != 1:
        raise Failure(f"{path.name}: expected one terminal, got {len(terminals)}")
    return terminals[0]

def wait_for_terminal(path: pathlib.Path, timeout: float = 15.0) -> dict:
    return wait_for(path, lambda row: row.get("event") == "terminal", timeout)

def wait_for_count(path: pathlib.Path, predicate, count: int, timeout: float = 30.0) -> list[dict]:
    end = time.monotonic() + timeout
    rows: list[dict] = []
    while time.monotonic() < end:
        rows = [row for row in read_rows(path) if predicate(row)]
        if len(rows) >= count:
            return rows
        time.sleep(0.05)
    raise Failure(f"timed out waiting for {count} rows in {path.name}; got {len(rows)}")

def recv_exact(peer: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = peer.recv(size - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)

def assert_process_terminals(paths: list[pathlib.Path]) -> bool:
    seen: set[pathlib.Path] = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        one_terminal(path)
    return True

def assert_final_resources(path: pathlib.Path) -> bool:
    rows = [row for row in read_rows(path) if row.get("event") == "resources"]
    if not rows:
        raise Failure(f"{path.name}: no resource record")
    final = rows[-1]
    if any(final.get(field, 0) != 0 for field in ("connections", "pending_opens", "workers", "tasks")):
        raise Failure(f"{path.name}: final resources are not zero: {final}")
    return True

def assert_privacy(run: Run, paths: list[pathlib.Path]) -> bool:
    output = "\\n".join(path.read_text(errors="replace") for path in paths)
    markers = [run.client_token, run.server_token, *run.private, run.payload_sentinel, f"127.0.0.1:{run.upstream_port}"]
    for marker in markers:
        if marker in output:
            raise Failure(f"privacy scan found exact run marker {marker}")
    return True

def assert_tunnel_lifecycle(case: str, client_rows: list[dict], server_rows: list[dict]) -> dict[str, bool]:
    client_accepted = [row for row in client_rows if row.get("event") == "tunnel_accepted"]
    server_accepted = [row for row in server_rows if row.get("event") == "tunnel_accepted"]
    client_terminal = [row for row in client_rows if row.get("event") == "tunnel_terminal"]
    server_terminal = [row for row in server_rows if row.get("event") == "tunnel_terminal"]
    expected = {
        "accepted": False,
        "terminal_correlation": False,
        "directional_bytes": False,
        "idle_terminal_class": False,
        "upstream_failure_or_idle": False,
    }
    base_case = case.split("/", 1)[0]
    if not client_accepted and not server_accepted:
        if client_terminal or server_terminal:
            raise Failure(f"{case} emitted a tunnel terminal without Accepted")
        expected["upstream_failure_or_idle"] = any(
            row.get("code") in {"upstream.connect_failed", "upstream.connect_timeout"}
            for row in server_rows
            if row.get("event") == "proxy_authorization"
        )
        if not expected["upstream_failure_or_idle"]:
            raise Failure(f"{case} did not observe a concrete pre-Accept failure")
        return expected
    if len(client_accepted) != len(server_accepted):
        raise Failure(f"{case} Accepted cardinality differs: client={len(client_accepted)} server={len(server_accepted)}")
    client_keys = {(row.get("request_id_hash"), row.get("stream_id_hash")) for row in client_accepted}
    server_keys = {(row.get("request_id_hash"), row.get("stream_id_hash")) for row in server_accepted}
    if client_keys != server_keys or len(client_keys) != len(client_accepted):
        raise Failure(f"{case} Accepted correlation mismatch")
    if len(client_terminal) != len(client_accepted) or len(server_terminal) != len(server_accepted):
        raise Failure(f"{case} terminal cardinality mismatch")
    client_terminals = {(row.get("request_id_hash"), row.get("stream_id_hash")): row for row in client_terminal}
    server_terminals = {(row.get("request_id_hash"), row.get("stream_id_hash")): row for row in server_terminal}
    if set(client_terminals) != client_keys or set(server_terminals) != server_keys:
        raise Failure(f"{case} terminal correlation mismatch")
    for key in client_keys:
        client_row = client_terminals[key]
        server_row = server_terminals[key]
        if client_row.get("local_to_remote_bytes") != server_row.get("local_to_remote_bytes"):
            raise Failure(f"{case} local-to-remote counters differ for {key}")
        if client_row.get("remote_to_local_bytes") != server_row.get("remote_to_local_bytes"):
            raise Failure(f"{case} remote-to-local counters differ for {key}")
        if client_row.get("selected_path") != server_row.get("selected_path"):
            raise Failure(f"{case} selected path differs for {key}")
        if client_row.get("setup_duration_ms", -1) < 0 or server_row.get("setup_duration_ms", -1) < 0:
            raise Failure(f"{case} setup duration was not frozen for {key}")
        if client_row.get("selected_path") not in {"direct", "relay"}:
            raise Failure(f"{case} client terminal path missing for {key}")
        if server_row.get("selected_path") not in {"direct", "relay"}:
            raise Failure(f"{case} server terminal path missing for {key}")
    expected["accepted"] = True
    expected["terminal_correlation"] = True
    expected["directional_bytes"] = True
    if base_case == "idle-timeout":
        if not any(row.get("terminal_class") == "idle_timeout" and row.get("code") == "upstream.idle_timeout" for row in server_terminal):
            raise Failure("idle-timeout did not emit idle_timeout terminal class with public code")
        expected["idle_terminal_class"] = True
        expected["upstream_failure_or_idle"] = True
    return expected

def run_case(root: pathlib.Path, case: str) -> None:
    run = Run(root, case)
    exchange_log = server_log = client_log = None
    try:
        if case not in {"upstream-refused", "upstream-timeout"}:
            mode = "half-close" if case.startswith("half-close") else "idle" if case == "idle-timeout" else "hold" if case in {"path-loss-recovery", "shutdown-cancellation", "concurrent-streams"} else "slow-first" if case.startswith("large-slow") else "echo"
            run.upstream = Upstream(run.upstream_port, mode)
            run.upstream.start()
        exchange_log = run.start_exchange()
        listen = wait_for(exchange_log, lambda row: row.get("event") == "listener_ready" and "/tcp/" in row.get("address", ""))
        exchange = listen["address"]
        server_log = run.start_server(exchange)
        wait_for(server_log, lambda row: row.get("event") == "server_readiness" and row.get("ready") is True, 45)
        wait_for(exchange_log, lambda row: row.get("event") == "registry_transition" and row.get("code") == "registry.registered", 45)
        client_log = run.start_client(exchange)
        wait_for(client_log, lambda row: row.get("event") == "started", 20)
        wait_for(client_log, lambda row: row.get("event") == "auth_readiness" and row.get("ready") is True, 45)
        run.start_sampler()
        client = None if case == "concurrent-streams" else socket.create_connection(("127.0.0.1", run.local_port), timeout=20)
        if client is not None:
            client.settimeout(900 if case.startswith("large-slow") else 60)
            if case not in {"upstream-refused", "upstream-timeout", "idle-timeout"}:
                wait_for(client_log, lambda row: row.get("event") == "tunnel_accepted", 45)
        if case == "stream-limits":
            assert client is not None
            held = [client]
            wait_for_count(server_log, lambda row: row.get("event") == "tunnel_accepted", 1, 60)
            third = socket.create_connection(("127.0.0.1", run.local_port), timeout=20)
            third.settimeout(30)
            third.sendall(b"n-plus-one")
            if third.recv(1) != b"":
                raise Failure("stream-limits forwarded a rejected stream")
            third.close()
            for peer in held:
                peer.close()
            client = None
            wait_for_count(server_log, lambda row: row.get("event") == "tunnel_terminal", 1, 45)
            reusable = socket.create_connection(("127.0.0.1", run.local_port), timeout=20)
            reusable.settimeout(20)
            reusable.sendall(b"released-capacity")
            if reusable.recv(len(b"released-capacity")) != b"released-capacity":
                raise Failure("released stream capacity was not reusable")
            reusable.close()
        elif case == "control-loss-direct":
            assert client is not None
            wait_for(client_log, lambda row: row.get("event") == "path_selected" and row.get("selected_path") == "direct", 45)
            first = b"control-loss-before"
            client.sendall(first)
            if client.recv(len(first)) != first:
                raise Failure("direct stream failed before control loss")
            wait_for(server_log, lambda row: row.get("event") == "proxy_authorization" and row.get("authorized") is True, 45)
            time.sleep(0.5)
            run.stop(exchange_log)
            second = b"control-loss-after"
            client.sendall(second)
            if client.recv(len(second)) != second:
                raise Failure("accepted direct stream did not survive exchange control loss")
            exchange_log = run.start_exchange("exchange-recovered")
            wait_for(exchange_log, lambda row: row.get("event") == "listener_ready" and "/tcp/" in row.get("address", ""), 45)
            wait_for(exchange_log, lambda row: row.get("event") == "registry_transition" and row.get("code") == "registry.registered", 60)
            wait_for(server_log, lambda row: row.get("event") == "server_readiness" and row.get("ready") is True and row.get("registration") is True, 60)
            wait_for(client_log, lambda row: row.get("event") == "auth_readiness" and row.get("ready") is True and row.get("generation", 0) >= 2, 60)
            recovered = socket.create_connection(("127.0.0.1", run.local_port), timeout=20)
            recovered.settimeout(30)
            recovered_payload = b"control-loss-recovered"
            recovered.sendall(recovered_payload)
            if recovered.recv(len(recovered_payload)) != recovered_payload:
                raise Failure("control-loss-direct did not recover a later ingress")
            recovered.close()
        elif case == "path-loss-recovery":
            assert client is not None
            client.sendall(b"path-loss-payload")
            time.sleep(0.3)
            client.close()
            client = None
            wait_for(client_log, lambda row: row.get("event") == "tunnel_terminal", 30)
            recovered = socket.create_connection(("127.0.0.1", run.local_port), timeout=20)
            recovered.settimeout(30)
            recovered.sendall(b"path-loss-recovered")
            if recovered.recv(len(b"path-loss-recovered")) != b"path-loss-recovered":
                raise Failure("path-loss-recovery did not accept a later ingress")
            recovered.close()
        elif case == "shutdown-cancellation":
            assert client is not None
            client.sendall(b"shutdown-cancellation")
            time.sleep(0.2)
            run.stop(client_log)
            client.close()
            client = None
            run.stop(server_log)
        elif case.startswith("half-close"):
            assert client is not None
            client.sendall(b"half-close-payload")
            client.shutdown(socket.SHUT_WR)
            expected = b"half-close-response:half-close-payload"
            data = bytearray()
            while len(data) < len(expected):
                chunk = client.recv(65536)
                if not chunk:
                    break
                data.extend(chunk)
            if bytes(data) != expected:
                raise Failure(f"half-close response mismatch: {data!r}")
        elif case == "idle-timeout":
            assert client is not None
            if client.recv(1) != b"":
                raise Failure("idle tunnel returned application data")
        elif case == "upstream-refused":
            assert client is not None
            if client.recv(1) != b"":
                raise Failure("refused upstream forwarded bytes")
        elif case == "upstream-timeout":
            assert client is not None
            if client.recv(1) != b"":
                raise Failure("timed-out upstream forwarded bytes")
        else:
            payload_size = 256 * 1024 * 1024 if case.startswith("large-slow") else 64
            if case == "concurrent-streams":
                peers: list[socket.socket] = []
                try:
                    for index in range(64):
                        peer = socket.create_connection(("127.0.0.1", run.local_port), timeout=60)
                        peer.settimeout(60)
                        peers.append(peer)
                        peer.sendall(f"stream-{index:03d}".encode() + secrets.token_bytes(32))
                    wait_for_count(client_log, lambda row: row.get("event") == "tunnel_accepted", 64, 90)
                    wait_for_count(server_log, lambda row: row.get("event") == "tunnel_accepted", 64, 90)
                    run.mark_resources("64_sustained")
                    with ThreadPoolExecutor(max_workers=64) as pool:
                        sustained = list(pool.map(lambda item: recv_exact(item[0], len(item[1])), zip(peers, [f"stream-{index:03d}".encode() + b"x" * 32 for index in range(64)])))
                    if any(not data for data in sustained):
                        raise Failure("concurrent sustained stream closed before release")
                    for peer in peers:
                        peer.close()
                    peers.clear()
                    wait_for_count(client_log, lambda row: row.get("event") == "tunnel_terminal", 64, 90)
                    wait_for_count(server_log, lambda row: row.get("event") == "tunnel_terminal", 64, 90)
                    expected_headroom: list[bytes] = []
                    client_accepted_before_headroom = sum(row.get("event") == "tunnel_accepted" for row in read_rows(client_log))
                    server_accepted_before_headroom = sum(row.get("event") == "tunnel_accepted" for row in read_rows(server_log))
                    for index in range(128):
                        peer = socket.create_connection(("127.0.0.1", run.local_port), timeout=60)
                        peer.settimeout(60)
                        peers.append(peer)
                        payload = f"headroom-{index:03d}".encode()
                        expected_headroom.append(payload)
                        peer.sendall(payload)
                    wait_for_count(client_log, lambda row: row.get("event") == "tunnel_accepted", client_accepted_before_headroom + 128, 120)
                    wait_for_count(server_log, lambda row: row.get("event") == "tunnel_accepted", server_accepted_before_headroom + 128, 120)
                    run.mark_resources("128_headroom")
                    with ThreadPoolExecutor(max_workers=128) as pool:
                        actuals = list(pool.map(lambda item: recv_exact(item[0], len(item[1])), zip(peers, expected_headroom)))
                    mismatches = [(index, expected, actual) for index, (actual, expected) in enumerate(zip(actuals, expected_headroom)) if actual != expected]
                    if mismatches:
                        raise Failure(f"128 headroom echo mismatches={mismatches[:4]} total={len(mismatches)}")
                    for peer in peers:
                        peer.close()
                    peers.clear()
                    wait_for_count(client_log, lambda row: row.get("event") == "tunnel_terminal", 192, 120)
                    wait_for_count(server_log, lambda row: row.get("event") == "tunnel_terminal", 192, 120)
                    run.mark_resources("after_release")
                finally:
                    for peer in peers:
                        peer.close()
                (run.out / "resource-samples.json").write_text(json.dumps({
                    "samples": run.samples,
                    "resource_marks": run.resource_marks,
                    "copy_buffer_bytes": 32768,
                    "max_active_streams": 128,
                    "direction_buffers_per_component": 2,
                    "pending_client_preaccept_buffers": 1,
                    "declared_user_buffers": 9,
                    "declared_bytes": 9 * 32768,
                    "rss_delta_limit": 64 * 1024 * 1024,
                }, sort_keys=True) + "\n")
            else:
                assert client is not None
                if case.startswith("large-slow"):
                    sentinel = run.payload_sentinel.encode()
                    block = sentinel + b"x" * (64 * 1024 - len(sentinel))
                    expected = hashlib.sha256()
                    for offset in range(0, payload_size, len(block)):
                        expected.update(block[: min(len(block), payload_size - offset)])
                    send_error: list[BaseException] = []
                    def send_large() -> None:
                        try:
                            for offset in range(0, payload_size, len(block)):
                                client.sendall(block[: min(len(block), payload_size - offset)])
                            client.shutdown(socket.SHUT_WR)
                        except BaseException as error:
                            send_error.append(error)
                    sender = threading.Thread(target=send_large, daemon=True)
                    sender.start()
                    digest = hashlib.sha256()
                    received = 0
                    small_done = threading.Event()
                    def small_stream() -> None:
                        try:
                            with socket.create_connection(("127.0.0.1", run.local_port), timeout=30) as small:
                                small.settimeout(30)
                                small_payload = b"small-stream-during-large"
                                small.sendall(small_payload)
                                if small.recv(len(small_payload)) != small_payload:
                                    raise Failure("small stream payload mismatch during large transfer")
                            small_done.set()
                        except BaseException as error:
                            send_error.append(error)
                    small = threading.Thread(target=small_stream, daemon=True)
                    small.start()
                    while received < payload_size:
                        chunk = client.recv(min(65536, payload_size - received))
                        if not chunk:
                            raise Failure(f"large stream closed at {received} bytes")
                        digest.update(chunk)
                        received += len(chunk)
                    if not small_done.is_set():
                        raise Failure("small stream did not finish during large transfer")
                    sender.join(timeout=120)
                    small.join(timeout=60)
                    if send_error:
                        raise Failure(f"large stream failed: {send_error[0]}")
                    if not small_done.is_set():
                        raise Failure("small stream did not finish during large transfer")
                    if digest.digest() != expected.digest():
                        raise Failure("large stream hash mismatch")
                else:
                    sentinel = run.payload_sentinel.encode()
                    payload = (sentinel + secrets.token_bytes(max(32, payload_size - len(sentinel))))[:payload_size]
                    send_error: list[BaseException] = []
                    def send_payload() -> None:
                        try:
                            client.sendall(payload)
                            client.shutdown(socket.SHUT_WR)
                        except BaseException as error:
                            send_error.append(error)
                    sender = threading.Thread(target=send_payload, daemon=True)
                    sender.start()
                    data = bytearray()
                    while len(data) < len(payload):
                        data.extend(client.recv(min(65536, len(payload) - len(data))))
                    sender.join(timeout=30)
                    if send_error:
                        raise Failure(f"echo sender failed: {send_error[0]}")
                    if bytes(data) != payload:
                        raise Failure("echo payload mismatch")
            selected = [row.get("selected_path") for row in read_rows(client_log) if row.get("event") == "path_selected"]
            expected_path = "relay" if case.endswith("-relay") else "direct"
            if expected_path not in selected:
                raise Failure(f"expected {expected_path} selected path, saw {selected}")
            if case == "concurrent-streams":
                accepted_rows = [row for row in read_rows(client_log) if row.get("event") == "tunnel_accepted"]
                if len(accepted_rows) < 64:
                    raise Failure("concurrent-streams did not produce 64 accepted stream correlations")
        if client is not None:
            client.close()
        time.sleep(0.3)
        if case == "shutdown-cancellation":
            if wait_for_terminal(client_log).get("code") != "shutdown":
                raise Failure("shutdown-cancellation did not stop the client cleanly")
            if not any(row.get("event") == "resources" and row.get("workers") == 1 for row in read_rows(client_log)):
                raise Failure("shutdown-cancellation did not observe active work before cancellation")
        if case == "control-loss-direct":
            if not any(row.get("event") == "tunnel_terminal" and row.get("accepted") for row in read_rows(client_log)):
                raise Failure("control-loss-direct did not complete an accepted stream")
        if case == "path-loss-recovery":
            if sum(row.get("event") == "tunnel_terminal" for row in read_rows(client_log)) < 2:
                raise Failure("path-loss-recovery did not terminate and replace the active stream")
            if not any(row.get("event") == "connection_observed" and row.get("state") == "closed" for row in read_rows(client_log)):
                raise Failure("path-loss-recovery did not observe selected path loss")
        client_rows = read_rows(client_log)
        server_rows = read_rows(server_log)
        lifecycle_assertions = assert_tunnel_lifecycle(case, client_rows, server_rows)
        if case == "concurrent-streams" and sum(row.get("authorized") is True for row in server_rows if row.get("event") == "proxy_authorization") < 128:
            raise Failure("concurrent-streams did not authorize 128 independent streams")
        if case == "stream-limits" and not any(row.get("code") == "limit.proxy_streams" and not row.get("authorized") for row in server_rows):
            raise Failure("stream-limits did not observe N+1 rejection")
        if case == "concurrent-streams" and not all(name in run.resource_marks for name in ("64_sustained", "128_headroom")):
            raise Failure("concurrent-streams did not capture 64/128 resource marks")
        if case == "stream-limits" and sum(row.get("authorized") is True for row in server_rows if row.get("event") == "proxy_authorization") < 1:
            raise Failure("stream-limits did not authorize the held stream")
        if case == "stream-limits" and not any(row.get("event") == "resources" and row.get("workers", 0) >= 1 for row in server_rows):
            raise Failure("stream-limits did not observe a held active worker")
        if case == "shutdown-cancellation":
            for path in (client_log, server_log):
                wait_for_terminal(path)
                rows = read_rows(path)
                if not any(row.get("event") == "terminal" and row.get("code") == "shutdown" for row in rows):
                    raise Failure(f"{path.name} did not report shutdown")
                final_resources = [row for row in rows if row.get("event") == "resources"][-1:]
                if final_resources and any(row.get("workers", 0) or row.get("tasks", 0) or row.get("pending_opens", 0) for row in final_resources):
                    raise Failure(f"{path.name} did not drain logical resources: {final_resources}")
        if case.startswith("large-slow"):
            large_terminals = [
                row for row in read_rows(client_log)
                if row.get("event") == "tunnel_terminal"
                and row.get("local_to_remote_bytes", 0) >= 256 * 1024 * 1024
                and row.get("remote_to_local_bytes", 0) >= 256 * 1024 * 1024
            ]
            if not large_terminals:
                raise Failure(f"{case} did not report the complete transfer")
            rss = [value for row in run.samples for key, value in row.items() if key.startswith("rss_p2x-client") and isinstance(value, int)]
            fds = [value for row in run.samples for key, value in row.items() if key.startswith("fds_p2x-client") and isinstance(value, int)]
            if not rss or not fds or max(fds) - min(fds) > 32:
                raise Failure(f"{case} resource samples did not drain: rss={rss[-3:]} fds={fds[-3:]}")
            if max(rss) - min(rss) > 64 * 1024 * 1024:
                raise Failure(f"{case} RSS exceeded the bounded process delta: {rss[-3:]}")
            (run.out / "resource-samples.json").write_text(json.dumps({"samples": run.samples, "resource_marks": run.resource_marks, "copy_buffer_bytes": 32768, "max_active_streams": 128, "direction_buffers_per_component": 2, "pending_client_preaccept_buffers": 1, "declared_user_buffers": 9, "declared_bytes": 9 * 32768, "rss_delta_limit": 64 * 1024 * 1024}, sort_keys=True) + "\n")
        if case.endswith("-relay") and not any(row.get("event") == "path_selected" and row.get("selected_path") == "relay" for row in read_rows(client_log)):
            raise Failure("forced relay path was not selected")
        if case == "upstream-refused" and not any(row.get("code") == "upstream.connect_failed" and not row.get("authorized") for row in server_rows):
            raise Failure("upstream refusal was not classified")
        if case == "upstream-timeout" and not any(row.get("code") == "upstream.connect_timeout" and not row.get("authorized") for row in server_rows):
            raise Failure("upstream timeout was not classified")
        accepted = [row for row in read_rows(client_log) if row.get("event") == "tunnel_accepted"]
        terminals = [row for row in read_rows(client_log) if row.get("event") == "tunnel_terminal"]
        base_case = case.split("/", 1)[0]
        if base_case not in {"upstream-refused", "upstream-timeout", "idle-timeout"} and not accepted:
            raise Failure(f"{case} did not observe tunnel acceptance")
        if len(terminals) > len(accepted):
            raise Failure(f"{case} emitted more tunnel terminals than accepted streams")
        if case != "shutdown-cancellation":
            run.stop(client_log)
        run.stop(server_log)
        run.stop(exchange_log)
        for path in (client_log, server_log, exchange_log):
            wait_for_terminal(path)
        process_logs = [path for _, path, _ in run.processes]
        process_terminals = assert_process_terminals(process_logs)
        client_resources = assert_final_resources(client_log)
        server_resources = assert_final_resources(server_log)
        privacy_clean = assert_privacy(run, process_logs)
        if base_case == "concurrent-streams":
            accepted_rows = [row for row in read_rows(client_log) if row.get("event") == "tunnel_accepted"]
            if len(accepted_rows) < 128:
                raise Failure("concurrent-streams did not produce 128 accepted stream terminals")
        summary = {
            "case": case,
            "passed": True,
            "observed_assertions": {
                "accepted_and_opaque_bytes": lifecycle_assertions["accepted"],
                "upstream_failure_or_idle": lifecycle_assertions["upstream_failure_or_idle"],
                "terminal_correlation": lifecycle_assertions["terminal_correlation"],
                "directional_bytes": lifecycle_assertions["directional_bytes"],
                "idle_terminal_class": lifecycle_assertions["idle_terminal_class"],
                "privacy_scan_clean": privacy_clean,
                "one_terminal_each": process_terminals,
                "resources_drained": client_resources and server_resources,
            },
        }
        (run.out / "summary.json").write_text(json.dumps(summary, sort_keys=True) + "\n")
        print(json.dumps(summary, sort_keys=True), flush=True)
    finally:
        run.cleanup()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: live.py ROOT CASE", file=sys.stderr)
        raise SystemExit(2)
    try:
        run_case(pathlib.Path(sys.argv[1]), sys.argv[2])
    except (Failure, subprocess.CalledProcessError) as error:
        print(f"tunnel case failed: {error}", file=sys.stderr)
        raise SystemExit(1)
