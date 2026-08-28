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
                threading.Thread(target=self.handle, args=(client,), daemon=True).start()

    def handle(self, client: socket.socket) -> None:
        with client:
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
        self.upstream_port = free_port(socket.SOCK_STREAM)
        self.local_port = free_port(socket.SOCK_STREAM)
        self.exchange_tcp = free_port(socket.SOCK_STREAM)
        self.exchange_quic = free_port(socket.SOCK_DGRAM)
        self.upstream: Upstream | None = None
        self.private = ["orders", "tunnel"]
        self.client_token, client_digest = token("client")
        self.server_token, server_digest = token("server")
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
  - credential_id: client
    token_sha256: \"{client_digest}\"
    peer_id: \"{self.client_peer}\"
    tenant: test
    role: client
    scopes: [open_proxy_stream]
    quota_profile: standard
    not_before: {now - 60}
    expires_at: {now + 3600}
    revoked: false
  - credential_id: server
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
        idle = 1_000 if self.case == "idle-timeout" else 300_000
        connect = self.upstream_port
        if self.case == "upstream-refused":
            connect = free_port(socket.SOCK_STREAM)
            self.upstream_port = connect
        self.services = self.secret / "services.yaml"
        self.services.write_text(
            f"""schema_version: 1
registration:
  requested_lease_seconds: 30
  refresh_seconds: 10
services:
  - upstream_id: orders
    selector:
      protocol: tcp
      metadata: {{service: orders}}
    enabled: true
    connect: 127.0.0.1:{connect}
    connect_timeout_ms: 3000
    idle_timeout_ms: {idle}
    concurrency_limit: 64
proxy:
  max_workers: 256
  max_workers_per_client: 32
  max_upstream_dials: 64
  copy_buffer_bytes: 32768
  max_replay_entries: 8192
  ticket_clock_skew: 5
"""
        )
        direct = 0 if self.case.endswith("-relay") else 1500
        self.routes = self.secret / "routes.yaml"
        self.routes.write_text(
            f"""schema_version: 1
network:
  direct_preference_ms: {direct}
  connection_setup_timeout_ms: 20000
targets:
  - route_id: orders
    selector:
      protocol: tcp
      metadata: {{service: orders}}
raw_tcp:
  - name: orders-local
    bind: 127.0.0.1:{self.local_port}
    route_id: orders
limits:
  max_peer_states: 64
  max_pending_setups: 128
  max_pending_per_server: 64
  max_ingress_connections: 512
  max_streams_per_server: 128
  copy_buffer_bytes: 32768
"""
        )

    def start(self, name: str, argv: list[str], env: dict[str, str]) -> pathlib.Path:
        log = self.out / f"{name}.ndjson"
        handle = log.open("w")
        child_env = os.environ.copy()
        child_env.update(env)
        child_env["P2X_RUN_ID"] = f"tunnel-{self.case}"
        process = subprocess.Popen(argv, cwd=self.root, env=child_env, stdout=handle, stderr=subprocess.STDOUT)
        self.processes.append((process, log, handle))
        return log

    def start_exchange(self) -> pathlib.Path:
        base = f"/ip4/127.0.0.1/tcp/{self.exchange_tcp}"
        advertised = base + f"/p2p/{self.exchange_peer}"
        return self.start(
            "exchange",
            [str(self.root / "target/debug/p2x-exchange"), "--identity-file", str(self.secret / "exchange.key"), "--credential-file", str(self.credentials), "--ticket-key-file", str(self.ticket_key), "--tcp-listen", base, "--quic-listen", f"/ip4/127.0.0.1/udp/{self.exchange_quic}/quic-v1", "--advertise", advertised, "--case-id", self.case],
            {},
        )

    def start_server(self, exchange: str) -> pathlib.Path:
        args = [str(self.root / "target/debug/p2x-server"), "--identity-file", str(self.secret / "server.key"), "--exchange", exchange, "--exchange-peer-id", self.exchange_peer, "--credential-env", "P2X_TOKEN", "--ticket-verification-keys-file", str(self.verification_keys), "--services-file", str(self.services), "--case-id", self.case]
        env = {"P2X_TOKEN": self.server_token}
        if self.case == "upstream-timeout":
            args += ["--test-hold-upstream-dial-ms", "4000"]
            env["P2X_ENABLE_TEST_HOOKS"] = "1"
        return self.start("server", args, env)

    def start_client(self, exchange: str, name: str = "client") -> pathlib.Path:
        return self.start(
            name,
            [str(self.root / "target/debug/p2x-client"), "--identity-file", str(self.secret / "client.key"), "--exchange", exchange, "--exchange-peer-id", self.exchange_peer, "--credential-env", "P2X_TOKEN", "--routes-file", str(self.routes), "--case-id", self.case],
            {"P2X_TOKEN": self.client_token},
        )

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
        if self.upstream is not None:
            self.upstream.close()
        import shutil
        shutil.rmtree(self.secret, ignore_errors=True)


def one_terminal(path: pathlib.Path) -> dict:
    terminals = [row for row in read_rows(path) if row.get("event") == "terminal"]
    if len(terminals) != 1:
        raise Failure(f"{path.name}: expected one terminal, got {len(terminals)}")
    return terminals[0]


def run_case(root: pathlib.Path, case: str) -> None:
    run = Run(root, case)
    exchange_log = server_log = client_log = None
    try:
        if case not in {"upstream-refused", "upstream-timeout"}:
            mode = "half-close" if case.startswith("half-close") else "idle" if case == "idle-timeout" else "echo"
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
        client = socket.create_connection(("127.0.0.1", run.local_port), timeout=20)
        client.settimeout(20)
        if case.startswith("half-close"):
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
            if client.recv(1) != b"":
                raise Failure("idle tunnel returned application data")
        elif case == "upstream-refused":
            if client.recv(1) != b"":
                raise Failure("refused upstream forwarded bytes")
        elif case == "upstream-timeout":
            if client.recv(1) != b"":
                raise Failure("timed-out upstream forwarded bytes")
        else:
            payload = (b"p2x-tunnel-sentinel-" + secrets.token_bytes(32))
            client.sendall(payload)
            data = bytearray()
            while len(data) < len(payload):
                data.extend(client.recv(len(payload) - len(data)))
            if bytes(data) != payload:
                raise Failure("echo payload mismatch")
            selected = [row.get("selected_path") for row in read_rows(client_log) if row.get("event") == "path_selected"]
            expected_path = "relay" if case.endswith("-relay") else "direct"
            if expected_path not in selected:
                raise Failure(f"expected {expected_path} selected path, saw {selected}")
        client.close()
        time.sleep(0.3)
        all_output = "\n".join(path.read_text(errors="replace") for _, path, _ in run.processes)
        server_rows = read_rows(server_log)
        if case == "upstream-refused" and not any(row.get("code") == "upstream.connect_failed" and not row.get("authorized") for row in server_rows):
            raise Failure("upstream refusal was not classified")
        if case == "upstream-timeout" and not any(row.get("code") == "upstream.connect_timeout" and not row.get("authorized") for row in server_rows):
            raise Failure("upstream timeout was not classified")
        for marker in [run.client_token, run.server_token, "raw_ticket", "token_secret", "session_id", "127.0.0.1:" + str(run.upstream_port)]:
            if marker in all_output:
                raise Failure(f"privacy scan found {marker}")
        run.stop(client_log)
        run.stop(server_log)
        run.stop(exchange_log)
        summary = {"case": case, "passed": True, "observed_assertions": {"accepted_and_opaque_bytes": case not in {"upstream-refused", "upstream-timeout", "idle-timeout"}, "upstream_failure_or_idle": case in {"upstream-refused", "upstream-timeout", "idle-timeout"}, "privacy_scan_clean": True}}
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
