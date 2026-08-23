#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
case_name=""
while (($#)); do
  case "$1" in
    --case) case_name="${2:?missing case}"; shift 2 ;;
    *) echo "usage: $0 --case <name|all>" >&2; exit 2 ;;
  esac
done
[[ -n "$case_name" ]] || { echo "--case is required" >&2; exit 2; }

cases=(
  resolve-ticket-tcp resolve-ticket-quic unknown-selector offline-selector cross-tenant
  idempotent-resolve forced-relay direct-preferred direct-open-fallback ticket-replay
  ticket-bindings ticket-expiry registration-revision-change connection-reuse
  concurrent-opens resolve-limit proxy-limit exchange-restart server-restart graceful-drain
)
if [[ "$case_name" == all ]]; then
  cd "$root"
  cargo build -q --workspace --bins
  cargo build -q -p p2x-config --example identity-id --example ticket-verification
  for case in "${cases[@]}"; do
    P2X_RESOLUTION_BUILT=1 "$0" --case "$case"
  done
  exit 0
fi
valid=false
for case in "${cases[@]}"; do
  if [[ "$case_name" == "$case" ]]; then
    valid=true
    break
  fi
done
[[ "$valid" == true ]] || { echo "unknown resolution case: $case_name" >&2; exit 2; }

cd "$root"
if [[ "${P2X_RESOLUTION_BUILT:-}" != 1 ]]; then
  cargo build -q --workspace --bins
  cargo build -q -p p2x-config --example identity-id --example ticket-verification
fi

python3 - "$root" "$case_name" <<'PY'
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
import tempfile
import time

root = pathlib.Path(sys.argv[1])
case = sys.argv[2]
bin_dir = root / "target" / "debug"
identity = bin_dir / "examples" / "identity-id"
ring_generator = bin_dir / "examples" / "ticket-verification"

# ponytail: the CLI currently exposes one finite empty-Authorized open; add a
# dedicated fault injector before promoting the remaining matrix cases.
SUPPORTED = {
    "resolve-ticket-tcp": ("tcp", "success"),
    "resolve-ticket-quic": ("quic", "success"),
    "unknown-selector": ("tcp", "not_found"),
    "cross-tenant": ("tcp", "not_found"),
    "offline-selector": ("tcp", "offline"),
    "forced-relay": ("tcp", "success_relay"),
    "direct-preferred": ("tcp", "success_direct"),
}
if case not in SUPPORTED:
    print(
        f"resolution case '{case}' is incomplete: the current product CLI has no "
        "ticket-replay, revision, concurrency, restart, or offline fault injector",
        file=sys.stderr,
    )
    raise SystemExit(2)

class CaseFailure(RuntimeError):
    pass


def rows(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    result = []
    for line in path.read_text(errors="replace").splitlines():
        try:
            result.append(json.loads(line))
        except json.JSONDecodeError:
            raise CaseFailure(f"invalid lifecycle JSON in {path}: {line!r}")
    return result


def free_port(kind: int) -> int:
    sock = socket.socket(socket.AF_INET, kind)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def token(name: str) -> tuple[str, str]:
    raw = secrets.token_bytes(32)
    value = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    digest = hashlib.sha256(b"p2x-fixed-token-v1\0" + raw).digest()
    encoded_digest = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return f"p2x1.{name}.{value}", encoded_digest


def wait_for(path: pathlib.Path, predicate, timeout: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in rows(path):
            if predicate(row):
                return row
        time.sleep(0.05)
    tail = "\n".join(path.read_text(errors="replace").splitlines()[-20:]) if path.exists() else "<missing>"
    raise CaseFailure(f"timeout waiting for {path.name};\n{tail}")


class Run:
    def __init__(self) -> None:
        run_id = os.environ.get("P2X_RUN_ID", time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
        self.out = root / "target" / "p2x-resolution" / run_id / case
        self.out.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="p2x-resolution-")
        self.secret = pathlib.Path(self.temp.name)
        self.processes: list[tuple[subprocess.Popen, pathlib.Path, object]] = []
        self.private = ["orders", "missing", "test", "other"]
        self.exchange_peer = self.make_identity("exchange")
        self.server_peer = self.make_identity("server")
        self.client_peer = self.make_identity("client")
        self.exchange_tcp = free_port(socket.SOCK_STREAM)
        self.exchange_quic = free_port(socket.SOCK_DGRAM)
        self.exchange_base = (
            f"/ip4/127.0.0.1/udp/{self.exchange_quic}/quic-v1"
            if SUPPORTED[case][0] == "quic"
            else f"/ip4/127.0.0.1/tcp/{self.exchange_tcp}"
        )
        self.exchange_address = None
        self.client_token, client_digest = token("client")
        self.server_token, server_digest = token("server")
        now = int(time.time())
        self.ticket_key = self.secret / "ticket.key"
        self.ticket_key.write_bytes(b"\x01" + secrets.token_bytes(32))
        self.ticket_key.chmod(0o600)
        self.verification_keys = self.secret / "verification-keys.yaml"
        subprocess.run(
            [str(ring_generator), str(self.ticket_key), str(self.verification_keys)],
            check=True,
            stdout=subprocess.DEVNULL,
        )
        self.verification_keys.chmod(0o600)
        self.credentials = self.secret / "credentials.yaml"
        client_tenant = "other" if SUPPORTED[case][1] == "not_found" and case == "cross-tenant" else "test"
        self.private.append(client_tenant)
        self.credentials.write_text(
            f"""schema_version: 1
authorization_revision: 1
credentials:
  - credential_id: client
    token_sha256: \"{client_digest}\"
    peer_id: \"{self.client_peer}\"
    tenant: {client_tenant}
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
        self.services = self.secret / "services.yaml"
        enabled = "false" if case == "offline-selector" else "true"
        self.services.write_text(
            f"""schema_version: 1
registration:
  requested_lease_seconds: 30
  refresh_seconds: 10
services:
  - upstream_id: orders
    selector:
      protocol: http
      metadata: {{service: orders}}
    enabled: {enabled}
"""
        )
        selector = "missing" if case == "unknown-selector" else "orders"
        direct_preference = 0 if case == "forced-relay" else 1500
        self.routes = self.secret / "routes.yaml"
        self.routes.write_text(
            f"""schema_version: 1
network:
  direct_preference_ms: {direct_preference}
  connection_setup_timeout_ms: 20000
targets:
  - route_id: orders
    selector:
      protocol: http
      metadata: {{service: {selector}}}
limits:
  max_peer_states: 64
  max_pending_setups: 128
  max_pending_per_server: 64
"""
        )

    def make_identity(self, name: str) -> str:
        path = self.secret / f"{name}.key"
        return subprocess.check_output([str(identity), str(path), "--generate"], text=True).strip()

    def start(self, name: str, argv: list[str], env: dict[str, str] | None = None) -> pathlib.Path:
        log = self.out / f"{name}.ndjson"
        handle = log.open("w")
        child_env = os.environ.copy()
        child_env["P2X_RUN_ID"] = f"resolution-{case}"
        if env:
            child_env.update(env)
        process = subprocess.Popen(argv, cwd=root, env=child_env, stdout=handle, stderr=subprocess.STDOUT)
        self.processes.append((process, log, handle))
        return log

    def stop(self, log: pathlib.Path, graceful: bool = True) -> None:
        for process, path, handle in self.processes:
            if path != log or process.poll() is not None:
                continue
            process.send_signal(signal.SIGINT if graceful else signal.SIGKILL)
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            handle.close()
            return

    def cleanup(self) -> None:
        for process, _, handle in reversed(self.processes):
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
        deadline = time.monotonic() + 12
        for process, _, handle in reversed(self.processes):
            remaining = max(0.1, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            if not handle.closed:
                handle.close()
        self.temp.cleanup()


def assert_one_terminal(log: pathlib.Path) -> dict:
    terminal = [row for row in rows(log) if row.get("event") == "terminal"]
    if len(terminal) != 1:
        raise CaseFailure(f"{log.name}: expected one terminal, got {len(terminal)}")
    return terminal[0]


def finish(run: Run, expected: str, client_log: pathlib.Path, server_log: pathlib.Path, exchange_log: pathlib.Path) -> None:
    client_rows = rows(client_log)
    server_rows = rows(server_log)
    exchange_rows = rows(exchange_log)
    terminal = assert_one_terminal(client_log)
    if terminal.get("code") != expected:
        raise CaseFailure(f"client expected {expected}, got {terminal.get('code')}")
    resolution_client = [row for row in client_rows if row.get("event") == "resolution_outcome"]
    resolution_exchange = [row for row in exchange_rows if row.get("event") == "resolution_outcome"]
    if len(resolution_client) != 1 or len(resolution_exchange) != 1:
        raise CaseFailure(f"resolution outcome cardinality: client={len(resolution_client)} exchange={len(resolution_exchange)}")
    if resolution_client[0].get("request_id_hash") != resolution_exchange[0].get("request_id_hash"):
        raise CaseFailure("client/exchange resolution correlation mismatch")
    if expected == "proxy.authorized":
        if not resolution_client[0].get("resolved") or not resolution_client[0].get("ticket_issued"):
            raise CaseFailure("successful resolution did not report a ticketed grant")
        client_auth = [row for row in client_rows if row.get("event") == "proxy_authorization" and row.get("authorized")]
        server_auth = [row for row in server_rows if row.get("event") == "proxy_authorization" and row.get("authorized")]
        if len(client_auth) != 1 or len(server_auth) != 1:
            raise CaseFailure(f"proxy authorization cardinality: client={len(client_auth)} server={len(server_auth)}")
        if (client_auth[0].get("request_id_hash"), client_auth[0].get("stream_id_hash")) != (
            server_auth[0].get("request_id_hash"), server_auth[0].get("stream_id_hash")
        ):
            raise CaseFailure("client/server authorization correlation mismatch")
        selected = [row for row in client_rows if row.get("event") == "path_selected"]
        if len(selected) != 1:
            raise CaseFailure(f"expected one selected path, got {len(selected)}")
        if selected[0].get("connection_id_hash") != client_auth[0].get("connection_id_hash"):
            raise CaseFailure("authorized connection differs from selected connection")
        mode = SUPPORTED[case][1]
        if mode == "success_relay" and selected[0].get("selected_path") != "relay":
            raise CaseFailure(f"forced relay selected {selected[0].get('selected_path')}")
        if mode == "success_direct" and selected[0].get("selected_path") != "direct":
            raise CaseFailure(f"direct-preferred selected {selected[0].get('selected_path')}")
        if not any(row.get("event") == "registry_transition" and row.get("code") == "registry.registered" for row in exchange_rows):
            raise CaseFailure("server registration was not observed")
    else:
        if resolution_client[0].get("resolved") or resolution_exchange[0].get("resolved"):
            raise CaseFailure("rejected resolution was reported as resolved")
        if resolution_client[0].get("code") != expected or resolution_exchange[0].get("code") != expected:
            raise CaseFailure("client/exchange resolution code mismatch")
    forbidden = [run.client_token, run.server_token, "token_secret", "raw_ticket", "session_id"] + run.private
    output = "\n".join(path.read_text(errors="replace") for _, path, _ in run.processes)
    if any(marker and marker in output for marker in forbidden):
        raise CaseFailure("privacy scan found credentials, session data, ticket data, or selector values")
    summary = {
        "case": case,
        "passed": True,
        "observed_assertions": {
            "client_terminal": expected,
            "client_exchange_resolution_correlated": True,
            "server_authorization_correlated": expected == "proxy.authorized",
            "exact_selected_connection": expected == "proxy.authorized",
            "privacy_scan_clean": True,
        },
    }
    (run.out / "summary.json").write_text(json.dumps(summary, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True), flush=True)


run = Run()
exchange_log = server_log = client_log = None
try:
    transport, expected_mode = SUPPORTED[case]
    exchange_log = run.start(
        "exchange",
        [
            str(bin_dir / "p2x-exchange"),
            "--identity-file", str(run.secret / "exchange.key"),
            "--credential-file", str(run.credentials),
            "--ticket-key-file", str(run.ticket_key),
            "--tcp-listen", f"/ip4/127.0.0.1/tcp/{run.exchange_tcp}",
            "--quic-listen", f"/ip4/127.0.0.1/udp/{run.exchange_quic}/quic-v1",
            "--advertise", run.exchange_base + f"/p2p/{run.exchange_peer}",
            "--case-id", case,
        ],
    )
    listen = wait_for(
        exchange_log,
        lambda row: row.get("event") == "listener_ready"
        and ((transport == "quic" and "/quic-v1" in row.get("address", "")) or (transport == "tcp" and "/tcp/" in row.get("address", ""))),
    )
    run.exchange_address = listen["address"]
    server_log = run.start(
        "server",
        [
            str(bin_dir / "p2x-server"),
            "--identity-file", str(run.secret / "server.key"),
            "--exchange", run.exchange_address,
            "--exchange-peer-id", run.exchange_peer,
            "--credential-env", "P2X_TOKEN",
            "--ticket-verification-keys-file", str(run.verification_keys),
            "--services-file", str(run.services),
            "--case-id", case,
        ],
        {"P2X_TOKEN": run.server_token},
    )
    wait_for(server_log, lambda row: row.get("event") == "server_readiness" and row.get("ready") is True, 45)
    wait_for(exchange_log, lambda row: row.get("event") == "registry_transition" and row.get("code") == "registry.registered", 15)
    client_log = run.start(
        "client",
        [
            str(bin_dir / "p2x-client"),
            "--identity-file", str(run.secret / "client.key"),
            "--exchange", run.exchange_address,
            "--exchange-peer-id", run.exchange_peer,
            "--credential-env", "P2X_TOKEN",
            "--routes-file", str(run.routes),
            "--finite-proxy-check",
            "--case-id", case,
        ],
        {"P2X_TOKEN": run.client_token},
    )
    expected = {
        "not_found": "registry.not_found",
        "offline": "registry.offline",
    }.get(expected_mode, "proxy.authorized")
    terminal = wait_for(client_log, lambda row: row.get("event") == "terminal", 45)
    if terminal.get("code") != expected:
        raise CaseFailure(f"client expected {expected}, got {terminal.get('code')}")
    if expected == "proxy.authorized":
        wait_for(server_log, lambda row: row.get("event") == "proxy_authorization" and row.get("authorized") is True, 15)
    run.stop(client_log)
    run.stop(server_log)
    wait_for(exchange_log, lambda row: row.get("event") == "exchange_resources" and all(row.get(key) == 0 for key in ("sessions", "relay_admissions", "reservations", "circuits", "registrations", "selector_owners", "auth_requests", "registry_requests")), 15)
    run.stop(exchange_log)
    finish(run, expected, client_log, server_log, exchange_log)
except (CaseFailure, subprocess.CalledProcessError) as error:
    print(f"resolution case '{case}' failed: {error}", file=sys.stderr)
    raise SystemExit(1)
finally:
    run.cleanup()
PY
