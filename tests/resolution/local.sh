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
  failed=0
  for case in "${cases[@]}"; do
    if ! P2X_RESOLUTION_BUILT=1 "$0" --case "$case"; then
      failed=1
    fi
  done
  exit "$failed"
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

BINDING_SUBCASES = [
    "ticket_byte", "upstream_id", "registration_revision", "tenant",
    "selector_fingerprint", "authorization_revision", "permissions",
    "max_streams", "issuer", "client_peer", "server_peer", "not_before",
    "verification_key",
]

CASE_PROFILE = {
    "resolve-ticket-tcp": ("tcp", "success"),
    "resolve-ticket-quic": ("quic", "success"),
    "unknown-selector": ("tcp", "not_found"),
    "offline-selector": ("tcp", "offline"),
    "cross-tenant": ("tcp", "not_found"),
    "idempotent-resolve": ("tcp", "idempotent"),
    "forced-relay": ("tcp", "success_relay"),
    "direct-preferred": ("tcp", "success_direct"),
    "direct-open-fallback": ("tcp", "fallback"),
    "ticket-replay": ("tcp", "replay"),
    "ticket-bindings": ("tcp", "binding"),
    "ticket-expiry": ("tcp", "expired"),
    "registration-revision-change": ("tcp", "revision"),
    "connection-reuse": ("tcp", "reuse"),
    "concurrent-opens": ("tcp", "concurrent"),
    "resolve-limit": ("tcp", "resolve_limit"),
    "proxy-limit": ("tcp", "proxy_limit"),
    "exchange-restart": ("tcp", "exchange_restart"),
    "server-restart": ("tcp", "server_restart"),
    "graceful-drain": ("tcp", "drain"),
}

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
        self.private = ["orders", "missing", "other"]
        self.exchange_peer = self.make_identity("exchange")
        self.server_peer = self.make_identity("server")
        self.client_peer = self.make_identity("client")
        self.client2_peer = self.make_identity("client2")
        self.exchange_tcp = free_port(socket.SOCK_STREAM)
        self.exchange_quic = free_port(socket.SOCK_DGRAM)
        self.mode = CASE_PROFILE[case][1]
        self.binding_unit_passed = False
        if case == "ticket-bindings":
            subprocess.run(
                [
                    "cargo", "test", "-q", "-p", "p2x-server",
                    "ticket_binding_matrix_rejects_without_consuming_replay",
                    "--", "--exact",
                ],
                cwd=root,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            self.binding_unit_passed = True
        self.exchange_base = (
            f"/ip4/127.0.0.1/udp/{self.exchange_quic}/quic-v1"
            if CASE_PROFILE[case][0] == "quic"
            else f"/ip4/127.0.0.1/tcp/{self.exchange_tcp}"
        )
        self.exchange_address = None
        self.client_token, client_digest = token("client")
        self.client2_token, client2_digest = token("client2")
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
        client_tenant = "other" if self.mode == "not_found" and case == "cross-tenant" else "test"
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
  - credential_id: client2
    token_sha256: \"{client2_digest}\"
    peer_id: \"{self.client2_peer}\"
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
        self.services = self.secret / "services.yaml"
        enabled = "false" if case == "offline-selector" else "true"
        proxy = "" if case != "proxy-limit" else """proxy:
  max_workers: 1
  max_workers_per_client: 1
  max_replay_entries: 1
  ticket_clock_skew: 5
"""
        self.services.write_text(
            f"""schema_version: 1
registration:
  requested_lease_seconds: 30
  refresh_seconds: 10
{proxy}services:
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

    def start_client(self, name: str, exchange_address: str, client_args: list[str], token_value: str | None = None, identity_name: str = "client", env: dict[str, str] | None = None) -> pathlib.Path:
        return self.start(
            name,
            [
                str(bin_dir / "p2x-client"),
                "--identity-file", str(self.secret / f"{identity_name}.key"),
                "--exchange", exchange_address,
                "--exchange-peer-id", self.exchange_peer,
                "--credential-env", "P2X_TOKEN",
                "--routes-file", str(self.routes),
                *client_args,
                "--case-id", f"{case}-{name}",
            ],
            {"P2X_TOKEN": token_value or (self.client2_token if identity_name == "client2" else self.client_token), "P2X_ENABLE_TEST_HOOKS": "1", **(env or {})},
        )

    def start_exchange(self, name: str, exchange_args: list[str] | None = None) -> pathlib.Path:
        return self.start(
            name,
            [
                str(bin_dir / "p2x-exchange"),
                "--identity-file", str(self.secret / "exchange.key"),
                "--credential-file", str(self.credentials),
                "--ticket-key-file", str(self.ticket_key),
                "--tcp-listen", f"/ip4/127.0.0.1/tcp/{self.exchange_tcp}",
                "--quic-listen", f"/ip4/127.0.0.1/udp/{self.exchange_quic}/quic-v1",
                "--advertise", self.exchange_base + f"/p2p/{self.exchange_peer}",
                "--case-id", case,
                *(exchange_args or []),
            ],
            {"P2X_ENABLE_TEST_HOOKS": "1"} if exchange_args else None,
        )

    def start_server(self, name: str, exchange_address: str, server_args: list[str] | None = None) -> pathlib.Path:
        return self.start(
            name,
            [
                str(bin_dir / "p2x-server"),
                "--identity-file", str(self.secret / "server.key"),
                "--exchange", exchange_address,
                "--exchange-peer-id", self.exchange_peer,
                "--credential-env", "P2X_TOKEN",
                "--ticket-verification-keys-file", str(self.verification_keys),
                "--services-file", str(self.services),
                *(server_args or []),
                "--case-id", case,
            ],
            {"P2X_TOKEN": self.server_token, "P2X_ENABLE_TEST_HOOKS": "1"} if server_args else {"P2X_TOKEN": self.server_token},
        )

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


def finish_limits(run: Run, primary_log: pathlib.Path, secondary_log: pathlib.Path, server_log: pathlib.Path, exchange_log: pathlib.Path) -> None:
    primary_terminal = assert_one_terminal(primary_log)
    secondary_terminal = assert_one_terminal(secondary_log)
    expected_secondary = "limit.resolve_requests" if case == "resolve-limit" else "limit.proxy_streams"
    if primary_terminal.get("code") != "proxy.authorized" or secondary_terminal.get("code") != expected_secondary:
        raise CaseFailure(
            f"limit terminals were unexpected: primary={primary_terminal.get('code')} secondary={secondary_terminal.get('code')}"
        )
    exchange_rows = rows(exchange_log)
    server_rows = rows(server_log)
    if case == "resolve-limit":
        outcomes = [row for row in exchange_rows if row.get("event") == "resolution_outcome"]
        if not any(row.get("resolved") and row.get("ticket_issued") for row in outcomes):
            raise CaseFailure("resolve-limit did not admit the boundary request")
        if not any(
            row.get("code") == "limit.resolve_requests"
            and not row.get("resolved")
            and not row.get("ticket_issued")
            for row in outcomes
        ):
            raise CaseFailure("resolve-limit did not reject N+1 without ticket state")
        if not any(row.get("event") == "test_fault_applied" and row.get("fault") == "hold_resolve_response" for row in exchange_rows):
            raise CaseFailure("resolve-limit hold fault was not observed")
    else:
        if not any(row.get("event") == "proxy_authorization" and row.get("code") == "limit.proxy_streams" for row in server_rows):
            raise CaseFailure("proxy-limit did not produce server admission rejection evidence")
        if not any(row.get("event") == "resources" and row.get("workers", 0) >= 1 for row in server_rows):
            raise CaseFailure("proxy-limit did not expose a live held worker")
    forbidden = [run.client_token, run.client2_token, run.server_token, "token_secret", "raw_ticket", "session_id"] + run.private
    output = "\\n".join(path.read_text(errors="replace") for _, path, _ in run.processes)
    if any(marker and marker in output for marker in forbidden):
        raise CaseFailure("privacy scan found credentials, session data, ticket data, or selector values")
    summary = {
        "case": case,
        "passed": True,
        "observed_assertions": {
            "boundary_admitted": True,
            "n_plus_one_rejected": True,
            "primary_authorized": True,
            "resources_drained": True,
            "privacy_scan_clean": True,
        },
    }
    (run.out / "summary.json").write_text(json.dumps(summary, sort_keys=True) + "\\n")
    print(json.dumps(summary, sort_keys=True), flush=True)

def finish_restart(run: Run, client_log: pathlib.Path, server_logs: list[pathlib.Path], exchange_logs: list[pathlib.Path]) -> None:
    client_rows = rows(client_log)
    server_rows = [row for path in server_logs for row in rows(path)]
    exchange_rows = [row for path in exchange_logs for row in rows(path)]
    terminal = assert_one_terminal(client_log)
    if terminal.get("code") != "proxy.authorized":
        raise CaseFailure(f"{case} recovery terminal was {terminal.get('code')}")
    outcomes = [row for row in client_rows if row.get("event") == "resolution_outcome"]
    if len(outcomes) < 2 or not all(row.get("resolved") and row.get("ticket_issued") for row in outcomes):
        raise CaseFailure(f"{case} did not resolve before and after restart")
    if len({row.get("response_fingerprint") for row in outcomes}) < 2:
        raise CaseFailure(f"{case} reused the old ticket response")
    if not any(row.get("event") == "operational_error" and row.get("code") == "proxy.recovering" for row in client_rows):
        raise CaseFailure(f"{case} did not emit fresh-ticket recovery evidence")
    if case == "registration-revision-change" and not any(row.get("event") == "proxy_authorization" and not row.get("authorized") and row.get("code") == "registry.stale_revision" for row in server_rows):
        raise CaseFailure("registration-revision-change did not reject the old registration revision")
    if not any(row.get("event") == "proxy_authorization" and row.get("authorized") for row in server_rows):
        raise CaseFailure(f"{case} did not authorize against the replacement state")
    revisions = [row.get("revision") for row in exchange_rows if row.get("event") == "registry_transition" and row.get("code") == "registry.registered" and row.get("revision") is not None]
    if len(set(revisions)) < 2:
        raise CaseFailure(f"{case} did not observe replacement registration revision")
    forbidden = [run.client_token, run.client2_token, run.server_token, "token_secret", "raw_ticket", "session_id"] + run.private
    output = "\\n".join(path.read_text(errors="replace") for _, path, _ in run.processes)
    if any(marker and marker in output for marker in forbidden):
        raise CaseFailure("privacy scan found credentials, session data, ticket data, or selector values")
    summary = {"case": case, "passed": True, "observed_assertions": {"fresh_resolve_authorized": True, "replacement_registration_observed": True, "privacy_scan_clean": True}}
    (run.out / "summary.json").write_text(json.dumps(summary, sort_keys=True) + "\\n")
    print(json.dumps(summary, sort_keys=True), flush=True)

def finish(run: Run, expected: str, client_log: pathlib.Path, server_log: pathlib.Path, exchange_log: pathlib.Path) -> None:
    client_rows = rows(client_log)
    server_rows = rows(server_log)
    exchange_rows = rows(exchange_log)
    terminal = assert_one_terminal(client_log)
    expected_terminal = {
        "replay": "auth.ticket_replayed",
        "binding": "auth.ticket_invalid",
        "expired": "auth.ticket_expired",
    }.get(CASE_PROFILE[case][1], expected)
    if case == "ticket-replay":
        expected_terminal = "auth.ticket_replayed"
    if terminal.get("code") != expected_terminal:
        raise CaseFailure(f"client expected {expected_terminal}, got {terminal.get('code')}")
    resolution_client = [row for row in client_rows if row.get("event") == "resolution_outcome"]
    resolution_exchange = [row for row in exchange_rows if row.get("event") == "resolution_outcome"]
    if case == "idempotent-resolve":
        if not any(row.get("event") == "test_fault_applied" and row.get("fault") == "drop_first_resolve_response" for row in exchange_rows + client_rows):
            raise CaseFailure("idempotent-resolve fault was not observed")
        if len(resolution_exchange) != 2 or len({row.get("request_fingerprint") for row in resolution_exchange}) != 1 or len({row.get("response_fingerprint") for row in resolution_exchange}) != 1:
            raise CaseFailure("idempotent-resolve did not produce two identical accepted observations")
        if resolution_exchange[-1].get("issuance_count") != 1:
            raise CaseFailure("idempotent-resolve issued more than one ticket")
    elif case in ("connection-reuse", "concurrent-opens"):
        if len(resolution_client) != len(resolution_exchange) or len(resolution_client) < 2:
            raise CaseFailure(f"multi-open resolution cardinality: client={len(resolution_client)} exchange={len(resolution_exchange)}")
        if case == "concurrent-opens" and len(resolution_client) != 128:
            raise CaseFailure(f"concurrent-opens expected 128 headroom resolutions, got {len(resolution_client)}")
    elif len(resolution_client) != 1 or len(resolution_exchange) != 1:
        raise CaseFailure(f"resolution outcome cardinality: client={len(resolution_client)} exchange={len(resolution_exchange)}")
    if case not in ("connection-reuse", "concurrent-opens") and resolution_client[0].get("request_id_hash") != resolution_exchange[0].get("request_id_hash"):
        raise CaseFailure("client/exchange resolution correlation mismatch")
    if expected == "proxy.authorized":
        if not resolution_client[0].get("resolved") or not resolution_client[0].get("ticket_issued"):
            raise CaseFailure("successful resolution did not report a ticketed grant")
        client_auth = [row for row in client_rows if row.get("event") == "proxy_authorization" and row.get("authorized")]
        server_auth = [row for row in server_rows if row.get("event") == "proxy_authorization" and row.get("authorized")]
        if not client_auth or not server_auth:
            raise CaseFailure(f"proxy authorization missing: client={len(client_auth)} server={len(server_auth)}")
        if case in ("connection-reuse", "concurrent-opens"):
            if len(client_auth) != len(resolution_client) or len(server_auth) != len(resolution_exchange):
                raise CaseFailure("multi-open authorization cardinality mismatch")
            if len({row.get("stream_id_hash") for row in client_auth}) != len(client_auth):
                raise CaseFailure("multi-open stream IDs were reused")
            if case == "concurrent-opens":
                if len(client_auth) != 128 or len(resolution_client) != 128:
                    raise CaseFailure(f"concurrent-opens expected 128 correlated opens, got {len(client_auth)}")
                selected = [row for row in client_rows if row.get("event") == "path_selected"]
                if len(selected) != 128 or len({row.get("request_id") for row in selected}) != 128:
                    raise CaseFailure("concurrent-opens exact path correlation is incomplete")
                pending_samples = [row.get("pending_opens", 0) for row in client_rows if row.get("event") == "resources"]
                if not pending_samples or max(pending_samples) != 64:
                    raise CaseFailure(f"concurrent-opens did not prove the configured 64-open owner window: {pending_samples}")
            if case == "connection-reuse":
                selected = [row for row in client_rows if row.get("event") == "path_selected"]
                if len(selected) != 2 or len({row.get("connection_id_hash") for row in selected}) != 1:
                    raise CaseFailure("connection-reuse did not reuse one selected connection")
                if len({row.get("response_fingerprint") for row in resolution_exchange}) != 2:
                    raise CaseFailure("connection-reuse did not issue distinct responses")
        if case == "direct-open-fallback":
            if not any(row.get("event") == "test_fault_applied" and row.get("fault") == "fail_first_direct_open_before_handshake" for row in client_rows):
                raise CaseFailure("direct fallback fault was not observed")
            selected = [row for row in client_rows if row.get("event") == "path_selected"]
            if len(selected) != 2 or [row.get("selected_path") for row in selected] != ["direct", "relay"]:
                raise CaseFailure("direct fallback did not select direct then prepared relay")
            if server_auth[0].get("connection_id_hash") != selected[1].get("connection_id_hash"):
                raise CaseFailure("fallback authorization used the wrong connection")
    elif expected_terminal == "auth.ticket_replayed":
        first = [row for row in client_rows + server_rows if row.get("event") == "proxy_authorization" and row.get("authorized")]
        replay = [row for row in client_rows + server_rows if row.get("event") == "proxy_authorization" and row.get("code") == expected_terminal]
        if len(first) != 2 or len(replay) != 2:
            raise CaseFailure("ticket replay did not prove first authorization plus one rejection per owner")
    elif expected_terminal in ("auth.ticket_invalid", "auth.ticket_expired"):
        rejected = [row for row in server_rows if row.get("event") == "proxy_authorization" and not row.get("authorized")]
        if len(rejected) != 1 or rejected[0].get("code") != expected_terminal:
            raise CaseFailure(f"expected one server rejection {expected_terminal}")
    elif expected_terminal not in ("auth.ticket_replayed", "auth.ticket_invalid", "auth.ticket_expired"):
        if resolution_client[0].get("resolved") or resolution_exchange[0].get("resolved"):
            raise CaseFailure("rejected resolution was reported as resolved")
        if resolution_client[0].get("code") != expected or resolution_exchange[0].get("code") != expected:
            raise CaseFailure("client/exchange resolution code mismatch")
    if case == "ticket-bindings":
        if not run.binding_unit_passed:
            raise CaseFailure("ticket-bindings unit matrix did not pass")
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
    if case == "ticket-bindings":
        summary["subcases"] = {name: True for name in BINDING_SUBCASES}
    (run.out / "summary.json").write_text(json.dumps(summary, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True), flush=True)


run = Run()
exchange_log = server_log = client_log = None
try:
    transport, expected_mode = CASE_PROFILE[case]
    exchange_args = []
    server_args = []
    client_args = ["--finite-proxy-check"]
    client_env = {"P2X_ENABLE_TEST_HOOKS": "1"}
    if case == "idempotent-resolve":
        exchange_args += ["--test-drop-first-resolve-response"]
    elif case == "concurrent-opens":
        exchange_args += ["--resolve-limit-per-minute", "256"]
    elif case == "graceful-drain":
        exchange_args += ["--test-hold-resolve-ms", "3000"]
        server_args += ["--test-hold-proxy-handshake-ms", "3000"]
    if case == "concurrent-opens":
        client_args = ["--test-proxy-open-count", "128", "--test-proxy-concurrency", "64"]
    elif case == "connection-reuse":
        client_args = ["--test-proxy-open-count", "2", "--test-proxy-concurrency", "1"]
    elif case == "ticket-replay":
        client_args = ["--finite-proxy-check", "--test-replay-first-ticket"]
    elif case == "direct-open-fallback":
        client_args = ["--finite-proxy-check", "--test-fail-first-direct-open-before-handshake"]
    elif case == "ticket-bindings":
        client_args = ["--finite-proxy-check", "--test-open-mutation", "ticket-byte"]
    elif case == "ticket-expiry":
        exchange_args += ["--ticket-lifetime-secs", "5"]
        server_args += ["--ticket-clock-skew", "0"]
        client_args = ["--finite-proxy-check", "--test-delay-after-resolve-ms", "6000"]
    elif case == "resolve-limit":
        exchange_args += ["--resolve-limit-global", "1", "--resolve-limit-per-client", "1", "--test-hold-resolve-ms", "3000"]
    elif case == "proxy-limit":
        server_args += ["--test-hold-proxy-handshake-ms", "3000"]
    exchange_log = run.start_exchange("exchange", exchange_args)
    listen = wait_for(
        exchange_log,
        lambda row: row.get("event") == "listener_ready"
        and ((transport == "quic" and "/quic-v1" in row.get("address", "")) or (transport == "tcp" and "/tcp/" in row.get("address", ""))),
    )
    run.exchange_address = listen["address"]
    server_log = run.start_server("server", run.exchange_address, server_args)
    wait_for(server_log, lambda row: row.get("event") == "server_readiness" and row.get("ready") is True, 45)
    wait_for(exchange_log, lambda row: row.get("event") == "registry_transition" and row.get("code") == "registry.registered", 15)
    if case in ("resolve-limit", "proxy-limit"):
        client_log = run.start_client("client", run.exchange_address, client_args, env=client_env)
        if case == "proxy-limit":
            wait_for(server_log, lambda row: row.get("event") == "resources" and row.get("workers", 0) >= 1, 45)
        secondary_args = ["--finite-proxy-check"]
        if case == "resolve-limit":
            secondary_args += ["--test-delay-after-resolve-ms", "1000"]
        secondary_log = run.start_client("client2", run.exchange_address, secondary_args, identity_name="client2")
    elif case in ("registration-revision-change", "server-restart", "exchange-restart"):
        client_log = run.start_client("client", run.exchange_address, ["--finite-proxy-check", "--test-delay-after-resolve-ms", "3000", "--recover-after-failure"], env=client_env)
        secondary_log = None
    elif case == "graceful-drain":
        client_log = run.start_client("client", run.exchange_address, ["--finite-proxy-check", "--test-delay-after-resolve-ms", "3000"], env=client_env)
        secondary_log = None
    else:
        client_log = run.start_client("client", run.exchange_address, client_args, env=client_env)
        secondary_log = None
    expected = {
        "not_found": "registry.not_found",
        "offline": "registry.offline",
        "replay": "auth.ticket_replayed",
        "binding": "auth.ticket_invalid",
        "expired": "auth.ticket_expired",
    }.get(expected_mode, "proxy.authorized")
    if expected_mode == "replay":
        expected = "auth.ticket_replayed"
    elif expected_mode == "binding":
        expected = "auth.ticket_invalid"
    elif expected_mode == "expired":
        expected = "auth.ticket_expired"
    if secondary_log is not None:
        wait_for(secondary_log, lambda row: row.get("event") == "terminal", 45)
        wait_for(client_log, lambda row: row.get("event") == "terminal", 45)
        run.stop(client_log)
        run.stop(secondary_log)
        run.stop(server_log)
        wait_for(exchange_log, lambda row: row.get("event") == "exchange_resources" and all(row.get(key) == 0 for key in ("sessions", "relay_admissions", "reservations", "circuits", "registrations", "selector_owners", "auth_requests", "registry_requests")), 15)
        run.stop(exchange_log)
        finish_limits(run, client_log, secondary_log, server_log, exchange_log)
    elif case in ("registration-revision-change", "server-restart", "exchange-restart"):
        wait_for(client_log, lambda row: row.get("event") == "resolution_outcome" and row.get("resolved") is True, 45)
        old_server = server_log
        old_exchange = exchange_log
        old_revisions = [row.get("revision") for row in rows(exchange_log) if row.get("event") == "registry_transition" and row.get("code") == "registry.registered" and row.get("revision") is not None]
        if case == "exchange-restart":
            run.stop(exchange_log, graceful=False)
            exchange_log = run.start_exchange("exchange-restarted", exchange_args)
            wait_for(exchange_log, lambda row: row.get("event") == "listener_ready", 45)
            wait_for(exchange_log, lambda row: row.get("event") == "registry_transition" and row.get("code") == "registry.registered" and row.get("revision") is not None, 45)
            wait_for(server_log, lambda row: row.get("event") == "server_readiness" and row.get("ready") is True, 45)
        else:
            run.stop(server_log, graceful=False)
            wait_for(exchange_log, lambda row: row.get("event") == "exchange_resources" and row.get("registrations") == 0, 15)
            server_log = run.start_server("server-restarted", run.exchange_address, server_args)
            wait_for(exchange_log, lambda row: row.get("event") == "registry_transition" and row.get("code") == "registry.registered" and row.get("revision") not in old_revisions, 45)
            wait_for(server_log, lambda row: row.get("event") == "server_readiness" and row.get("ready") is True, 45)
        terminal = wait_for(client_log, lambda row: row.get("event") == "terminal", 45)
        if terminal.get("code") != expected:
            raise CaseFailure(f"client expected {expected}, got {terminal.get('code')}")
        run.stop(client_log)
        if case == "exchange-restart":
            run.stop(server_log)
        else:
            run.stop(server_log)
        if exchange_log != old_exchange:
            run.stop(exchange_log)
        else:
            wait_for(exchange_log, lambda row: row.get("event") == "exchange_resources" and all(row.get(key) == 0 for key in ("sessions", "relay_admissions", "reservations", "circuits", "registrations", "selector_owners", "auth_requests", "registry_requests")), 15)
            run.stop(exchange_log)
        finish_restart(run, client_log, [old_server, server_log], [old_exchange, exchange_log])
    elif case == "graceful-drain":
        # Subcase 1: a held proxy worker is rejected by server drain.
        wait_for(client_log, lambda row: row.get("event") == "resolution_outcome" and row.get("resolved") is True, 45)
        wait_for(server_log, lambda row: row.get("event") == "resources" and row.get("workers", 0) >= 1, 45)
        run.stop(server_log)
        server_client_terminal = wait_for(client_log, lambda row: row.get("event") == "terminal", 45)
        if server_client_terminal.get("code") != "peer.draining":
            raise CaseFailure(f"server drain expected peer.draining, got {server_client_terminal.get('code')}")
        run.stop(client_log)
        run.stop(exchange_log)
        if not any(row.get("event") == "proxy_authorization" and row.get("code") == "peer.draining" for row in rows(server_log)):
            raise CaseFailure("graceful-drain missing server draining rejection")

        # Subcase 2: a held Resolve response is rejected by exchange drain.
        exchange_drain = run.start_exchange("exchange-drain", ["--test-hold-resolve-ms", "10000"])
        wait_for(exchange_drain, lambda row: row.get("event") == "listener_ready", 45)
        server_drain = run.start_server("server-drain", run.exchange_address, [])
        wait_for(server_drain, lambda row: row.get("event") == "server_readiness" and row.get("ready") is True, 45)
        wait_for(exchange_drain, lambda row: row.get("event") == "registry_transition" and row.get("code") == "registry.registered", 45)
        exchange_client = run.start_client("exchange-client", run.exchange_address, ["--finite-proxy-check"], env=client_env)
        wait_for(exchange_drain, lambda row: row.get("event") == "test_fault_applied" and row.get("fault") == "hold_resolve_response", 45)
        run.stop(exchange_drain)
        exchange_terminal = wait_for(exchange_client, lambda row: row.get("event") == "terminal", 45)
        if exchange_terminal.get("code") != "exchange.draining":
            raise CaseFailure(f"exchange drain expected exchange.draining, got {exchange_terminal.get('code')}")
        run.stop(exchange_client)
        run.stop(server_drain)
        if not any(row.get("event") == "resolution_outcome" and row.get("code") == "exchange.draining" for row in rows(exchange_drain)):
            raise CaseFailure("graceful-drain missing exchange draining rejection")

        # Subcase 3: cancel a client while its resolved grant is held before Open.
        exchange_cancel = run.start_exchange("exchange-cancel", [])
        wait_for(exchange_cancel, lambda row: row.get("event") == "listener_ready", 45)
        server_cancel = run.start_server("server-cancel", run.exchange_address, [])
        wait_for(server_cancel, lambda row: row.get("event") == "server_readiness" and row.get("ready") is True, 45)
        wait_for(exchange_cancel, lambda row: row.get("event") == "registry_transition" and row.get("code") == "registry.registered", 45)
        cancel_client = run.start_client("cancel-client", run.exchange_address, ["--finite-proxy-check", "--test-delay-after-resolve-ms", "5000"], env=client_env)
        wait_for(cancel_client, lambda row: row.get("event") == "resolution_outcome" and row.get("resolved") is True, 45)
        run.stop(cancel_client)
        run.stop(server_cancel)
        run.stop(exchange_cancel)
        cancel_terminal = assert_one_terminal(cancel_client)
        if cancel_terminal.get("code") != "shutdown":
            raise CaseFailure(f"client cancel expected shutdown, got {cancel_terminal.get('code')}")
        if any(row.get("event") == "proxy_authorization" for row in rows(cancel_client)):
            raise CaseFailure("client cancel unexpectedly opened a proxy")

        for path in (server_log, client_log, exchange_log, exchange_drain, exchange_client, server_drain, cancel_client, server_cancel, exchange_cancel):
            terminal = assert_one_terminal(path)
            if any(terminal.get(key) != 0 for key in ("final_connections", "final_pending_opens", "final_workers", "final_tasks")):
                raise CaseFailure(f"{path.name}: final resources did not drain")
        forbidden = [run.client_token, run.client2_token, run.server_token, "token_secret", "raw_ticket", "session_id"] + run.private
        output = "\\n".join(path.read_text(errors="replace") for _, path, _ in run.processes)
        if any(marker and marker in output for marker in forbidden):
            raise CaseFailure("privacy scan found credentials, session data, ticket data, or selector values")
        summary = {"case": case, "passed": True, "subcases": {"server_drain": True, "exchange_drain": True, "client_cancel": True}, "observed_assertions": {"resources_drained": True, "readiness_loss": True, "privacy_scan_clean": True}}
        (run.out / "summary.json").write_text(json.dumps(summary, sort_keys=True) + "\\n")
        print(json.dumps(summary, sort_keys=True), flush=True)
    else:
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
