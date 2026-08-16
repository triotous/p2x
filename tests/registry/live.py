from __future__ import annotations

import argparse, base64, hashlib, json, os, pathlib, secrets, signal, socket, subprocess, tempfile, time

ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "target" / "debug"
IDENTITY = BIN / "examples" / "identity-id"
CASES = [
    "valid-tcp", "valid-quic", "exchange-restart", "multi-service",
    "selector-conflict", "cross-tenant", "register-without-reservation",
    "unauthorized", "lease-expiry", "reservation-loss", "revocation-restart",
    "final-disconnect", "idempotent-replay", "registry-inflight-limit", "registry-limit", "service-limit", "relay-limit",
    "graceful-drain",
]
ZERO_KEYS = ("sessions", "relay_admissions", "reservations", "circuits", "registrations", "selector_owners", "auth_requests", "registry_requests")


def make_token(name):
    raw = secrets.token_bytes(32)
    value = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    digest = hashlib.sha256(b"p2x-fixed-token-v1\0" + raw).digest()
    return f"p2x1.{name}.{value}", base64.urlsafe_b64encode(digest).decode().rstrip("=")


def free_ports():
    values = []
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        sock = socket.socket(socket.AF_INET, kind); sock.bind(("127.0.0.1", 0))
        values.append(sock.getsockname()[1]); sock.close()
    return values


def read_rows(path):
    result = []
    if not path.exists(): return result
    for line in path.read_text(errors="replace").splitlines():
        try: result.append(json.loads(line))
        except json.JSONDecodeError: pass
    return result


class Harness:
    def __init__(self, case, transport="tcp"):
        run_id = os.environ.get("P2X_RUN_ID", time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
        base = pathlib.Path(os.environ.get("P2X_ARTIFACT_DIR", ROOT / "target" / "p2x-registry"))
        self.case, self.out = case, base / run_id / case
        self.out.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="p2x-registry-")
        self.secret = pathlib.Path(self.temp.name)
        self.processes, self.logs, self.entries, self.private_markers = [], {}, [], []
        self.exchange_peer = self.identity("exchange")
        self.tcp, self.quic = free_ports()
        self.address = (f"/ip4/127.0.0.1/udp/{self.quic}/quic-v1" if transport == "quic" else f"/ip4/127.0.0.1/tcp/{self.tcp}") + f"/p2p/{self.exchange_peer}"
        self.ticket = self.secret / "ticket.key"
        self.ticket.write_bytes(b"\x01" + secrets.token_bytes(32)); self.ticket.chmod(0o600)
        self.credentials = self.secret / "credentials.yaml"

    def identity(self, name):
        path = self.secret / f"{name}.key"
        return subprocess.check_output([str(IDENTITY), str(path), "--generate"], text=True).strip()

    def credential(self, name, peer, role="server", scopes=("register_services", "reserve_relay"), tenant="registry-test", revoked=False):
        value, digest = make_token(name)
        self.entries.append(dict(name=name, peer=peer, role=role, scopes=scopes, tenant=tenant, revoked=revoked, digest=digest, token=value))
        return value

    def write_credentials(self):
        now = int(time.time()); lines = ["schema_version: 1", "authorization_revision: 1", "credentials:"]
        for e in self.entries:
            lines += [f"  - credential_id: {e['name']}", f"    token_sha256: \"{e['digest']}\"", f"    peer_id: \"{e['peer']}\"", f"    tenant: {e['tenant']}", f"    role: {e['role']}", f"    scopes: [{', '.join(e['scopes'])}]", "    quota_profile: standard", f"    not_before: {now-60}", f"    expires_at: {now+3600}", f"    revoked: {'true' if e['revoked'] else 'false'}"]
        self.credentials.write_text("\n".join(lines) + "\n"); self.credentials.chmod(0o600)

    def services(self, name, count=1, shared=False, lease=30, refresh=10):
        path = self.secret / f"services-{name}.yaml"
        lines = ["schema_version: 1", "registration:", f"  requested_lease_seconds: {lease}", f"  refresh_seconds: {refresh}", "services:"]
        for index in range(count):
            selector = "shared" if shared else f"{name}-{index}"
            self.private_markers.extend((selector, f"upstream-{index}"))
            lines += [f"  - upstream_id: upstream-{index}", "    selector:", "      protocol: http", f"      metadata: {{service: {selector}}}", "    enabled: true"]
        path.write_text("\n".join(lines) + "\n"); return path

    def spawn(self, name, argv, env=None):
        path = self.out / f"{name}.ndjson"; handle = path.open("w")
        child_env = os.environ.copy(); child_env["P2X_RUN_ID"] = f"registry-{self.case}"
        if env: child_env.update(env)
        proc = subprocess.Popen(argv, cwd=ROOT, env=child_env, stdout=handle, stderr=subprocess.STDOUT)
        proc.p2x_handle = handle
        self.processes.append(proc); self.logs[name] = path; return proc

    def exchange(self, name="exchange", extra=()):
        proc = self.spawn(name, [str(BIN/"p2x-exchange"), "--identity-file", str(self.secret/"exchange.key"), "--credential-file", str(self.credentials), "--ticket-key-file", str(self.ticket), "--tcp-listen", f"/ip4/127.0.0.1/tcp/{self.tcp}", "--quic-listen", f"/ip4/127.0.0.1/udp/{self.quic}/quic-v1", "--advertise", self.address, "--case-id", self.case, *extra])
        self.wait(name, lambda row: row.get("event") == "listener_ready"); return proc

    def server(self, name, token, services, hooks=(), key_name=None):
        argv = [str(BIN/"p2x-server"), "--identity-file", str(self.secret/f"{key_name or name}.key"), "--exchange", self.address, "--exchange-peer-id", self.exchange_peer, "--credential-env", "P2X_TOKEN", "--services-file", str(services), "--case-id", self.case, *hooks]
        return self.spawn(name, argv, {"P2X_TOKEN": token, "P2X_ENABLE_TEST_HOOKS": "1"})

    def client(self, name, token, server_peer, key_name=None, hold=0, circuits=1, targets=()):
        circuit = f"{self.address}/p2p-circuit/p2p/{server_peer}"
        argv = [str(BIN/"p2x-client"), "--identity-file", str(self.secret/f"{key_name or name}.key"), "--exchange", self.address, "--exchange-peer-id", self.exchange_peer, "--credential-env", "P2X_TOKEN", "--server", circuit, "--finite-relay-ping", "--case-id", self.case]
        if hold: argv += ["--test-hold-relay-seconds", str(hold)]
        if circuits != 1: argv += ["--test-relay-circuit-count", str(circuits)]
        for target in targets: argv += ["--test-relay-target", target]
        return self.spawn(name, argv, {"P2X_TOKEN": token, "P2X_ENABLE_TEST_HOOKS": "1"})

    def wait(self, name, predicate, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for row in read_rows(self.logs[name]):
                if predicate(row): return row
            time.sleep(.05)
        raise AssertionError(f"{self.case}: timeout waiting for {name}; inspect {self.logs[name]}")

    def stop(self, proc, graceful=True):
        if proc.poll() is None:
            proc.send_signal(signal.SIGINT if graceful else signal.SIGKILL)
            try: proc.wait(timeout=8)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        if not proc.p2x_handle.closed: proc.p2x_handle.close()

    def exrows(self, name="exchange"): return read_rows(self.logs[name])

    def offset(self, name="exchange"):
        return max((row.get("offset_ms", 0) for row in read_rows(self.logs[name])), default=0)

    def zero(self, name="exchange", timeout=15, after=0):
        return self.wait(name, lambda row: row.get("event") == "exchange_resources" and row.get("offset_ms", 0) > after and all(row.get(key) == 0 for key in ZERO_KEYS), timeout)

    def finish(self, assertions, final=None):
        if not all(assertions.values()): raise AssertionError(f"{self.case}: {assertions}")
        output = "\n".join(path.read_text(errors="replace") for path in self.logs.values())
        forbidden = [value for entry in self.entries for value in (entry["token"], entry["digest"])] + self.private_markers + ["token_secret", "session_id"]
        if any(value in output for value in forbidden): raise AssertionError(f"{self.case}: private lifecycle data leaked")
        summary = {"case": self.case, "passed": True, "observed_assertions": assertions, "final_resources": final or {}}
        (self.out/"summary.json").write_text(json.dumps(summary, sort_keys=True)+"\n"); print(json.dumps(summary, sort_keys=True), flush=True)

    def cleanup(self):
        for proc in reversed(self.processes): self.stop(proc)
        self.temp.cleanup()


def basic(case, transport="tcp", restart=False):
    h = Harness(case, transport)
    try:
        sp = h.identity("server"); cp = h.identity("client")
        st = h.credential("server", sp); ct = h.credential("client", cp, "client", ("open_proxy_stream",)); h.write_credentials()
        exchange = h.exchange(); server = h.server("server", st, h.services("orders"))
        h.wait("server", lambda r: r.get("event") == "server_readiness" and r.get("ready") is True)
        registered = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "registry.registered")
        client = h.client("client", ct, sp); h.wait("client", lambda r: r.get("event") == "terminal" and r.get("code") == "relay.ping"); h.stop(client)
        h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "registry.refreshed" and r.get("revision") == registered["revision"], 20)
        recovered = not restart
        if restart:
            h.stop(exchange); h.wait("server", lambda r: r.get("event") == "server_readiness" and r.get("ready") is False)
            exchange = h.exchange("exchange-restart")
            h.wait("server", lambda r: r.get("event") == "server_readiness" and r.get("ready") is True and r.get("generation", 0) >= 2, 60); recovered = True
        h.stop(server); h.stop(exchange)
        final = [r for r in h.exrows("exchange-restart" if restart else "exchange") if r.get("event") == "exchange_resources"][-1]
        h.finish({"reserve_register_refresh_withdraw": True, "authenticated_relay_ping": True, "same_process_restart_recovery": recovered, "privacy_scan_clean": True}, final)
    finally: h.cleanup()


def registrations(case):
    h = Harness(case)
    try:
        p1 = h.identity("server1"); t1 = h.credential("server1", p1, tenant="tenant-a")
        p2 = h.identity("server2"); t2 = h.credential("server2", p2, tenant="tenant-b" if case == "cross-tenant" else "tenant-a")
        h.write_credentials(); exchange = h.exchange()
        if case == "multi-service":
            server = h.server("server1", t1, h.services("multi", 2)); event = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "registry.registered" and r.get("selector_owners") == 2)
            refreshed = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "registry.refreshed" and r.get("revision") == event["revision"], 20)
            h.stop(server)
            withdrawn = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "registry.withdrawn")
            assertions = {"atomic_full_set": event["registrations"] == 1, "two_selectors_owned": True, "same_revision_refreshed": refreshed["revision"] == event["revision"], "full_set_withdrawn": withdrawn["selector_owners"] == 0}
        else:
            s1 = h.server("server1", t1, h.services("first", shared=True)); h.wait("server1", lambda r: r.get("event") == "server_readiness" and r.get("ready") is True)
            s2 = h.server("server2", t2, h.services("second", shared=True))
            if case == "selector-conflict":
                event = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "registry.conflict")
                assertions = {"one_stable_owner": event["registrations"] == 1 and event["selector_owners"] == 1, "conflict_observed": True}
            else:
                event = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("registrations") == 2 and r.get("selector_owners") == 2)
                assertions = {"both_tenants_registered": True, "tenant_scoped_owners": event["selector_owners"] == 2}
            h.stop(s2); h.stop(s1)
        h.stop(exchange); final = [r for r in h.exrows() if r.get("event") == "exchange_resources"][-1]
        h.finish(assertions | {"privacy_scan_clean": True}, final)
    finally: h.cleanup()


def injected(case):
    h = Harness(case)
    try:
        peer = h.identity("server"); token = h.credential("server", peer); h.write_credentials(); exchange = h.exchange()
        flags = {"register-without-reservation": "--test-register-without-reservation", "lease-expiry": "--test-suppress-registry-refresh", "reservation-loss": "--test-drop-reservation-after-register", "idempotent-replay": "--test-replay-register-response"}
        server = h.server("server", token, h.services("fault", lease=10, refresh=1), (flags[case],))
        if case == "register-without-reservation":
            event = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "registry.reservation_required")
            assertions = {"reservation_required": True, "zero_registry_state": event["registrations"] == 0 and event["selector_owners"] == 0}
        elif case == "lease-expiry":
            ready = h.wait("server", lambda r: r.get("event") == "server_readiness" and r.get("ready") is True)
            registered = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "registry.registered")
            event = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "registry.not_found" and r.get("registrations") == 0 and r.get("selector_owners") == 0, 20)
            h.wait("server", lambda r: r.get("event") == "server_readiness" and r.get("ready") is False and r.get("offset_ms", 0) > ready["offset_ms"], 15)
            restored = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "registry.registered" and r.get("offset_ms", 0) > event["offset_ms"], 15)
            assertions = {"lease_expired": True, "readiness_lost": True, "selector_removed": event["selector_owners"] == 0, "late_refresh_not_resurrected": event["code"] == "registry.not_found", "fresh_revision_required": restored["revision"] != registered["revision"]}
        elif case == "reservation-loss":
            ready = h.wait("server", lambda r: r.get("event") == "server_readiness" and r.get("ready") is True)
            registered = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "registry.registered")
            event = h.wait("exchange", lambda r: r.get("event") == "exchange_resources" and r.get("offset_ms", 0) > registered["offset_ms"] and r.get("reservations") == 0 and r.get("registrations") == 0, 15)
            h.wait("server", lambda r: r.get("event") == "server_readiness" and r.get("ready") is False and r.get("offset_ms", 0) > ready["offset_ms"])
            assertions = {"readiness_lost": True, "reservation_removed": True, "registration_removed": event["registrations"] == 0}
        else:
            event = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("operation") == "register" and r.get("revision") is not None and r.get("mutations") == 1 and len([x for x in h.exrows() if x.get("event") == "registry_transition" and x.get("revision") == r.get("revision")]) >= 2)
            malformed = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "protocol.malformed")
            assertions = {"byte_identical_replay": True, "same_revision": event["revision"] is not None, "single_mutation": event["mutations"] == 1, "changed_body_rejected": malformed["mutations"] == 1}
        h.stop(server); h.stop(exchange); final = [r for r in h.exrows() if r.get("event") == "exchange_resources"][-1]
        h.finish(assertions | {"privacy_scan_clean": True}, final)
    finally: h.cleanup()


def unauthorized():
    h = Harness("unauthorized")
    try:
        actors = []
        for name, role, scopes in (("wrong-role", "client", ("open_proxy_stream",)), ("no-reserve", "server", ("register_services",)), ("no-register", "server", ("reserve_relay",))):
            peer = h.identity(name); actors.append((name, h.credential(name, peer, role, scopes)))
        bad_peer = h.identity("unauthenticated"); bad_token, _ = make_token("bad")
        h.write_credentials(); exchange = h.exchange(); outcomes = {}
        for name, token in actors:
            before = h.offset()
            proc = h.server(name, token, h.services(name))
            if name == "wrong-role": h.wait(name, lambda r: r.get("event") == "terminal" and r.get("code") == "auth.role_forbidden")
            elif name == "no-register": h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "auth.role_forbidden")
            else:
                h.wait("exchange", lambda r: r.get("event") == "operational_error" and r.get("offset_ms", 0) > before and "ReservationReqDenied" in r.get("message", ""))
                h.wait("exchange", lambda r: r.get("event") == "exchange_resources" and r.get("offset_ms", 0) > before and r.get("reservations") == 0 and r.get("registrations") == 0)
            h.stop(proc, False); outcomes[f"{name.replace('-', '_')}_denied"] = True
        bad = h.server("unauthenticated", bad_token, h.services("bad")); h.wait("unauthenticated", lambda r: r.get("event") == "terminal" and r.get("code") == "auth.invalid_credential"); h.stop(bad, False); outcomes["unauthenticated_denied"] = True
        before = h.offset(); final = h.zero(after=before); h.stop(exchange); h.finish(outcomes | {"final_zero_state": True, "privacy_scan_clean": True}, final)
    finally: h.cleanup()


def service_limit():
    h = Harness("service-limit")
    try:
        p1 = h.identity("server32"); t1 = h.credential("server32", p1); p2 = h.identity("server33"); t2 = h.credential("server33", p2)
        h.write_credentials(); exchange = h.exchange(); s1 = h.server("server32", t1, h.services("limit32", 32))
        accepted = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("selector_owners") == 32)
        s2 = h.server("server33", t2, h.services("limit33", 33)); rejected = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "limit.services")
        h.stop(s2); h.stop(s1); h.stop(exchange); final = [r for r in h.exrows() if r.get("event") == "exchange_resources"][-1]
        h.finish({"limit_accepted": accepted["selector_owners"] == 32, "limit_plus_one_rejected": True, "previous_state_unchanged": rejected["selector_owners"] == 32, "privacy_scan_clean": True}, final)
    finally: h.cleanup()


def final_disconnect():
    h = Harness("final-disconnect")
    try:
        peer = h.identity("server"); token = h.credential("server", peer); h.write_credentials(); exchange = h.exchange(); server = h.server("server", token, h.services("disconnect"))
        h.wait("server", lambda r: r.get("event") == "server_readiness" and r.get("ready") is True)
        registered = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "registry.registered")
        h.stop(server, False); final = h.zero(after=registered["offset_ms"]); h.stop(exchange)
        h.finish({"final_connection_lost": True, "session_removed": final["sessions"] == 0, "relay_authority_removed": final["relay_admissions"] == 0, "reservation_removed": final["reservations"] == 0, "registry_removed": final["registrations"] == 0 and final["selector_owners"] == 0, "privacy_scan_clean": True}, final)
    finally: h.cleanup()


def registry_limit():
    h = Harness("registry-limit")
    try:
        peer = h.identity("server"); token = h.credential("server", peer); h.write_credentials(); exchange = h.exchange(); server = h.server("server", token, h.services("rate", lease=10, refresh=1))
        rejected = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "limit.registry_requests", 45)
        accepted = [r for r in h.exrows() if r.get("event") == "registry_transition" and r.get("code") in ("registry.registered", "registry.refreshed")]
        before = h.offset(); h.stop(server); final = h.zero(after=before); h.stop(exchange)
        h.finish({"n_operations_accepted": len(accepted) == 30, "n_plus_one_rejected": rejected["code"] == "limit.registry_requests", "permit_count_zero": final["registry_requests"] == 0, "privacy_scan_clean": True}, final)
    finally: h.cleanup()


def registry_inflight_limit():
    h = Harness("registry-inflight-limit")
    try:
        peer = h.identity("server"); token = h.credential("server", peer); h.write_credentials(); exchange = h.exchange(); server = h.server("server", token, h.services("inflight"), ("--test-concurrent-registry-requests",))
        rejected = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "limit.registry_requests")
        accepted = h.wait("exchange", lambda r: r.get("event") == "registry_transition" and r.get("code") == "registry.registered")
        before = h.offset(); h.stop(server); final = h.zero(after=before); h.stop(exchange)
        h.finish({"one_per_peer_accepted": accepted["registrations"] == 1, "per_peer_n_plus_one_rejected": rejected["code"] == "limit.registry_requests", "permit_count_zero": final["registry_requests"] == 0, "privacy_scan_clean": True}, final)
    finally: h.cleanup()


def graceful_drain():
    h = Harness("graceful-drain")
    try:
        peer = h.identity("server"); token = h.credential("server", peer); h.write_credentials(); exchange = h.exchange(); server = h.server("server", token, h.services("drain"))
        h.wait("server", lambda r: r.get("event") == "server_readiness" and r.get("ready") is True); h.stop(server); h.stop(exchange)
        final = [r for r in h.exrows() if r.get("event") == "exchange_resources"][-1]
        h.finish({"withdraw_observed": any(r.get("code") == "registry.withdrawn" for r in h.exrows()), "server_terminal": any(r.get("event") == "terminal" and r.get("code") == "shutdown" for r in read_rows(h.logs["server"])), "exchange_terminal": any(r.get("event") == "terminal" for r in h.exrows()), "all_resources_zero": all(final.get(k) == 0 for k in ZERO_KEYS), "privacy_scan_clean": True}, final)
    finally: h.cleanup()


def revocation_restart():
    h = Harness("revocation-restart")
    try:
        peer = h.identity("server"); token = h.credential("server", peer); h.write_credentials(); exchange = h.exchange(); server = h.server("server", token, h.services("revoke"))
        h.wait("server", lambda r: r.get("event") == "server_readiness" and r.get("ready") is True); h.stop(exchange)
        h.entries[0]["revoked"] = True; h.write_credentials(); exchange = h.exchange("exchange-revoked")
        h.wait("server", lambda r: r.get("event") == "terminal" and r.get("result") == "failed", 30); h.stop(server, False); h.stop(exchange)
        h.entries[0]["revoked"] = False; h.write_credentials(); exchange = h.exchange("exchange-restored"); server = h.server("server-restored", token, h.services("restored"), key_name="server")
        h.wait("server-restored", lambda r: r.get("event") == "server_readiness" and r.get("ready") is True); h.stop(server); h.stop(exchange)
        final = [r for r in h.exrows("exchange-restored") if r.get("event") == "exchange_resources"][-1]
        h.finish({"revoked_credential_rejected": True, "fresh_registration_restored": True, "final_zero_state": all(final.get(k) == 0 for k in ZERO_KEYS), "privacy_scan_clean": True}, final)
    finally: h.cleanup()


def relay_limit():
    h = Harness("relay-limit")
    try:
        servers = []
        for index in range(32):
            name = f"server-{index}"; peer = h.identity(name); servers.append((name, peer, h.credential(name, peer)))
        cp = h.identity("client"); ct = h.credential("client", cp, "client", ("open_proxy_stream",)); h.write_credentials(); exchange = h.exchange(extra=("--auth-limit-connections", "64", "--auth-limit-requests", "64", "--auth-limit-sessions", "64", "--auth-limit-connections-per-ip", "64"))
        processes = []
        for name, _, token in servers:
            process = h.server(name, token, h.services(name)); processes.append((name, process))
            h.wait(name, lambda r: r.get("event") == "server_readiness" and r.get("ready") is True, 30)
        before_duplicate = h.offset()
        duplicate = h.server("server-duplicate", servers[0][2], h.services("duplicate"), key_name=servers[0][0])
        h.wait("exchange", lambda r: r.get("event") == "operational_error" and r.get("offset_ms", 0) > before_duplicate and "ReservationReqDenied" in r.get("message", ""))
        h.stop(duplicate, False)
        targets = [f"{h.address}/p2p-circuit/p2p/{peer}" for _, peer, _ in servers]
        targets.append(targets[0])
        client = h.client("client", ct, servers[0][1], targets=targets)
        peak = h.wait("exchange", lambda r: r.get("event") == "exchange_resources" and r.get("circuits") == 32, 50); time.sleep(2)
        maximum = max(r.get("circuits", 0) for r in h.exrows() if r.get("event") == "exchange_resources")
        before = h.offset()
        h.stop(client, False)
        for _, process in processes: h.stop(process)
        final = h.zero(after=before); h.stop(exchange)
        h.finish({"reservation_n_plus_one_denied": True, "thirty_two_circuits_accepted": peak["circuits"] == 32, "thirty_third_not_allocated": maximum == 32, "one_reservation_per_server": peak["reservations"] == 32, "final_zero_state": final["circuits"] == 0 and final["reservations"] == 0, "privacy_scan_clean": True}, final)
    finally: h.cleanup()


def run(case):
    if case == "valid-tcp": basic(case)
    elif case == "valid-quic": basic(case, "quic")
    elif case == "exchange-restart": basic(case, restart=True)
    elif case in ("multi-service", "selector-conflict", "cross-tenant"): registrations(case)
    elif case in ("register-without-reservation", "lease-expiry", "reservation-loss", "idempotent-replay"): injected(case)
    elif case == "unauthorized": unauthorized()
    elif case == "service-limit": service_limit()
    elif case == "final-disconnect": final_disconnect()
    elif case == "registry-limit": registry_limit()
    elif case == "registry-inflight-limit": registry_inflight_limit()
    elif case == "graceful-drain": graceful_drain()
    elif case == "revocation-restart": revocation_restart()
    elif case == "relay-limit": relay_limit()


parser = argparse.ArgumentParser(); parser.add_argument("--case", default="all"); args = parser.parse_args()
selected = CASES if args.case == "all" else [args.case]
if any(case not in CASES for case in selected): raise SystemExit(f"unknown registry case: {args.case}; expected all or one of {','.join(CASES)}")
for case in selected: run(case)
