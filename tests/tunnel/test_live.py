from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("tunnel_live", pathlib.Path(__file__).with_name("live.py"))
assert SPEC is not None and SPEC.loader is not None
live = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(live)


class TunnelGateTests(unittest.TestCase):
    def test_privacy_marker_scanner_detects_each_exact_marker(self) -> None:
        markers = ["payload-random", "selector-random", "ticket-session-random"]
        for marker in markers:
            self.assertEqual(live.private_markers_in(marker, markers), [marker])

    def test_private_marker_evidence_requires_session_and_ticket(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "private-markers"
            path.write_text("session:c2Vzc2lvbg\n")
            with self.assertRaises(live.Failure):
                live.read_test_private_markers(path)
            path.write_text("session:c2Vzc2lvbg\nticket:dGlja2V0\n")
            self.assertEqual(live.read_test_private_markers(path), ["c2Vzc2lvbg", "dGlja2V0"])

    def test_deadline_stage_matrix_is_closed_and_stage_specific(self) -> None:
        self.assertEqual(
            live.DEADLINE_STAGES,
            (
                ("resolve", "hold_resolve_response"),
                ("verification", "hold_server_verification"),
                ("owner-decision", "hold_server_owner_decision"),
                ("promotion", "hold_server_promotion"),
                ("upstream-dial", "hold_server_upstream_dial"),
                ("accepted-write", "hold_server_accepted_write"),
            ),
        )
        client_rows = [
            {"event": "ingress_accepted", "ingress_id": 1},
            {"event": "ingress_rejected", "ingress_id": 1, "code": "peer.setup_timeout"},
        ]
        self.assertEqual(
            live.assert_named_contract("deadline-stages/promotion", client_rows, []),
            "deadline_stage_timeout",
        )
        with self.assertRaises(live.Failure):
            live.assert_named_contract(
                "deadline-stages/accepted-write",
                [
                    {"event": "ingress_accepted", "ingress_id": 1},
                    {"event": "ingress_rejected", "ingress_id": 2, "code": "peer.setup_timeout"},
                ],
                [],
            )

    def test_resolve_recovery_requires_a_real_rejected_response(self) -> None:
        client_rows = [
            {"event": "started"},
            {"event": "ingress_accepted", "ingress_id": 1},
            {"event": "ingress_accepted", "ingress_id": 2},
            {"event": "resolution_outcome", "code": "registry.offline"},
            {"event": "ingress_rejected", "ingress_id": 1, "code": "registry.offline"},
        ]
        self.assertEqual(
            live.assert_named_contract("per-ingress-failure-recovery/resolve", client_rows, []),
            "per_ingress_failure_recovery",
        )
        with self.assertRaises(live.Failure):
            live.assert_named_contract(
                "per-ingress-failure-recovery/resolve",
                [row for row in client_rows if row.get("event") != "resolution_outcome"],
                [],
            )

    def test_path_capacity_requires_client_pending_limit(self) -> None:
        client_rows = [{"event": "started"}] + [
            {"event": "ingress_accepted", "ingress_id": ingress_id}
            for ingress_id in (1, 2, 3)
        ]
        client_rows.extend([
            {"event": "ingress_rejected", "ingress_id": 2, "code": "limit.peer_connections", "offset_ms": 2},
            {"event": "tunnel_accepted", "offset_ms": 3},
        ])
        self.assertEqual(
            live.assert_named_contract("per-ingress-failure-recovery/path-capacity", client_rows, []),
            "per_ingress_failure_recovery",
        )
        with self.assertRaises(live.Failure):
            live.assert_named_contract(
                "per-ingress-failure-recovery/path-capacity",
                client_rows,
                [{"event": "proxy_authorization", "authorized": False, "code": "limit.proxy_streams"}],
            )

    def test_stream_limit_rejections_are_exact_logical_requests(self) -> None:
        accepted = [
            {"event": "tunnel_accepted", "peer_id": "client-a"},
            {"event": "tunnel_accepted", "peer_id": "client-b"},
        ]
        rejected = {
            "event": "proxy_authorization",
            "peer_id": "client-a",
            "request_id_hash": 7,
            "authorized": False,
            "code": "limit.proxy_streams",
        }
        self.assertEqual(
            live.assert_named_contract("stream-limits/server-client", [], accepted + [rejected, rejected]),
            "stream_limit_boundary",
        )
        with self.assertRaises(live.Failure):
            live.assert_named_contract(
                "stream-limits/server-client",
                [],
                accepted + [rejected, {**rejected, "request_id_hash": 8}],
            )

    def test_server_dial_requires_held_and_final_zero_dial_count(self) -> None:
        rows = [
            {"event": "resources", "tasks": 1},
            {"event": "tunnel_accepted"},
            {"event": "proxy_authorization", "peer_id": "client", "request_id_hash": 7, "authorized": False, "code": "limit.proxy_streams"},
            {"event": "resources", "tasks": 0},
        ]
        self.assertEqual(
            live.assert_named_contract("stream-limits/server-dial", [], rows),
            "stream_limit_boundary",
        )
        with self.assertRaises(live.Failure):
            live.assert_named_contract("stream-limits/server-dial", [], rows[:-1])

    def test_setup_shutdown_requires_production_boundary_before_accepted(self) -> None:
        client_rows = [{"event": "route_owner_high_water", "opens": 1}, {"event": "terminal", "code": "shutdown"}]
        server_rows = [{"event": "test_fault_applied", "fault": "hold_server_verification"}]
        self.assertEqual(
            live.assert_named_contract("shutdown/client-setup", client_rows, server_rows),
            "shutdown_setup_drain",
        )
        with self.assertRaises(live.Failure):
            live.assert_named_contract(
                "shutdown/client-setup",
                client_rows + [{"event": "tunnel_accepted"}],
                server_rows,
            )
        with self.assertRaises(live.Failure):
            live.assert_named_contract("shutdown/server-setup", client_rows, [])

    def test_final_resources_require_every_zero_field(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "client.ndjson"
            path.write_text('{"event":"resources","connections":0,"pending_opens":0,"workers":0}\n')
            with self.assertRaises(live.Failure):
                live.assert_final_resources(path)
            path.write_text('{"event":"resources","connections":0,"pending_opens":0,"workers":0,"tasks":0}\n')
            self.assertTrue(live.assert_final_resources(path))

    def test_lifecycle_requires_frozen_accepted_metadata(self) -> None:
        accepted = {
            "event": "tunnel_accepted",
            "connection_id_hash": 3,
            "request_id_hash": 5,
            "stream_id_hash": 7,
            "selected_path": "direct",
            "setup_duration_ms": 11,
        }
        terminal = {
            "event": "tunnel_terminal",
            "component_side": "client",
            "connection_id_hash": 3,
            "request_id_hash": 5,
            "stream_id_hash": 7,
            "selected_path": "direct",
            "accepted": True,
            "setup_duration_ms": 12,
            "local_to_remote_bytes": 64,
            "remote_to_local_bytes": 64,
        }
        server_terminal = terminal | {"component_side": "server", "setup_duration_ms": 11}
        with self.assertRaises(live.Failure):
            live.assert_tunnel_lifecycle("terminal-correlation", [accepted, terminal], [accepted, server_terminal])


if __name__ == "__main__":
    unittest.main()
