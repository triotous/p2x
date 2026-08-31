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
