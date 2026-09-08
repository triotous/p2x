from __future__ import annotations

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
EXPECTED_CASES = {
    "http-direct", "http-relay", "http-keepalive", "http-pipeline-route-lock",
    "http-streaming", "http-websocket", "http-local-rejections", "http-error-mapping",
    "tls-direct", "tls-relay", "tls-fragmentation", "tls-local-rejections",
    "parse-deadlines", "setup-budget", "mixed-limits", "shutdown-parsing",
    "shutdown-active", "mixed-concurrency/64", "mixed-concurrency/128",
}


class IngressEntryPointContract(unittest.TestCase):
    def test_case_matrix_is_closed_and_complete(self) -> None:
        script = (ROOT / "tests/ingress/local.sh").read_text()
        match = re.search(r"cases=\(([^)]*)\)", script)
        self.assertIsNotNone(match)
        self.assertEqual(set(match.group(1).split()), EXPECTED_CASES)

    def test_entry_point_runs_all_three_parser_targets(self) -> None:
        script = (ROOT / "tests/ingress/local.sh").read_text()
        for target in ("domain_authority", "http_ingress", "tls_client_hello"):
            self.assertIn(f"--bin {target}", script)
        self.assertNotIn("incomplete: live case", script)

    def test_operations_doc_describes_completed_http_lifecycle(self) -> None:
        document = (ROOT / "docs/operations/domain-ingress.md").read_text()
        self.assertIn("Response framing is tracked", document)
        self.assertIn("associated `101`", document)
        self.assertNotIn("follow-up implementation item", document)


if __name__ == "__main__":
    unittest.main()
