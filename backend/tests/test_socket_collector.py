import unittest
from unittest.mock import patch
from types import SimpleNamespace

from app.collectors.socket import collect_socket_snapshot, _hash_cmdline


class SocketCollectorTests(unittest.TestCase):
    def test_cmdline_is_hashed_not_returned(self):
        raw = ["python", "script.py", "--token", "secret-value"]
        digest = _hash_cmdline(raw)
        self.assertIsNotNone(digest)
        self.assertNotIn("secret-value", digest)
        self.assertEqual(len(digest), 64)

    @patch("psutil.net_connections")
    @patch("psutil.Process")
    def test_snapshot_emits_metadata_t1_only(self, process_mock, connections_mock):
        conn = SimpleNamespace(
            raddr=SimpleNamespace(ip="203.0.113.8", port=443),
            laddr=SimpleNamespace(ip="192.0.2.2", port=52344),
            pid=123,
            type=1,
            status="ESTABLISHED",
        )
        connections_mock.return_value = [conn]
        process_mock.return_value.name.return_value = "python.exe"
        process_mock.return_value.exe.return_value = "C:/Python/python.exe"
        process_mock.return_value.username.return_value = "tester"
        process_mock.return_value.cmdline.return_value = ["python", "app.py"]
        with patch("app.collectors.socket._remote_host", return_value="api.anthropic.com"):
            result = collect_socket_snapshot()
        self.assertEqual(result["tier"], "T1")
        self.assertEqual(len(result["events"]), 1)
        event = result["events"][0]
        self.assertEqual(event["process"], "python.exe")
        self.assertEqual(event["destination"], "api.anthropic.com")
        self.assertFalse(event["content_inspected"])
        self.assertNotIn("cmdline", event["process_meta"])

    @patch("psutil.net_connections")
    def test_permission_error_degrades_gracefully(self, connections_mock):
        import psutil
        connections_mock.side_effect = psutil.AccessDenied()
        result = collect_socket_snapshot()
        self.assertTrue(result["partial_visibility"])
        self.assertEqual(result["events"], [])
        self.assertTrue(result["warnings"])


if __name__ == "__main__":
    unittest.main()
