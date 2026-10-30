import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app


class LocalAuthTests(unittest.TestCase):
    def test_post_rejected_when_token_configured_and_missing(self):
        with patch.dict(os.environ, {"SHADOWLENS_API_TOKEN": "test-token"}):
            response = TestClient(app).post("/api/analyze", json={"event": {}})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "Bearer token required for POST requests")

    def test_post_rejected_when_token_is_wrong(self):
        with patch.dict(os.environ, {"SHADOWLENS_API_TOKEN": "test-token"}):
            response = TestClient(app).post(
                "/api/analyze", json={"event": {}},
                headers={"Authorization": "Bearer wrong-token"},
            )
        self.assertEqual(response.status_code, 401)

    def test_post_allowed_with_matching_token(self):
        with patch.dict(os.environ, {"SHADOWLENS_API_TOKEN": "test-token"}):
            response = TestClient(app).post(
                "/api/analyze", json={"event": {}},
                headers={"Authorization": "Bearer test-token"},
            )
        self.assertEqual(response.status_code, 200)

    def test_get_health_remains_public(self):
        with patch.dict(os.environ, {"SHADOWLENS_API_TOKEN": "test-token"}):
            response = TestClient(app).get("/api/health")
        self.assertEqual(response.status_code, 200)


if __name__ == "__main__":
    unittest.main()
