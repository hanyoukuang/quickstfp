from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestSessionAPI:
    """SSH 会话 API 正常情况测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def _make_mock_session(self):
        session = MagicMock()
        session.host = "testhost"
        session.port = 22
        session.username = "testuser"
        session.banner_msg = "Welcome to test server"
        session.close = AsyncMock()
        return session

    def test_create_session_success(self):
        mock_session = self._make_mock_session()
        with patch("app.core.session.SSHSession.connect", new_callable=AsyncMock, return_value=mock_session):
            resp = self.client.post("/api/sessions", json={
                "host": "testhost",
                "port": 22,
                "username": "testuser",
                "password": "testpass",
            })
            assert resp.status_code == 200
            data = resp.json()
            assert data["host"] == "testhost"
            assert data["username"] == "testuser"
            assert "session_id" in data

    def test_get_session_status(self):
        mock_session = self._make_mock_session()
        with patch("app.core.session.SSHSession.connect", new_callable=AsyncMock, return_value=mock_session):
            resp = self.client.post("/api/sessions", json={
                "host": "testhost", "port": 22, "username": "testuser", "password": "testpass",
            })
            session_id = resp.json()["session_id"]

        resp2 = self.client.get(f"/api/sessions/{session_id}/status")
        assert resp2.status_code == 200
        assert resp2.json()["host"] == "testhost"
        assert resp2.json()["username"] == "testuser"

    def test_close_session_success(self):
        mock_session = self._make_mock_session()
        with patch("app.core.session.SSHSession.connect", new_callable=AsyncMock, return_value=mock_session):
            resp = self.client.post("/api/sessions", json={
                "host": "testhost", "port": 22, "username": "testuser", "password": "testpass",
            })
            session_id = resp.json()["session_id"]

        resp2 = self.client.delete(f"/api/sessions/{session_id}")
        assert resp2.status_code == 200
        assert resp2.json()["ok"] is True
        mock_session.close.assert_called_once()

    def test_create_session_with_client_keys(self):
        mock_session = self._make_mock_session()
        with patch("app.core.session.SSHSession.connect", new_callable=AsyncMock, return_value=mock_session) as mock_connect:
            resp = self.client.post("/api/sessions", json={
                "host": "testhost",
                "username": "testuser",
                "client_keys": ["/path/to/key"],
                "passphrase": "keypass",
            })
            assert resp.status_code == 200
            mock_connect.assert_called_once_with(
                host="testhost",
                port=22,
                username="testuser",
                password=None,
                client_keys=["/path/to/key"],
                passphrase="keypass",
            )

    def test_create_session_with_custom_port(self):
        mock_session = self._make_mock_session()
        mock_session.port = 2222
        with patch("app.core.session.SSHSession.connect", new_callable=AsyncMock, return_value=mock_session) as mock_connect:
            resp = self.client.post("/api/sessions", json={
                "host": "testhost",
                "port": 2222,
                "username": "testuser",
                "password": "testpass",
            })
            assert resp.status_code == 200
            mock_connect.assert_called_once_with(
                host="testhost",
                port=2222,
                username="testuser",
                password="testpass",
                client_keys=None,
                passphrase=None,
            )


class TestSessionAPIBoundary:
    """SSH 会话 API 边界情况测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_get_status_nonexistent(self):
        resp = self.client.get("/api/sessions/nonexistent/status")
        assert resp.status_code == 404

    def test_close_nonexistent(self):
        resp = self.client.delete("/api/sessions/nonexistent")
        assert resp.status_code == 404


class TestSessionAPIError:
    """SSH 会话 API 错误情况测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_create_missing_host(self):
        resp = self.client.post("/api/sessions", json={
            "username": "testuser",
            "password": "testpass",
        })
        assert resp.status_code == 422

    def test_create_empty_host(self):
        resp = self.client.post("/api/sessions", json={
            "host": "",
            "username": "testuser",
            "password": "testpass",
        })
        assert resp.status_code == 422

    def test_create_empty_username(self):
        resp = self.client.post("/api/sessions", json={
            "host": "testhost",
            "username": "",
            "password": "testpass",
        })
        assert resp.status_code == 422

    def test_create_invalid_port_zero(self):
        resp = self.client.post("/api/sessions", json={
            "host": "testhost",
            "port": 0,
            "username": "testuser",
            "password": "testpass",
        })
        assert resp.status_code == 422

    def test_create_invalid_port_high(self):
        resp = self.client.post("/api/sessions", json={
            "host": "testhost",
            "port": 65536,
            "username": "testuser",
            "password": "testpass",
        })
        assert resp.status_code == 422

    def test_create_permission_denied(self):
        import asyncssh
        with patch("app.core.session.SSHSession.connect", new_callable=AsyncMock) as mock_connect:
            mock_connect.side_effect = asyncssh.PermissionDenied("auth failed")
            resp = self.client.post("/api/sessions", json={
                "host": "testhost",
                "username": "testuser",
                "password": "wrong",
            })
            assert resp.status_code == 401

    def test_create_connection_failed(self):
        with patch("app.core.session.SSHSession.connect", new_callable=AsyncMock) as mock_connect:
            mock_connect.side_effect = OSError("Name or service not known")
            resp = self.client.post("/api/sessions", json={
                "host": "nonexistent.invalid",
                "username": "testuser",
                "password": "testpass",
            })
            assert resp.status_code == 502

    def test_create_value_error(self):
        with patch("app.core.session.SSHSession.connect", new_callable=AsyncMock) as mock_connect:
            mock_connect.side_effect = ValueError("host must not be empty")
            resp = self.client.post("/api/sessions", json={
                "host": "testhost",
                "username": "testuser",
                "password": "testpass",
            })
            assert resp.status_code == 400
