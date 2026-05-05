from unittest.mock import AsyncMock, MagicMock, patch

from starlette.websockets import WebSocketDisconnect
import pytest


class MockSSHProcess:
    stdout = MagicMock()
    stdin = MagicMock()

    def __init__(self):
        self.stdout.read = AsyncMock(return_value=b"")
        self.stdin.write = MagicMock()
        self.stdin.drain = AsyncMock()


class TestTerminalWS:
    """Terminal WebSocket 测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def _make_mock_session(self):
        session = MagicMock()
        session.host = "testhost"
        session.port = 22
        session.username = "testuser"
        session.banner_msg = ""
        session.process = MockSSHProcess()
        return session

    def _create_session(self):
        mock_session = self._make_mock_session()
        with patch("app.core.session.SSHSession.connect", new_callable=AsyncMock, return_value=mock_session):
            resp = self.client.post("/api/sessions", json={
                "host": "testhost", "username": "testuser", "password": "pass",
            })
            return resp.json()["session_id"]

    def test_ws_connect_nonexistent_session(self):
        try:
            with self.client.websocket_connect("/ws/terminal/nonexistent"):
                pass
        except WebSocketDisconnect:
            pass

    def test_ws_connect_existing_session(self):
        sid = self._create_session()
        with self.client.websocket_connect(f"/ws/terminal/{sid}") as ws:
            ws.close()


class TestProgressWS:
    """Progress WebSocket 测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def _make_mock_session(self):
        session = MagicMock()
        session.host = "testhost"
        session.port = 22
        session.username = "testuser"
        session.banner_msg = ""
        session.sftp = MagicMock()
        return session

    def _create_session(self):
        mock_session = self._make_mock_session()
        with patch("app.core.session.SSHSession.connect", new_callable=AsyncMock, return_value=mock_session):
            resp = self.client.post("/api/sessions", json={
                "host": "testhost", "username": "testuser", "password": "pass",
            })
            return resp.json()["session_id"]

    def test_ws_connect_nonexistent_session(self):
        try:
            with self.client.websocket_connect("/ws/transport/nonexistent"):
                pass
        except WebSocketDisconnect:
            pass

    def test_ws_connect_existing_session(self):
        sid = self._create_session()
        with self.client.websocket_connect(f"/ws/transport/{sid}") as ws:
            ws.close()
