import io
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_mock_session():
    session = MagicMock()
    session.host = "testhost"
    session.port = 22
    session.username = "testuser"
    session.banner_msg = ""
    session.sftp = MagicMock()
    session.sftp.makedirs = AsyncMock()
    session.sftp.open = MagicMock()
    return session


class TestTransportAPI:
    """文件传输 API 测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client
        self.mock_session = _make_mock_session()

    def _create_session(self):
        with patch("app.core.session.SSHSession.connect", new_callable=AsyncMock, return_value=self.mock_session):
            resp = self.client.post("/api/sessions", json={
                "host": "testhost", "username": "testuser", "password": "pass",
            })
            return resp.json()["session_id"]

    def test_upload_file(self):
        mock_remote_file = MagicMock()
        mock_remote_file.__aenter__ = AsyncMock(return_value=mock_remote_file)
        mock_remote_file.__aexit__ = AsyncMock(return_value=None)
        mock_remote_file.write = AsyncMock()
        self.mock_session.sftp.open.return_value = mock_remote_file

        sid = self._create_session()
        file_content = b"Hello upload"
        resp = self.client.post(
            f"/api/transport/{sid}/upload?path=/remote/dir",
            files={"file": ("test.txt", io.BytesIO(file_content), "text/plain")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert "Uploaded to" in data["message"]

    def test_upload_file_no_filename(self):
        mock_remote_file = MagicMock()
        mock_remote_file.__aenter__ = AsyncMock(return_value=mock_remote_file)
        mock_remote_file.__aexit__ = AsyncMock(return_value=None)
        mock_remote_file.write = AsyncMock()
        self.mock_session.sftp.open.return_value = mock_remote_file

        sid = self._create_session()
        resp = self.client.post(
            f"/api/transport/{sid}/upload?path=/remote/dir",
            files={"file": ("test.txt", b"content", "text/plain")},
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_upload_nonexistent_session(self):
        resp = self.client.post(
            "/api/transport/invalid_id/upload?path=/remote/dir",
            files={"file": ("test.txt", b"content", "text/plain")},
        )
        assert resp.status_code == 404

    def test_download_file(self):
        mock_remote_file = MagicMock()
        mock_remote_file.__aenter__ = AsyncMock(return_value=mock_remote_file)
        mock_remote_file.__aexit__ = AsyncMock(return_value=None)
        mock_remote_file.read = AsyncMock(return_value=b"download content")
        self.mock_session.sftp.open.return_value = mock_remote_file

        sid = self._create_session()
        resp = self.client.get(f"/api/transport/{sid}/download?path=/remote/test.txt")
        assert resp.status_code == 200
        assert resp.content == b"download content"
        assert "attachment" in resp.headers.get("Content-Disposition", "")

    def test_download_nonexistent_session(self):
        resp = self.client.get("/api/transport/invalid_id/download?path=/remote/test.txt")
        assert resp.status_code == 404

    def test_download_file_error(self):
        self.mock_session.sftp.open = MagicMock(side_effect=Exception("remote error"))
        sid = self._create_session()
        resp = self.client.get(f"/api/transport/{sid}/download?path=/remote/bad.txt")
        assert resp.status_code == 400

    def test_upload_without_file(self):
        sid = self._create_session()
        resp = self.client.post(f"/api/transport/{sid}/upload?path=/remote/dir")
        assert resp.status_code == 422
