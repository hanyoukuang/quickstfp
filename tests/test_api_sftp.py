from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _make_mock_session():
    session = MagicMock()
    session.host = "testhost"
    session.port = 22
    session.username = "testuser"
    session.banner_msg = ""
    session.sftp = MagicMock()
    session.sftp.scandir = AsyncMock(return_value=MagicMock())
    session.sftp.stat = AsyncMock()
    session.sftp.isfile = AsyncMock(return_value=True)
    session.read_file = AsyncMock(return_value="file content")
    session.save_file = AsyncMock(return_value=None)
    session.makedirs = AsyncMock(return_value=None)
    session.del_file = AsyncMock(return_value=None)
    session.rename = AsyncMock(return_value=None)
    session.copy_file = AsyncMock(return_value=None)
    session.move_file = AsyncMock(return_value=None)
    session.chmod = AsyncMock(return_value=None)
    return session


class TestSFTPAPI:
    """SFTP API 正常情况测试"""

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

    def test_list_dir(self):
        mock_entry = MagicMock()
        mock_entry.filename = "test.txt"
        mock_entry.attrs = MagicMock()
        mock_entry.attrs.mtime = 1600000000
        mock_entry.attrs.size = 1024
        mock_entry.attrs.permissions = 0o644
        mock_entry.attrs.type = 1

        async def mock_scandir(path):
            yield mock_entry
        self.mock_session.sftp.scandir = mock_scandir

        sid = self._create_session()
        resp = self.client.get(f"/api/sftp/{sid}/list?path=/home")
        assert resp.status_code == 200
        data = resp.json()
        assert data["current_path"] == "/home"
        assert len(data["entries"]) == 1
        assert data["entries"][0]["name"] == "test.txt"

    def test_list_dir_empty(self):
        async def mock_scandir(path):
            if False:
                yield
        self.mock_session.sftp.scandir = mock_scandir

        sid = self._create_session()
        resp = self.client.get(f"/api/sftp/{sid}/list?path=/empty")
        assert resp.status_code == 200
        assert len(resp.json()["entries"]) == 0

    def test_read_file(self):
        self.mock_session.read_file = AsyncMock(return_value="Hello World")
        sid = self._create_session()
        resp = self.client.get(f"/api/sftp/{sid}/read?path=/test.txt")
        assert resp.status_code == 200
        assert resp.json()["content"] == "Hello World"

    def test_write_file(self):
        sid = self._create_session()
        resp = self.client.put(
            f"/api/sftp/{sid}/write?path=/new.txt",
            json={"content": "new content"},
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        self.mock_session.save_file.assert_called_once_with("/new.txt", "new content")

    def test_mkdir(self):
        sid = self._create_session()
        resp = self.client.post(f"/api/sftp/{sid}/mkdir?path=/new/dir")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        self.mock_session.makedirs.assert_called_once_with("/new/dir")

    def test_delete(self):
        sid = self._create_session()
        resp = self.client.delete(f"/api/sftp/{sid}/delete?path=/test.txt")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        self.mock_session.del_file.assert_called_once_with("/test.txt")

    def test_rename(self):
        sid = self._create_session()
        resp = self.client.post(f"/api/sftp/{sid}/rename", json={
            "old_path": "/old.txt", "new_name": "/new.txt",
        })
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        self.mock_session.rename.assert_called_once_with("/old.txt", "/new.txt")

    def test_copy(self):
        sid = self._create_session()
        resp = self.client.post(f"/api/sftp/{sid}/copy", json={
            "src": "/src.txt", "dst": "/dst.txt",
        })
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        self.mock_session.copy_file.assert_called_once_with("/src.txt", "/dst.txt")

    def test_move(self):
        sid = self._create_session()
        resp = self.client.post(f"/api/sftp/{sid}/move", json={
            "src": "/src.txt", "dst": "/dst.txt",
        })
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        self.mock_session.move_file.assert_called_once_with("/src.txt", "/dst.txt")

    def test_chmod(self):
        sid = self._create_session()
        resp = self.client.put(
            f"/api/sftp/{sid}/chmod?path=/test.txt",
            json={"permissions": 0o755},
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        self.mock_session.chmod.assert_called_once_with("/test.txt", 0o755)


class TestSFTPAPIBoundary:
    """SFTP API 边界情况测试"""

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

    def test_list_dir_nonexistent_session(self):
        resp = self.client.get("/api/sftp/invalid_id/list?path=/")
        assert resp.status_code == 404

    def test_read_file_nonexistent_session(self):
        resp = self.client.get("/api/sftp/invalid_id/read?path=/test.txt")
        assert resp.status_code == 404

    def test_stat_nonexistent_session(self):
        resp = self.client.get("/api/sftp/invalid_id/stat?path=/test.txt")
        assert resp.status_code == 404

    def test_mkdir_nonexistent_session(self):
        resp = self.client.post("/api/sftp/invalid_id/mkdir?path=/new")
        assert resp.status_code == 404

    def test_rename_missing_fields(self):
        resp = self.client.post("/api/sftp/any_id/rename", json={})
        assert resp.status_code == 422

    def test_copy_missing_fields(self):
        resp = self.client.post("/api/sftp/any_id/copy", json={})
        assert resp.status_code == 422

    def test_write_empty_content(self):
        sid = self._create_session()
        resp = self.client.put(f"/api/sftp/{sid}/write?path=/empty.txt", json={"content": ""})
        assert resp.status_code == 200


class TestSFTPAPIError:
    """SFTP API 错误情况测试"""

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

    def test_list_dir_sftp_error(self):
        import asyncssh
        async def mock_scandir(path):
            raise asyncssh.SFTPError(1, "access denied")
            yield
        self.mock_session.sftp.scandir = mock_scandir
        sid = self._create_session()
        resp = self.client.get(f"/api/sftp/{sid}/list?path=/restricted")
        assert resp.status_code == 400

    def test_stat_file_not_found(self):
        import asyncssh
        self.mock_session.sftp.stat = AsyncMock(side_effect=asyncssh.SFTPNoSuchFile("not found"))
        sid = self._create_session()
        resp = self.client.get(f"/api/sftp/{sid}/stat?path=/nonexistent")
        assert resp.status_code == 404

    def test_read_file_sftp_error(self):
        import asyncssh
        self.mock_session.read_file = AsyncMock(side_effect=asyncssh.SFTPError(1, "read error"))
        sid = self._create_session()
        resp = self.client.get(f"/api/sftp/{sid}/read?path=/bad.txt")
        assert resp.status_code == 400

    def test_rename_sftp_error(self):
        import asyncssh
        self.mock_session.rename = AsyncMock(side_effect=asyncssh.SFTPError(1, "rename failed"))
        sid = self._create_session()
        resp = self.client.post(f"/api/sftp/{sid}/rename", json={
            "old_path": "/old.txt", "new_name": "/new.txt",
        })
        assert resp.status_code == 400

    def test_chmod_sftp_error(self):
        import asyncssh
        self.mock_session.chmod = AsyncMock(side_effect=asyncssh.SFTPError(1, "chmod failed"))
        sid = self._create_session()
        resp = self.client.put(
            f"/api/sftp/{sid}/chmod?path=/test.txt",
            json={"permissions": 0o755},
        )
        assert resp.status_code == 400
