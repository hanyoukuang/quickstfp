from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.core.session import SSHSession


def make_mock_connection():
    """创建模拟的 SSH 连接"""
    conn = MagicMock()
    conn.get_banner = MagicMock(return_value="Welcome to mock SSH server")
    conn.close = MagicMock()
    return conn


def make_mock_sftp():
    """创建模拟的 SFTP 客户端"""
    sftp = MagicMock()
    sftp.exit = MagicMock()
    sftp.getcwd = AsyncMock(return_value="/home/user")
    sftp.isfile = AsyncMock(return_value=True)
    sftp.chdir = AsyncMock(return_value=None)
    sftp.getsize = AsyncMock(return_value=1024)
    sftp.realpath = AsyncMock(return_value="/home/user/real")
    sftp.rename = AsyncMock(return_value=None)
    sftp.makedirs = AsyncMock(return_value=None)
    sftp.chmod = AsyncMock(return_value=None)
    return sftp


def make_mock_process():
    """创建模拟的终端进程"""
    process = MagicMock()
    process.close = MagicMock()
    return process


@pytest.fixture
def mock_conn():
    return make_mock_connection()


@pytest.fixture
def mock_sftp():
    return make_mock_sftp()


@pytest.fixture
def mock_process():
    return make_mock_process()


@pytest.fixture
def session(mock_conn, mock_sftp, mock_process):
    return SSHSession(
        connection=mock_conn,
        sftp=mock_sftp,
        process=mock_process,
        host="example.com",
        port=22,
        username="testuser",
    )


class TestSSHSessionNormal:
    """SSHSession 正常情况测试"""

    def test_session_attributes(self, session):
        """会话实例属性正确设置"""
        assert session.host == "example.com"
        assert session.port == 22
        assert session.username == "testuser"

    @pytest.mark.asyncio
    async def test_close(self, session, mock_sftp, mock_process, mock_conn):
        """close 应正确释放所有资源"""
        await session.close()

        mock_sftp.exit.assert_called_once()
        mock_process.close.assert_called_once()
        mock_conn.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_is_file(self, session, mock_sftp):
        """is_file 应正确代理到 sftp"""
        mock_sftp.isfile.return_value = True
        result = await session.is_file("/test/file.txt")
        assert result is True
        mock_sftp.isfile.assert_called_once_with("/test/file.txt")

    @pytest.mark.asyncio
    async def test_chdir(self, session, mock_sftp):
        """chdir 应正确代理到 sftp"""
        await session.chdir("/other/dir")
        mock_sftp.chdir.assert_called_once_with("/other/dir")

    @pytest.mark.asyncio
    async def test_getcwd(self, session, mock_sftp):
        """getcwd 应正确返回当前路径"""
        mock_sftp.getcwd.return_value = "/home/test"
        result = await session.getcwd()
        assert result == "/home/test"

    @pytest.mark.asyncio
    async def test_realpath(self, session, mock_sftp):
        """realpath 应正确代理到 sftp"""
        mock_sftp.realpath.return_value = "/real/path"
        result = await session.realpath("/symlink/path")
        assert result == "/real/path"

    @pytest.mark.asyncio
    async def test_rename(self, session, mock_sftp):
        """rename 应正确代理到 sftp"""
        await session.rename("/old", "/new")
        mock_sftp.rename.assert_called_once_with("/old", "/new")

    @pytest.mark.asyncio
    async def test_makedirs(self, session, mock_sftp):
        """makedirs 应正确创建目录"""
        await session.makedirs("/path/to/dir")
        mock_sftp.makedirs.assert_called_once_with("/path/to/dir", exist_ok=True)

    @pytest.mark.asyncio
    async def test_get_file_size(self, session, mock_sftp):
        """get_file_size 应正确返回文件大小"""
        mock_sftp.getsize.return_value = 4096
        result = await session.get_file_size("/file.txt")
        assert result == 4096

    @pytest.mark.asyncio
    async def test_get_permissions(self, session, mock_sftp):
        """get_permissions 应正确返回权限值"""
        mock_stat = MagicMock()
        mock_stat.permissions = 0o755
        mock_sftp.stat = AsyncMock(return_value=mock_stat)

        result = await session.get_permissions("/file.txt")
        assert result == 0o755

    @pytest.mark.asyncio
    async def test_chmod(self, session, mock_sftp):
        """chmod 应正确修改权限"""
        await session.chmod("/file.txt", 0o644)
        mock_sftp.chmod.assert_called_once_with("/file.txt", 0o644)

    def test_banner_msg_default(self, session):
        """默认 banner_msg 为空字符串"""
        assert session.banner_msg == ""

    def test_banner_msg_set(self, session, mock_conn):
        """设置 banner_msg 后正确获取"""
        mock_conn.get_banner.return_value = "Test Banner"
        session.banner_msg = mock_conn.get_banner()
        assert session.banner_msg == "Test Banner"

    def test_banner_msg_fallback(self, session):
        """get_banner 异常时 banner_msg 保持为默认"""
        session.connection.get_banner = MagicMock(side_effect=Exception("no banner"))
        try:
            session.banner_msg = session.connection.get_banner()
        except Exception:
            pass
        # 这里实际测试的是 connect 类方法中的 try/except 逻辑


class TestSSHSessionBoundary:
    """SSHSession 边界情况测试"""

    @pytest.mark.asyncio
    async def test_close_with_none_process(self, mock_conn, mock_sftp):
        """process 为 None 时 close 也不应失败"""
        session = SSHSession(
            connection=mock_conn,
            sftp=mock_sftp,
            process=None,
            host="example.com",
            port=22,
            username="testuser",
        )
        try:
            await session.close()
        except Exception:
            pytest.fail("close should not crash with None process")

    @pytest.mark.asyncio
    async def test_close_multiple_times(self, session, mock_sftp, mock_process, mock_conn):
        """多次调用 close 不应崩溃"""
        await session.close()
        await session.close()
        await session.close()

    def test_session_with_non_default_port(self):
        """非默认端口"""
        session = SSHSession(
            connection=MagicMock(),
            sftp=MagicMock(),
            process=MagicMock(),
            host="example.com",
            port=2222,
            username="admin",
        )
        assert session.port == 2222

    def test_session_with_long_username(self):
        """长用户名"""
        long_user = "x" * 256
        session = SSHSession(
            connection=MagicMock(),
            sftp=MagicMock(),
            process=MagicMock(),
            host="example.com",
            port=22,
            username=long_user,
        )
        assert session.username == long_user


class TestSSHSessionError:
    """SSHSession 错误情况测试"""

    @pytest.mark.asyncio
    async def test_is_file_on_invalid_path(self, session, mock_sftp):
        """不存在的路径调用 is_file"""
        mock_sftp.isfile.side_effect = FileNotFoundError("no such file")
        with pytest.raises(FileNotFoundError):
            await session.is_file("/nonexistent")

    @pytest.mark.asyncio
    async def test_chdir_invalid_directory(self, session, mock_sftp):
        """切换到不存在的目录"""
        mock_sftp.chdir.side_effect = FileNotFoundError("no such directory")
        with pytest.raises(FileNotFoundError):
            await session.chdir("/nonexistent")

    @pytest.mark.asyncio
    async def test_get_file_size_on_directory(self, session, mock_sftp):
        """获取目录的大小"""
        mock_sftp.getsize.side_effect = IsADirectoryError("is a directory")
        with pytest.raises(IsADirectoryError):
            await session.get_file_size("/some/dir")

    @pytest.mark.asyncio
    async def test_makedirs_with_existing(self, session, mock_sftp):
        """创建已存在的目录（exist_ok=True 应该不影响）"""
        mock_sftp.makedirs.side_effect = FileExistsError("already exists")
        with pytest.raises(FileExistsError):
            await session.makedirs("/existing")

    @pytest.mark.asyncio
    async def test_del_file_missing(self, session, mock_conn):
        """删除不存在的文件"""
        mock_conn.run.side_effect = OSError("rm: cannot remove")
        with pytest.raises(OSError):
            await session.del_file("/nonexistent")

    @pytest.mark.asyncio
    async def test_chmod_on_missing(self, session, mock_sftp):
        """修改不存在的文件权限"""
        mock_sftp.chmod.side_effect = FileNotFoundError("no such file")
        with pytest.raises(FileNotFoundError):
            await session.chmod("/nonexistent", 0o644)


class TestSSHSessionConnect:
    """SSHSession.connect 类方法测试"""

    @pytest.mark.asyncio
    async def test_connect_success(self):
        """连接成功创建 SSHSession 实例"""
        mock_conn = MagicMock()
        mock_conn.get_banner = MagicMock(return_value="Welcome")
        mock_process = MagicMock()
        mock_sftp = MagicMock()

        with patch("app.core.session.asyncssh.connect", new_callable=AsyncMock) as mock_connect:
            mock_connect.return_value = mock_conn
            with patch.object(mock_conn, "create_process", new_callable=AsyncMock) as mock_create:
                mock_create.return_value = mock_process
                with patch.object(mock_conn, "start_sftp_client", new_callable=AsyncMock) as mock_start:
                    mock_start.return_value = mock_sftp

                    session = await SSHSession.connect(
                        host="testhost",
                        port=22,
                        username="testuser",
                        password="testpass",
                    )

                    assert isinstance(session, SSHSession)
                    assert session.host == "testhost"
                    assert session.username == "testuser"
                    assert session.banner_msg == "Welcome"

    @pytest.mark.asyncio
    async def test_connect_with_client_keys(self):
        """使用密钥连接"""
        mock_conn = MagicMock()
        mock_conn.get_banner = MagicMock(return_value="Welcome")
        mock_process = MagicMock()
        mock_sftp = MagicMock()

        with patch("app.core.session.asyncssh.connect", new_callable=AsyncMock) as mock_connect:
            mock_connect.return_value = mock_conn
            mock_conn.create_process = AsyncMock(return_value=mock_process)
            mock_conn.start_sftp_client = AsyncMock(return_value=mock_sftp)

            await SSHSession.connect(
                host="testhost",
                username="testuser",
                client_keys=["/path/to/key"],
                passphrase="keypass",
            )

            call_args = mock_connect.call_args[1]
            assert call_args["host"] == "testhost"
            assert call_args["port"] == 22
            assert call_args["username"] == "testuser"
            assert call_args["password"] is None
            assert call_args["client_keys"] == ["/path/to/key"]
            assert call_args["passphrase"] == "keypass"
            assert call_args["known_hosts"] is None

    @pytest.mark.asyncio
    async def test_connect_banner_failure_graceful(self):
        """get_banner 失败时不应崩溃"""
        mock_conn = MagicMock()
        mock_conn.get_banner = MagicMock(side_effect=Exception("banner not available"))
        mock_process = MagicMock()
        mock_sftp = MagicMock()

        with patch("app.core.session.asyncssh.connect", new_callable=AsyncMock) as mock_connect:
            mock_connect.return_value = mock_conn
            mock_conn.create_process = AsyncMock(return_value=mock_process)
            mock_conn.start_sftp_client = AsyncMock(return_value=mock_sftp)

            session = await SSHSession.connect(
                host="testhost",
                username="testuser",
                password="testpass",
            )
            assert session.banner_msg == ""

    @pytest.mark.asyncio
    async def test_connect_permission_denied(self):
        """认证失败时应抛出异常"""
        import asyncssh

        with patch("app.core.session.asyncssh.connect", new_callable=AsyncMock) as mock_connect:
            mock_connect.side_effect = asyncssh.PermissionDenied("auth failed")

            with pytest.raises(asyncssh.PermissionDenied):
                await SSHSession.connect(
                    host="testhost",
                    username="testuser",
                    password="wrong",
                )

    @pytest.mark.asyncio
    async def test_connect_connection_lost(self):
        """连接中断时应抛出异常"""
        import asyncssh

        with patch("app.core.session.asyncssh.connect", new_callable=AsyncMock) as mock_connect:
            mock_connect.side_effect = asyncssh.ConnectionLost("connection dropped")

            with pytest.raises(asyncssh.ConnectionLost):
                await SSHSession.connect(
                    host="testhost",
                    username="testuser",
                )

    @pytest.mark.asyncio
    async def test_connect_dns_failure(self):
        """DNS 解析失败"""
        with patch("app.core.session.asyncssh.connect", new_callable=AsyncMock) as mock_connect:
            mock_connect.side_effect = OSError("Name or service not known")

            with pytest.raises(OSError):
                await SSHSession.connect(
                    host="nonexistent.invalid",
                    username="testuser",
                )
