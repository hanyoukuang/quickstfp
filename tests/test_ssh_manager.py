from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.service.ssh_manager import SSHManager, SessionNotFoundError
from app.core.session import SSHSession


@pytest.fixture
def manager():
    return SSHManager()


@pytest.fixture
def mock_session():
    session = MagicMock(spec=SSHSession)
    session.close = AsyncMock()
    session.host = "example.com"
    session.port = 22
    session.username = "root"
    session.banner_msg = "Welcome"
    session.connection = MagicMock()
    session.sftp = MagicMock()
    session.process = MagicMock()
    return session


class TestSSHManager:
    """SSHManager 正常情况测试"""

    @pytest.mark.asyncio
    async def test_connect_returns_session_id(self, manager, mock_session):
        """connect 成功后返回 session_id"""
        with patch.object(SSHSession, "connect", new_callable=AsyncMock, return_value=mock_session) as mock_connect:
            session_id = await manager.connect(
                host="example.com",
                port=22,
                username="root",
                password="secret",
            )
            assert isinstance(session_id, str)
            assert len(session_id) > 0
            args = mock_connect.call_args[1]
            assert args["host"] == "example.com"
            assert args["port"] == 22
            assert args["password"] == "secret"

    @pytest.mark.asyncio
    async def test_get_returns_session(self, manager, mock_session):
        """get 返回正确的会话"""
        with patch.object(SSHSession, "connect", new_callable=AsyncMock, return_value=mock_session):
            session_id = await manager.connect(host="example.com", username="root")
        session = manager.get(session_id)
        assert session is mock_session

    @pytest.mark.asyncio
    async def test_get_or_none_returns_session(self, manager, mock_session):
        """get_or_none 返回正确的会话"""
        with patch.object(SSHSession, "connect", new_callable=AsyncMock, return_value=mock_session):
            session_id = await manager.connect(host="example.com", username="root")
        session = manager.get_or_none(session_id)
        assert session is mock_session

    @pytest.mark.asyncio
    async def test_get_or_none_returns_none_for_unknown(self, manager):
        """get_or_none 对未知 session_id 返回 None"""
        assert manager.get_or_none("nonexistent") is None

    @pytest.mark.asyncio
    async def test_disconnect_removes_session(self, manager, mock_session):
        """disconnect 移除并关闭会话"""
        with patch.object(SSHSession, "connect", new_callable=AsyncMock, return_value=mock_session):
            session_id = await manager.connect(host="example.com", username="root")

        await manager.disconnect(session_id)
        mock_session.close.assert_called_once()
        assert manager.get_or_none(session_id) is None

    @pytest.mark.asyncio
    async def test_list_sessions(self, manager, mock_session):
        """list_sessions 返回所有活跃 session_id"""
        with patch.object(SSHSession, "connect", new_callable=AsyncMock, return_value=mock_session):
            sid1 = await manager.connect(host="a.com", username="r1")
            sid2 = await manager.connect(host="b.com", username="r2")

        sessions = manager.list_sessions()
        assert len(sessions) == 2
        assert sid1 in sessions
        assert sid2 in sessions

    @pytest.mark.asyncio
    async def test_is_active(self, manager, mock_session):
        """is_active 正确判断会话活跃状态"""
        with patch.object(SSHSession, "connect", new_callable=AsyncMock, return_value=mock_session):
            session_id = await manager.connect(host="example.com", username="root")

        assert manager.is_active(session_id)
        await manager.disconnect(session_id)
        assert not manager.is_active(session_id)

    @pytest.mark.asyncio
    async def test_active_count(self, manager, mock_session):
        """active_count 返回正确数量"""
        assert manager.active_count == 0

        with patch.object(SSHSession, "connect", new_callable=AsyncMock, return_value=mock_session):
            await manager.connect(host="a.com", username="r1")
            assert manager.active_count == 1
            await manager.connect(host="b.com", username="r2")
            assert manager.active_count == 2

        await manager.disconnect_all()
        assert manager.active_count == 0

    @pytest.mark.asyncio
    async def test_disconnect_all(self, manager, mock_session):
        """disconnect_all 关闭所有会话"""
        with patch.object(SSHSession, "connect", new_callable=AsyncMock, return_value=mock_session):
            await manager.connect(host="a.com", username="r1")
            await manager.connect(host="b.com", username="r2")
            await manager.connect(host="c.com", username="r3")

        await manager.disconnect_all()
        assert mock_session.close.call_count == 3
        assert manager.active_count == 0

    @pytest.mark.asyncio
    async def test_multiple_connections_unique_ids(self, manager, mock_session):
        """多次连接返回不同的 session_id"""
        with patch.object(SSHSession, "connect", new_callable=AsyncMock, return_value=mock_session):
            ids = set()
            for i in range(10):
                sid = await manager.connect(host=f"host{i}.com", username=f"user{i}")
                ids.add(sid)
            assert len(ids) == 10

    @pytest.mark.asyncio
    async def test_connect_with_client_keys(self, manager, mock_session):
        """使用密钥登录"""
        with patch.object(SSHSession, "connect", new_callable=AsyncMock, return_value=mock_session) as mock_connect:
            await manager.connect(
                host="example.com",
                username="root",
                client_keys=["/path/to/key"],
                passphrase="key_pass",
            )
            args = mock_connect.call_args[1]
            assert args["host"] == "example.com"
            assert args["username"] == "root"
            assert args["client_keys"] == ["/path/to/key"]
            assert args["passphrase"] == "key_pass"


class TestSSHManagerBoundary:
    """SSHManager 边界情况测试"""

    @pytest.mark.asyncio
    async def test_disconnect_nonexistent_session(self):
        """disconnect 不存在的会话应抛出 SessionNotFoundError"""
        manager = SSHManager()
        with pytest.raises(SessionNotFoundError, match="not found"):
            await manager.disconnect("nonexistent")

    @pytest.mark.asyncio
    async def test_get_nonexistent_session(self):
        """get 不存在的会话应抛出 SessionNotFoundError"""
        manager = SSHManager()
        with pytest.raises(SessionNotFoundError, match="not found"):
            manager.get("nonexistent")

    @pytest.mark.asyncio
    async def test_empty_manager_list_sessions(self):
        """空管理器的 list_sessions 返回空列表"""
        manager = SSHManager()
        assert manager.list_sessions() == []

    @pytest.mark.asyncio
    async def test_empty_manager_active_count(self):
        """空管理器的 active_count 为 0"""
        manager = SSHManager()
        assert manager.active_count == 0

    @pytest.mark.asyncio
    async def test_empty_manager_is_active(self):
        """空管理器的 is_active 返回 False"""
        manager = SSHManager()
        assert not manager.is_active("any_id")

    @pytest.mark.asyncio
    async def test_disconnect_all_on_empty_manager(self):
        """空管理器上调用 disconnect_all 不报错"""
        manager = SSHManager()
        await manager.disconnect_all()
        assert manager.active_count == 0

    @pytest.mark.asyncio
    async def test_session_id_not_reusable_after_disconnect(self, manager, mock_session):
        """断开会话后 session_id 不能被 get 获取"""
        with patch.object(SSHSession, "connect", new_callable=AsyncMock, return_value=mock_session):
            session_id = await manager.connect(host="example.com", username="root")

        await manager.disconnect(session_id)
        with pytest.raises(SessionNotFoundError):
            manager.get(session_id)


class TestSSHManagerError:
    """SSHManager 错误情况测试"""

    @pytest.mark.asyncio
    async def test_connect_with_empty_host(self):
        """host 为空时抛出 ValueError"""
        manager = SSHManager()
        with pytest.raises(ValueError, match="host must not be empty"):
            await manager.connect(host="", username="root")

    @pytest.mark.asyncio
    async def test_connect_with_empty_username(self):
        """username 为空时抛出 ValueError"""
        manager = SSHManager()
        with pytest.raises(ValueError, match="username must not be empty"):
            await manager.connect(host="example.com", username="")

    @pytest.mark.asyncio
    async def test_connect_with_empty_host_and_username(self):
        """host 和 username 都为空时抛出 ValueError"""
        manager = SSHManager()
        with pytest.raises(ValueError, match="host must not be empty"):
            await manager.connect(host="", username="")

    @pytest.mark.asyncio
    async def test_disconnect_closed_session_safe(self, manager, mock_session):
        """关闭一个已关闭的会话不应崩溃（由 SessionNotFoundError 捕获）"""
        with patch.object(SSHSession, "connect", new_callable=AsyncMock, return_value=mock_session):
            session_id = await manager.connect(host="example.com", username="root")

        await manager.disconnect(session_id)
        # 第二次断开应抛出 SessionNotFoundError
        with pytest.raises(SessionNotFoundError):
            await manager.disconnect(session_id)

    @pytest.mark.asyncio
    async def test_disconnect_all_handles_exceptions(self, manager):
        """disconnect_all 即使某个会话 close 报错也应继续"""
        session1 = MagicMock(spec=SSHSession)
        session1.close = AsyncMock(side_effect=OSError("connection lost"))
        session2 = MagicMock(spec=SSHSession)
        session2.close = AsyncMock()

        with patch.object(SSHSession, "connect", new_callable=AsyncMock, side_effect=[session1, session2]):
            await manager.connect(host="a.com", username="r1")
            await manager.connect(host="b.com", username="r2")

        await manager.disconnect_all()
        session1.close.assert_called_once()
        session2.close.assert_called_once()
        assert manager.active_count == 0
