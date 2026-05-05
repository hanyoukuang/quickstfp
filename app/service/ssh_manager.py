import secrets
from typing import Optional, List

from app.core.session import SSHSession


class SSHManagerError(Exception):
    """SSHManager 相关错误"""
    pass


class SessionNotFoundError(SSHManagerError):
    """会话不存在错误"""
    pass


class SSHManager:
    """
    SSH 会话生命周期管理器。
    负责创建、存储、检索和销毁 SSH 会话实例。

    用法:
        manager = SSHManager()
        session_id = await manager.connect(host="example.com", username="root", password="pass")
        session = manager.get(session_id)
        await manager.disconnect(session_id)
    """

    def __init__(self):
        self._sessions: dict[str, SSHSession] = {}

    async def connect(
        self,
        host: str,
        port: int = 22,
        username: str = "",
        password: Optional[str] = None,
        client_keys: Optional[List[str]] = None,
        passphrase: Optional[str] = None,
    ) -> str:
        """
        建立新的 SSH 连接并返回 session_id。

        Raises:
            ValueError: host 或 username 为空
            asyncssh.PermissionDenied: 认证失败
            OSError: DNS/网络不可达
            asyncssh.ConnectionLost: 连接异常中断
        """
        if not host:
            raise ValueError("host must not be empty")
        if not username:
            raise ValueError("username must not be empty")

        session = await SSHSession.connect(
            host=host,
            port=port,
            username=username,
            password=password,
            client_keys=client_keys,
            passphrase=passphrase,
        )

        session_id = secrets.token_urlsafe(16)
        self._sessions[session_id] = session

        return session_id

    def get(self, session_id: str) -> SSHSession:
        """
        根据 session_id 获取会话实例。

        Raises:
            SessionNotFoundError: 会话不存在
        """
        if session_id not in self._sessions:
            raise SessionNotFoundError(f"Session '{session_id}' not found")
        return self._sessions[session_id]

    def get_or_none(self, session_id: str) -> Optional[SSHSession]:
        """根据 session_id 获取会话实例，不存在返回 None"""
        return self._sessions.get(session_id)

    async def disconnect(self, session_id: str) -> None:
        """
        断开并清理指定的会话。

        Raises:
            SessionNotFoundError: 会话不存在
        """
        session = self.get(session_id)
        await session.close()
        del self._sessions[session_id]

    def list_sessions(self) -> list[str]:
        """列出所有活跃的 session_id"""
        return list(self._sessions.keys())

    def is_active(self, session_id: str) -> bool:
        """检查会话是否活跃"""
        return session_id in self._sessions

    async def disconnect_all(self) -> None:
        """断开并清理所有会话"""
        session_ids = list(self._sessions.keys())
        for sid in session_ids:
            try:
                session = self._sessions[sid]
                await session.close()
            except Exception:
                pass
        self._sessions.clear()

    @property
    def active_count(self) -> int:
        """活跃会话数量"""
        return len(self._sessions)
