import asyncssh
from asyncssh import SFTPClient, SSHClientProcess, SSHClientConnection
from typing import Optional, List


class SSHSession:
    """
    纯异步 SSH 会话类，不再继承 QThread。
    所有操作均为 async 方法，由调用方在同一个 asyncio 事件循环中调度。
    """
    connection: SSHClientConnection
    sftp: SFTPClient
    process: SSHClientProcess

    def __init__(
        self,
        connection: SSHClientConnection,
        sftp: SFTPClient,
        process: SSHClientProcess,
        host: str,
        port: int,
        username: str,
    ):
        self.connection = connection
        self.sftp = sftp
        self.process = process
        self.host = host
        self.port = port
        self.username = username
        self.banner_msg = ""

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int = 22,
        username: str = "",
        password: Optional[str] = None,
        client_keys: Optional[List[str]] = None,
        passphrase: Optional[str] = None,
    ) -> "SSHSession":
        """
        建立 SSH 连接、创建终端进程和 SFTP 客户端，返回 SSHSession 实例。

        Raises:
            asyncssh.PermissionDenied: 认证失败
            asyncssh.ConnectionLost: 连接意外中断
            OSError: DNS/网络不可达
        """
        connection = await asyncssh.connect(
            host=host,
            port=port,
            username=username,
            password=password,
            client_keys=client_keys,
            passphrase=passphrase,
            known_hosts=None,
        )
        process = await connection.create_process(
            request_pty=True,
            term_type="xterm-256color",
            term_size=(80, 24),
        )
        sftp = await connection.start_sftp_client()

        session = cls(
            connection=connection,
            sftp=sftp,
            process=process,
            host=host,
            port=port,
            username=username,
        )

        try:
            session.banner_msg = connection.get_banner() or ""
        except Exception:
            session.banner_msg = ""

        return session

    async def close(self):
        """关闭 SSH 会话，释放所有底层资源"""
        if getattr(self, "sftp", None):
            self.sftp.exit()
        if getattr(self, "process", None):
            self.process.close()
        if getattr(self, "connection", None):
            self.connection.close()

    async def is_file(self, path: str) -> bool:
        return await self.sftp.isfile(path)

    async def chdir(self, path: str) -> None:
        await self.sftp.chdir(path)

    async def getcwd(self) -> str:
        return await self.sftp.getcwd()

    async def read_file(self, path: str) -> str:
        async with self.sftp.open(path, "rb") as fp:
            return (await fp.read()).decode("u8")

    async def save_file(self, path: str, text: str) -> None:
        async with self.sftp.open(path, "wb") as f:
            await f.write(text.encode())

    async def realpath(self, path: str) -> str:
        return await self.sftp.realpath(path)

    async def del_file(self, path: str) -> None:
        await self.connection.run(f"rm -rf {path}\n")

    async def makedirs(self, path: str) -> None:
        await self.sftp.makedirs(path, exist_ok=True)

    async def copy_file(self, old_path: str, new_path: str) -> None:
        await self.connection.run(f"cp -rf {old_path} {new_path}\n")

    async def move_file(self, old_path: str, new_path: str) -> None:
        await self.connection.run(f"mv {old_path} {new_path}\n")

    async def rename(self, old_name: str, new_name: str) -> None:
        await self.sftp.rename(old_name, new_name)

    async def get_file_size(self, path: str) -> int:
        return await self.sftp.getsize(path)

    async def get_permissions(self, path: str) -> int:
        attrs = await self.sftp.stat(path)
        return attrs.permissions

    async def chmod(self, path: str, permissions: int) -> None:
        await self.sftp.chmod(path, permissions)
