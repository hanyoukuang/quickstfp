# core/session.py
import asyncio
from asyncio import AbstractEventLoop
from typing import Optional, List

import asyncssh
from PySide6.QtCore import QThread
from asyncssh import SFTPClient, SSHClientProcess, SSHClientConnection


class SSHSFTPInfo(QThread):
    """
    SSH 与 SFTP 连接的核心管理类。
    负责维护底层的 asyncssh 连接、SFTP 会话和伪终端进程，
    并在独立的 QThread 中运行 asyncio 的事件循环。
    """
    sftp: SFTPClient
    connection: SSHClientConnection
    process: SSHClientProcess
    loop: AbstractEventLoop
    connect_is_ready: bool = False

    def __init__(
            self,
            host: str,
            port: int,
            username: str,
            password: Optional[str] = None,
            client_keys: Optional[List[str]] = None,
            passphrase: Optional[str] = None
    ):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client_keys = client_keys
        self.passphrase = passphrase

        # 初始化并在主线程阻塞等待连接建立完成
        self.loop = asyncio.new_event_loop()
        self.loop.run_until_complete(self.get_session())

    async def get_session(self) -> None:
        """异步建立 SSH 连接、初始化 SFTP 客户端及终端进程"""
        self.connection = await asyncssh.connect(
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            client_keys=self.client_keys,
            passphrase=self.passphrase,
            known_hosts=None
        )
        self.sftp = await self.connection.start_sftp_client()
        self.process = await self.connection.create_process(
            request_pty=True,
            term_type='xterm',
            term_size=(80, 24)
        )
        self.connect_is_ready = True

    def is_file(self, path: str) -> bool:
        """判断远端路径是否为文件"""
        future = asyncio.run_coroutine_threadsafe(self.sftp.isfile(path), self.loop)
        return future.result()

    def chdir(self, path: str) -> None:
        """切换远端工作目录"""
        future = asyncio.run_coroutine_threadsafe(self.sftp.chdir(path), self.loop)
        future.result()

    def getcwd(self) -> str:
        """获取远端当前工作目录"""
        future = asyncio.run_coroutine_threadsafe(self.sftp.getcwd(), self.loop)
        return future.result()

    async def _read_file(self, path: str) -> str:
        text = ""
        async with self.sftp.open(path, "rb") as fp:
            text = (await fp.read()).decode('u8')
        return text

    async def _save_file(self, src: str, text: str) -> None:
        async with self.sftp.open(src, 'wb') as f:
            await f.write(text.encode())

    def read_file(self, path: str) -> str:
        """读取远端文件内容"""
        future = asyncio.run_coroutine_threadsafe(self._read_file(path), self.loop)
        return future.result()

    def save_file(self, path: str, text: str) -> None:
        """保存内容到远端文件"""
        future = asyncio.run_coroutine_threadsafe(self._save_file(path, text), self.loop)
        future.result()

    def realpath(self, path: str) -> str:
        """获取远端绝对路径"""
        future = asyncio.run_coroutine_threadsafe(self.sftp.realpath(path), self.loop)
        return future.result()

    def del_file(self, path: str) -> None:
        """删除远端文件或目录"""
        future = asyncio.run_coroutine_threadsafe(self.connection.run(f"rm -rf {path}\n"), self.loop)
        future.result()

    def makedirs(self, path: str) -> None:
        """在远端创建目录"""
        future = asyncio.run_coroutine_threadsafe(self.sftp.makedirs(path, exist_ok=True), self.loop)
        future.result()

    def copy_file(self, old_path: str, new_path: str) -> None:
        """在远端复制文件"""
        future = asyncio.run_coroutine_threadsafe(self.connection.run(f"cp -rf {old_path} {new_path}\n"), self.loop)
        future.result()

    def move_file(self, old_path: str, new_path: str) -> None:
        """在远端移动文件"""
        future = asyncio.run_coroutine_threadsafe(self.connection.run(f"mv {old_path} {new_path}\n"), self.loop)
        future.result()

    def rename(self, old_name: str, new_name: str) -> None:
        """在远端重命名文件"""
        future = asyncio.run_coroutine_threadsafe(self.sftp.rename(old_name, new_name), self.loop)
        future.result()

    def run(self) -> None:
        """启动独立线程中的 asyncio 事件循环"""
        self.loop.run_forever()
