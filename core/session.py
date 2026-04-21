# core/session.py
import asyncio
import threading
from asyncio import AbstractEventLoop
from typing import Optional, List

import asyncssh
from PySide6.QtCore import QThread, QEventLoop, QTimer
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
        self.banner_msg = ""

        # 用于在主线程和后台线程间同步连接状态
        self.connect_is_ready = False
        self.connect_error = None
        self.connect_event = threading.Event()

    def wait_for_connection(self):
        """主线程调用此方法来等待连接完成，期间保持 UI 刷新"""
        event_loop = QEventLoop()
        timer = QTimer()

        # 每 50ms 检查一次后台线程是否连上了
        def check_status():
            if self.connect_event.is_set():
                event_loop.quit()

        timer.timeout.connect(check_status)
        timer.start(50)
        event_loop.exec()  # 开启局部事件循环，阻止代码往下走，但允许 UI 刷新

        # 如果连接报错，将异常抛给主线程
        if self.connect_error:
            raise self.connect_error

    def _wait_future(self, future):
        """通用的局部阻塞等待机制：在等待网络请求时保持 GUI 界面存活"""
        event_loop = QEventLoop()
        timer = QTimer()

        def check_status():
            if future.done():
                event_loop.quit()

        timer.timeout.connect(check_status)
        timer.start(20)  # 20ms 的高频检查
        event_loop.exec()

        # 事件循环退出时，future 必定已完成
        return future.result()

    async def get_session(self) -> None:
        """异步建立 SSH 连接、初始化 SFTP 客户端及终端进程"""

        # 【修改】将拦截器通过 client_factory 注入到连接中
        self.connection = await asyncssh.connect(
            host=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            client_keys=self.client_keys,
            passphrase=self.passphrase,
            known_hosts=None,
        )
        self.process = await self.connection.create_process(
            request_pty=True,
            term_type='xterm-256color',
            term_size=(80, 24)
        )
        self.sftp = await self.connection.start_sftp_client()

    def _run_sync(self, coro):
        """统一封装异步协程的同步等待"""
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return self._wait_future(future)

    def is_file(self, path: str) -> bool:
        return self._run_sync(self.sftp.isfile(path))

    def chdir(self, path: str) -> None:
        self._run_sync(self.sftp.chdir(path))

    def getcwd(self) -> str:
        return self._run_sync(self.sftp.getcwd())

    async def _read_file(self, path: str) -> str:
        async with self.sftp.open(path, "rb") as fp:
            return (await fp.read()).decode('u8')

    async def _save_file(self, src: str, text: str) -> None:
        async with self.sftp.open(src, 'wb') as f:
            await f.write(text.encode())

    def read_file(self, path: str) -> str:
        return self._run_sync(self._read_file(path))

    def save_file(self, path: str, text: str) -> None:
        self._run_sync(self._save_file(path, text))

    def realpath(self, path: str) -> str:
        return self._run_sync(self.sftp.realpath(path))

    def del_file(self, path: str) -> None:
        return self._run_sync(self.connection.run(f"rm -rf {path}\n"))

    def makedirs(self, path: str) -> None:
        return self._run_sync(self.sftp.makedirs(path, exist_ok=True))

    def copy_file(self, old_path: str, new_path: str) -> None:
        return self._run_sync(self.connection.run(f"cp -rf {old_path} {new_path}\n"))

    def move_file(self, old_path: str, new_path: str) -> None:
        return self._run_sync(self.connection.run(f"mv {old_path} {new_path}\n"))

    def rename(self, old_name: str, new_name: str) -> None:
        return self._run_sync(self.sftp.rename(old_name, new_name))

    def get_file_size(self, path: str) -> int:
        return self._run_sync(self.sftp.getsize(path))

    def run(self) -> None:
        """启动独立线程中的 asyncio 事件循环"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self.get_session())
            self.connect_is_ready = True
        except Exception as e:
            self.connect_error = e
        finally:
            self.connect_event.set()

        if self.connect_is_ready:
            self.loop.run_forever()
