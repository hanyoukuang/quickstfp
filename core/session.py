# core/session.py
import asyncio
import shlex
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
            passphrase: Optional[str] = None,
            verify_host_key: bool = True,
            startup_commands: Optional[List[str]] = None,
    ):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client_keys = client_keys
        self.passphrase = passphrase
        self.banner_msg = ""
        self.verify_host_key = verify_host_key
        self.startup_commands = startup_commands or []
        self._reconnect_enabled = True
        self._reconnect_delay = 1

        # 用于在主线程和后台线程间同步连接状态
        self.connect_is_ready = False
        self.connect_error = None
        self.connect_event = threading.Event()
        self._host_key_warning = False
        self._host_key_fingerprint = ""

    def wait_for_connection(self, timeout: float = 30.0):
        """主线程调用此方法来等待连接完成，期间保持 UI 刷新"""
        event_loop = QEventLoop()
        poll_timer = QTimer()
        timeout_timer = QTimer()
        timed_out = False

        def check_status():
            if self.connect_event.is_set():
                poll_timer.stop()
                if timeout_timer.isActive():
                    timeout_timer.stop()
                event_loop.quit()

        def on_timeout():
            nonlocal timed_out
            timed_out = True
            poll_timer.stop()
            event_loop.quit()

        poll_timer.timeout.connect(check_status)
        poll_timer.start(50)
        timeout_timer.setSingleShot(True)
        timeout_timer.timeout.connect(on_timeout)
        timeout_timer.start(int(timeout * 1000))
        event_loop.exec()

        if timed_out:
            raise TimeoutError(f"连接超时 ({timeout}s)")

        if self.connect_error:
            raise self.connect_error

    def _wait_future(self, future, timeout: float = None):
        event_loop = QEventLoop()
        poll_timer = QTimer()
        timeout_timer = QTimer()
        timed_out = False

        def check_status():
            if future.done():
                poll_timer.stop()
                if timeout_timer.isActive():
                    timeout_timer.stop()
                event_loop.quit()

        def on_timeout():
            nonlocal timed_out
            timed_out = True
            poll_timer.stop()
            event_loop.quit()

        poll_timer.timeout.connect(check_status)
        poll_timer.start(20)

        if timeout is not None:
            timeout_timer.setSingleShot(True)
            timeout_timer.timeout.connect(on_timeout)
            timeout_timer.start(int(timeout * 1000))

        event_loop.exec()

        if timed_out:
            raise TimeoutError(f"操作超时 ({timeout}s)")

        return future.result()

    async def get_session(self) -> None:
        """异步建立 SSH 连接、初始化 SFTP 客户端及终端进程"""

        try:
            self.connection = await asyncssh.connect(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                client_keys=self.client_keys,
                passphrase=self.passphrase,
                known_hosts=asyncssh.SSHKnownHosts() if self.verify_host_key else None,
                connect_timeout=10,
                keepalive_interval=30,
                keepalive_count_max=3,
            )
        except asyncssh.HostKeyNotVerifiable as e:
            self._host_key_warning = True
            self._host_key_fingerprint = str(e)
            return
        self.process = await self.connection.create_process(
            request_pty=True,
            term_type='xterm-256color',
            term_size=(80, 24)
        )
        self.sftp = await self.connection.start_sftp_client()

        for cmd in self.startup_commands:
            try:
                self.process.stdin.write(cmd + "\n")
                await self.process.stdin.drain()
            except Exception:
                pass

    def _run_sync(self, coro):
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return self._wait_future(future)

    def forward_local_port(self, listen_host: str, listen_port: int, remote_host: str, remote_port: int):
        async def _fwd():
            await self.connection.forward_local_port(listen_host, listen_port, remote_host, remote_port)
        self._run_sync(_fwd())

    def forward_remote_port(self, listen_host: str, listen_port: int, local_host: str, local_port: int):
        async def _fwd():
            await self.connection.forward_remote_port(listen_host, listen_port, local_host, local_port)
        self._run_sync(_fwd())

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
        return self._run_sync(self.connection.run(f"rm -rf {shlex.quote(path)}\n"))

    def makedirs(self, path: str) -> None:
        return self._run_sync(self.sftp.makedirs(path, exist_ok=True))

    def copy_file(self, old_path: str, new_path: str) -> None:
        return self._run_sync(self.connection.run(f"cp -rf {shlex.quote(old_path)} {shlex.quote(new_path)}\n"))

    def move_file(self, old_path: str, new_path: str) -> None:
        return self._run_sync(self.connection.run(f"mv {shlex.quote(old_path)} {shlex.quote(new_path)}\n"))

    def rename(self, old_name: str, new_name: str) -> None:
        return self._run_sync(self.sftp.rename(old_name, new_name))

    def get_file_size(self, path: str) -> int:
        return self._run_sync(self.sftp.getsize(path))

    def get_permissions(self, path: str) -> int:
        """获取远端文件/文件夹的权限 (返回十进制的 stat 权限值)"""
        attrs = self._run_sync(self.sftp.stat(path))
        return attrs.permissions

    def chmod(self, path: str, permissions: int) -> None:
        """修改远端文件/文件夹的权限"""
        self._run_sync(self.sftp.chmod(path, permissions))

    def run(self) -> None:
        """启动独立线程中的 asyncio 事件循环"""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self.get_session())
            if not self._host_key_warning:
                self.connect_is_ready = True
        except Exception as e:
            self.connect_error = e
        finally:
            self.connect_event.set()

        if self.connect_is_ready:
            self.loop.run_forever()

    def close_session(self):
        """
        线程安全地关闭会话，取消所有后台协程，防止 Task destroyed but it is pending 报错
        """
        if getattr(self, 'loop', None) is None or not self.loop.is_running():
            return

        async def _cleanup():
            # 1. 正常关闭 SSH/SFTP/Process 等底层连接
            if getattr(self, 'sftp', None):
                self.sftp.exit()
            if getattr(self, 'process', None):
                self.process.close()
            if getattr(self, 'connection', None):
                self.connection.close()

            # 2. 找出当前事件循环中除了“清理任务本身”之外的所有挂起的 Task
            current_task = asyncio.current_task(self.loop)
            tasks = [t for t in asyncio.all_tasks(self.loop) if t is not current_task]

            # 3. 向这些任务发送终止(Cancel)信号
            for task in tasks:
                task.cancel()

            # 4. 等待这些任务处理完 CancelledError 并彻底结束
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

            # 5. 所有任务清理完毕后，安全停止事件循环
            self.loop.stop()

        # 将上面的异步清理逻辑通过线程安全的通道丢给后台 asyncio 去执行
        asyncio.run_coroutine_threadsafe(_cleanup(), self.loop)
