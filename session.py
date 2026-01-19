import asyncio
from asyncio import AbstractEventLoop

import asyncssh
from PySide6.QtCore import QThread
from asyncssh import SFTPClient, SSHClientProcess, SSHClientConnection


class SSHSFTPInfo(QThread):
    sftp: SFTPClient
    connection: SSHClientConnection
    process: SSHClientProcess
    loop: AbstractEventLoop
    connect_is_ready: bool = False

    def __init__(self, host: str, port: int, username: str, password: str = None, client_keys: list = None,
                 passphrase: str = None):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client_keys = client_keys
        self.passphrase = passphrase
        self.loop = asyncio.new_event_loop()
        self.loop.run_until_complete(self.get_session())

    async def get_session(self):
        self.connection = await asyncssh.connect(host=self.host, port=self.port, username=self.username,
                                                 password=self.password, client_keys=self.client_keys,
                                                 passphrase=self.passphrase, known_hosts=None)
        self.sftp = await self.connection.start_sftp_client()
        self.process = await self.connection.create_process(request_pty=True,
                                                            term_type='xterm',
                                                            term_size=(80, 24))

    def is_file(self, path: str) -> bool:
        future = asyncio.run_coroutine_threadsafe(self.sftp.isfile(path), self.loop)
        return future.result()

    def chdir(self, path: str) -> None:
        future = asyncio.run_coroutine_threadsafe(self.sftp.chdir(path), self.loop)
        future.result()

    def getcwd(self) -> str:
        future = asyncio.run_coroutine_threadsafe(self.sftp.getcwd(), self.loop)
        return future.result()

    async def _read_file(self, path: str) -> str:
        text = ""
        async with self.sftp.open(path, "rb") as fp:
            try:
                text = (await fp.read()).decode('u8')
            except Exception as e:
                raise e
        return text

    async def _save_file(self, src: str, text: str) -> None:
        async with self.sftp.open(src, 'wb') as f:
            await f.write(text.encode())

    def read_file(self, path: str) -> str:
        future = asyncio.run_coroutine_threadsafe(self._read_file(path), self.loop)
        return future.result()

    def save_file(self, path: str, text: str) -> None:
        future = asyncio.run_coroutine_threadsafe(self._save_file(path, text), self.loop)
        future.result()

    def realpath(self, path: str) -> str:
        future = asyncio.run_coroutine_threadsafe(self.sftp.realpath(path), self.loop)
        return future.result()

    def del_file(self, path: str):
        future = asyncio.run_coroutine_threadsafe(self.connection.run(f"rm -rf {path}\n"), self.loop)
        future.result()

    def makedirs(self, path: str) -> None:
        future = asyncio.run_coroutine_threadsafe(self.sftp.makedirs(path, exist_ok=True), self.loop)
        future.result()

    def copy_file(self, old_path: str, new_path: str) -> None:
        future = asyncio.run_coroutine_threadsafe(self.connection.run(f"cp -rf {old_path} {new_path}\n"), self.loop)
        future.result()

    def move_file(self, old_path: str, new_path: str) -> None:
        future = asyncio.run_coroutine_threadsafe(self.connection.run(f"mv {old_path} {new_path}\n"), self.loop)
        future.result()

    def rename(self, old_name: str, new_name: str) -> None:
        future = asyncio.run_coroutine_threadsafe(self.sftp.rename(old_name, new_name), self.loop)
        future.result()

    def run(self):
        self.loop.run_forever()
