from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from core.session import SSHSFTPInfo


class SFTPFileManager:
    """
    SFTP 文件操作门面。
    将文件系统操作从 SSHSFTPInfo 中分离，提供聚焦的文件操作接口。
    通过组合模式包装底层 SSHSFTPInfo，可与 ISFTPConnection 协议兼容。
    """

    def __init__(self, session: 'SSHSFTPInfo'):
        self._session = session

    def is_file(self, path: str) -> bool:
        return self._session.is_file(path)

    def chdir(self, path: str) -> None:
        self._session.chdir(path)

    def getcwd(self) -> str:
        return self._session.getcwd()

    def read_file(self, path: str) -> str:
        return self._session.read_file(path)

    def save_file(self, path: str, text: str) -> None:
        self._session.save_file(path, text)

    def realpath(self, path: str) -> str:
        return self._session.realpath(path)

    def del_file(self, path: str) -> None:
        self._session.del_file(path)

    def makedirs(self, path: str) -> None:
        self._session.makedirs(path)

    def copy_file(self, old_path: str, new_path: str) -> None:
        self._session.copy_file(old_path, new_path)

    def move_file(self, old_path: str, new_path: str) -> None:
        self._session.move_file(old_path, new_path)

    def rename(self, old_name: str, new_name: str) -> None:
        self._session.rename(old_name, new_name)

    def get_file_size(self, path: str) -> int:
        return self._session.get_file_size(path)

    def get_permissions(self, path: str) -> int:
        return self._session.get_permissions(path)

    def chmod(self, path: str, permissions: int) -> None:
        self._session.chmod(path, permissions)

    @property
    def sftp(self):
        return self._session.sftp

    @property
    def connection(self):
        return self._session.connection
