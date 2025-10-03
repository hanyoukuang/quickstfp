import os
import sys
import asyncio
import time
from typing import Sequence
import asyncssh
import asyncio_pool
from PySide6.QtGui import QAction, QDropEvent, QDragEnterEvent, QCloseEvent
from PySide6.QtCore import QThread, Signal, Slot, Qt, QPoint, QModelIndex, QMutex
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
    QProgressBar, QLineEdit, QLabel, QPushButton, QStyle, QListWidget,
    QListWidgetItem, QTextEdit, QStackedWidget, QFileDialog, QMenu,
    QInputDialog, QMainWindow, QTabWidget, QComboBox, QCheckBox,
    QAbstractItemView, QSplitter, QMessageBox, QToolBar
)
from qdarktheme import setup_theme
from user_database import UserInfoData

# Attempt to import uvloop for enhanced async performance, compatible with Windows and other platforms
try:
    import uvloop
except ImportError:
    import winuvloop as uvloop
finally:
    uvloop.install()


def path_stand(src: str, loc: str) -> tuple[str, str]:
    """
    Standardizes file path formats and appends the source file/folder name to the destination path.
    Example:
        src = "c:\\path\\to\\src\\" -> "c:/path/to/src"
        loc = "c:\\path\\to\\loc\\" -> "c:/path/to/loc/src"

    :param src: Source file or folder path to standardize.
    :param loc: Destination path to append the source name to.
    :return: A tuple containing the standardized source and destination paths.
    """
    src = src.replace('\\', '/').rstrip('/')
    loc = loc.replace('\\', '/').rstrip('/')
    loc = '/'.join((loc, src.split('/')[-1]))
    return src, loc


class PasswordController(QWidget):
    """
    Manages the user password interface, storing user information in the host.db database.
    Provides functionality to display, add, and delete users.
    """

    def __init__(self) -> None:
        """
        Initializes the PasswordController widget with a user list and database connection.
        """
        super().__init__()
        self.userinfo = UserInfoData()  # User information database instance
        self.vbox = QVBoxLayout()  # Vertical layout for the widget
        self.user_list_widget = QListWidget()  # List widget to display user information
        self.vbox.addWidget(self.user_list_widget)
        self.setLayout(self.vbox)
        self.idxs = []  # Stores database indices of user records
        self.add_user_dict = {}  # Tracks added users to prevent duplicates
        self.user_list_widget.clicked.connect(self.item_clicked)

    def add_all_user(self) -> None:
        """
        Loads all user information from the database and displays it in the list widget.
        """
        for value in self.userinfo.query_all():
            if self.add_user_dict.get(value):
                continue
            self.add_user_dict[value] = True
            self.add_item(*value)

    def add_item(self, idx: int, host: str, port: int, username: str, _password: str) -> None:
        """
        Adds a user entry to the list widget.

        :param idx: Database index of the user record.
        :param host: Host address of the user.
        :param port: Port number for the connection.
        :param username: Username for the connection.
        :param _password: Password for the connection (not displayed).
        """
        self.idxs.append(idx)
        item = QListWidgetItem(f"IP地址: {host} 端口号:{port} 用户名:{username}")
        item.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DialogCancelButton))
        self.user_list_widget.addItem(item)

    def item_clicked(self, idx: QModelIndex) -> None:
        """
        Handles user clicking a list item, prompting to delete user information.

        :param idx: Index of the clicked list item.
        """
        query = QMessageBox.question(
            self, "询问", "是否删除用户信息",
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if query == QMessageBox.StandardButton.Ok:
            self.user_list_widget.takeItem(idx.row())
            self.userinfo.del_idx(self.idxs[idx.row()])


class Edit(QWidget):
    """
    File editing window for modifying remote file content.
    """

    def __init__(self, session: 'SFTPSession', src: str, text: str) -> None:
        """
        Initializes the Edit widget for editing a remote file.

        :param session: SFTP session object for file operations.
        :param src: Path to the remote file.
        :param text: Initial content of the file.
        """
        super().__init__()
        self.setGeometry(0, 0, 500, 500)  # Set window size
        self.src = src  # Remote file path
        self.session = session
        self.text = text
        self.vbox = QVBoxLayout()  # Vertical layout
        self.textEdit = QTextEdit()  # Text edit area for file content
        self.textEdit.setText(text)
        self.vbox.addWidget(self.textEdit)
        self.setLayout(self.vbox)
        self.show()

    def closeEvent(self, event: QCloseEvent) -> None:
        """
        Handles window close event, prompting to save changes if the file content has been modified.

        :param event: Close event object.
        """
        now_text = self.textEdit.toPlainText()
        if now_text == self.text:
            return
        reply = QMessageBox.question(self, "文件", "文件有改动，是否保存",
                                     QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
        if reply == QMessageBox.StandardButton.Ok:
            self.session.save_file(self.src, now_text)


class Transport(QThread):
    """
    Base class for file transfers, supporting upload and download with progress bar and error handling.
    TODO: Add support for resumable transfers.
    """

    def __init__(self, src: str, loc: str, co_num: int, session: 'SFTPSession', pbar: int) -> None:
        """
        Initializes the Transport thread for file transfers.

        :param src: Source path for the transfer.
        :param loc: Destination path for the transfer.
        :param co_num: Number of concurrent coroutines for the transfer.
        :param session: SFTP session object for file operations.
        :param pbar: Index of the progress bar in the UI.
        """
        super().__init__()
        self.src = src  # Source path
        self.loc = loc  # Destination path
        self.co_num = co_num  # Number of concurrent coroutines
        self.session = session  # SFTP session
        self.sftp = session.sftp  # SFTP client
        self.loop = session.loop  # Async event loop
        self.task_core = []  # Stores transfer tasks
        self.transport_fail_file = []  # Tracks failed file transfers
        self.now_progress_bar = 0  # Current progress bar value
        self.pbar = pbar  # Progress bar index
        self.msg = session.msg  # Signal for progress bar updates
        self.pbar_msg = session.pbar_msg  # Signal for progress bar initialization
        self.err_msg = session.err_msg  # Signal for error messages

    async def start_core(self):
        """
        Starts concurrent transfer tasks, prioritizing large files while handling small files concurrently.
        """
        self.task_core.sort(key=lambda item: item[0], reverse=True)
        self.task_core = [core for _, core in self.task_core]
        r = len(self.task_core) - 1
        async with asyncio_pool.AioPool(self.co_num, loop=self.loop) as pool:
            for l in range(0, r + 1):
                if r <= l + 1:
                    break
                self.task_core[l] = await pool.spawn(self.task_core[l])
                for idx in reversed(range(l + 1, r + 1)):
                    if self.task_core[l].done():
                        break
                    self.task_core[idx] = await pool.spawn(self.task_core[idx])
                    r = idx

    async def transport(self):
        """
        Abstract method for specific transfer logic, implemented by subclasses.
        """
        pass

    def run(self):
        """
        Runs the transfer task and handles error messages.
        """
        _ = asyncio.run_coroutine_threadsafe(self.transport(), self.loop).result()
        err_src_str = "".join(self.transport_fail_file)
        self.err_msg.emit(err_src_str)
        self.deleteLater()


class DownloadTransport(Transport):
    """File download class, inherits from Transport."""

    def __init__(self, src: str, loc: str, co_num: int, session: 'SFTPSession', pbar: int) -> None:
        """
        Initializes the DownloadTransport thread for downloading files.

        :param src: Remote source path for the download.
        :param loc: Local destination path for the download.
        :param co_num: Number of concurrent coroutines for the transfer.
        :param session: SFTP session object for file operations.
        :param pbar: Index of the progress bar in the UI.
        """
        super().__init__(src, loc, co_num, session, pbar)

    async def _transport_file(self, src: str, loc: str) -> None:
        """
        Downloads a single file and updates the progress bar.

        :param src: Remote file path to download.
        :param loc: Local destination path for the file.
        """
        last_size = 0

        def update(_src: bytes, _loc: bytes, now_size: int, _all_size: int) -> None:
            nonlocal last_size
            self.msg.emit(self.pbar, self.now_progress_bar + now_size - last_size)
            self.now_progress_bar += now_size - last_size
            last_size = now_size

        try:
            await self.sftp.get(src, loc, progress_handler=update)
        except (OSError, asyncssh.SFTPError):
            all_size = await self.sftp.getsize(src)
            self.msg.emit(self.pbar, self.now_progress_bar + all_size - last_size)
            self.now_progress_bar += all_size - last_size
            self.transport_fail_file.append(src + "\n")

    async def _transport_dir_init(self, src: str, loc: str) -> int:
        """
        Initializes directory download, recursively handling subdirectories and files.

        :param src: Remote directory path to download.
        :param loc: Local destination path for the directory.
        :return: Total size of files in the directory.
        """
        if not os.path.exists(loc):
            os.mkdir(loc)
        task_list = []
        total = 0
        async for entry in self.sftp.scandir(src):
            if entry.filename in ('.', '..'):
                continue
            next_src = "/".join((src, entry.filename))
            next_loc = "/".join((loc, entry.filename))
            if entry.attrs.type == 2:  # Directory
                task_list.append(asyncio.create_task(self._transport_dir_init(next_src, next_loc)))
            else:  # File
                total += entry.attrs.size
                self.task_core.append((entry.attrs.size, self._transport_file(next_src, next_loc)))
        for future in asyncio.as_completed(task_list):
            total += await future
        return total

    async def transport(self) -> None:
        """
        Executes the download task for files or directories.
        """
        src, loc = path_stand(self.src, self.loc)
        if await self.sftp.isdir(src):
            all_size = await self._transport_dir_init(src, loc)
            self.pbar_msg.emit(self.pbar, all_size)
            await self.start_core()
        else:
            all_size = await self.sftp.getsize(src)
            self.pbar_msg.emit(self.pbar, all_size)
            await self._transport_file(src, loc)
        self.msg.emit(self.pbar, all_size)


class UploadTransport(Transport):
    """File upload class, inherits from Transport."""

    def __init__(self, src: str, loc: str, co_num: int, session: 'SFTPSession', pbar: int) -> None:
        """
        Initializes the UploadTransport thread for uploading files.

        :param src: Local source path for the upload.
        :param loc: Remote destination path for the upload.
        :param co_num: Number of concurrent coroutines for the transfer.
        :param session: SFTP session object for file operations.
        :param pbar: Index of the progress bar in the UI.
        """
        super().__init__(src, loc, co_num, session, pbar)
        self.task_list_mkdir = []

    async def _transport_file(self, src: str, loc: str) -> None:
        """
        Uploads a single file and updates the progress bar.

        :param src: Local file path to upload.
        :param loc: Remote destination path for the file.
        """
        last_size = 0

        def update(_src: bytes, _loc: bytes, now_size: int, _all_size: int) -> None:
            nonlocal last_size
            self.msg.emit(self.pbar, self.now_progress_bar + now_size - last_size)
            self.now_progress_bar += now_size - last_size
            last_size = now_size

        try:
            await self.sftp.put(src, loc, progress_handler=update)
        except (OSError, asyncssh.SFTPError):
            all_size = os.path.getsize(src)
            self.msg.emit(self.pbar, self.now_progress_bar + all_size - last_size)
            self.now_progress_bar += all_size - last_size
            self.transport_fail_file.append(src + "\n")

    def _transport_dir_init(self, src: str, loc: str) -> int:
        """
        Initializes directory upload, recursively handling subdirectories and files.

        :param src: Local directory path to upload.
        :param loc: Remote destination path for the directory.
        :return: Total size of files in the directory.
        """
        total_size = 0
        self.task_list_mkdir.append(self.sftp.makedirs(loc, exist_ok=True))
        for entry in os.scandir(src):
            next_src = "/".join((src, entry.name))
            next_loc = "/".join((loc, entry.name))
            if entry.is_dir():
                total_size += self._transport_dir_init(next_src, next_loc)
            else:
                self.task_core.append((entry.stat().st_size, self._transport_file(next_src, next_loc)))
                total_size += entry.stat().st_size
        return total_size

    async def transport(self) -> None:
        """
        Executes the upload task for files or directories.
        """
        src, loc = path_stand(self.src, self.loc)
        if os.path.isdir(src):
            all_size = self._transport_dir_init(src, loc)
            self.pbar_msg.emit(self.pbar, all_size)
            for future in asyncio.as_completed(self.task_list_mkdir):
                await future
            await self.start_core()
        else:
            all_size = os.path.getsize(src)
            self.pbar_msg.emit(self.pbar, all_size)
            await self._transport_file(src, loc)
        self.msg.emit(self.pbar, all_size)


class SFTPSession(QThread):
    """
    Manages SFTP sessions for connecting to a remote server and performing file operations.
    """
    msg = Signal(int, int)  # Signal for progress bar updates
    pbar_msg = Signal(int, int)  # Signal for progress bar initialization
    err_msg = Signal(str)  # Signal for error messages

    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        """
        Initializes the SFTP session with connection details.

        :param host: Remote server host address.
        :param port: Port number for the SFTP connection.
        :param username: Username for authentication.
        :param password: Password for authentication.
        """
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.transport = []  # Stores transfer tasks
        self.loop = asyncio.new_event_loop()  # Creates async event loop
        self.ssh = self.loop.run_until_complete(
            asyncssh.connect(host=host, port=port, username=username, password=password, known_hosts=None))
        self.sftp = self.loop.run_until_complete(self.ssh.start_sftp_client())

    def run(self) -> None:
        """
        Runs the async event loop for the SFTP session.
        """
        self.loop.run_forever()
        self.deleteLater()

    def getcwd(self) -> str:
        """
        Retrieves the current working directory on the remote server.

        :return: Current working directory path.
        """
        return asyncio.run_coroutine_threadsafe(self.sftp.getcwd(), self.loop).result()

    def read_dir(self, src: str) -> Sequence[asyncssh.SFTPName]:
        """
        Reads the contents of a specified directory on the remote server.

        :param src: Path to the directory to read.
        :return: Sequence of SFTPName objects representing directory contents.
        """
        return asyncio.run_coroutine_threadsafe(self.sftp.readdir(src), self.loop).result()

    def change_dir(self, src: str) -> None:
        """
        Changes the current working directory on the remote server.

        :param src: Path to the new directory.
        """
        asyncio.run_coroutine_threadsafe(self.sftp.chdir(src), self.loop).result()

    def is_file(self, src: str) -> bool:
        """
        Checks if the specified path is a file on the remote server.

        :param src: Path to check.
        :return: True if the path is a file, False otherwise.
        """
        return asyncio.run_coroutine_threadsafe(self.sftp.isfile(src), self.loop).result()

    async def _read_file(self, src: str) -> str:
        """
        Asynchronously reads the content of a remote file.

        :param src: Path to the remote file.
        :return: File content as a string.
        """
        text = ""
        async with self.sftp.open(src, 'rb') as f:
            text += (await f.read()).decode()
        return text

    def read_file(self, src: str) -> str:
        """
        Synchronously reads the content of a remote file.

        :param src: Path to the remote file.
        :return: File content as a string.
        """
        return asyncio.run_coroutine_threadsafe(self._read_file(src), self.loop).result()

    async def _save_file(self, src: str, text: str) -> None:
        """
        Asynchronously saves content to a remote file.

        :param src: Path to the remote file.
        :param text: Content to write to the file.
        """
        async with self.sftp.open(src, 'wb') as f:
            await f.write(text.encode())

    def save_file(self, src: str, text: str) -> None:
        """
        Synchronously saves content to a remote file.

        :param src: Path to the remote file.
        :param text: Content to write to the file.
        """
        asyncio.run_coroutine_threadsafe(self._save_file(src, text), self.loop).result()

    def del_file(self, src: str) -> None:
        """
        Deletes a file on the remote server.

        :param src: Path to the file to delete.
        """
        asyncio.run_coroutine_threadsafe(self.sftp.remove(src), self.loop).result()

    def del_dir(self, src: str) -> None:
        """
        Deletes a directory on the remote server.

        :param src: Path to the directory to delete.
        """
        asyncio.run_coroutine_threadsafe(self.remove_dir(src), self.loop).result()

    def make_dir(self, src: str) -> None:
        """
        Creates a directory on the remote server.

        :param src: Path to the directory to create.
        """
        asyncio.run_coroutine_threadsafe(self.sftp.makedirs(src, exist_ok=True), self.loop).result()

    def rename(self, src: str, new: str) -> None:
        """
        Renames a file or directory on the remote server.

        :param src: Current path of the file or directory.
        :param new: New path for the file or directory.
        """
        asyncio.run_coroutine_threadsafe(self.sftp.rename(src, new), self.loop).result()

    def download(self, src: str, loc: str, co_num: int, pbar: int) -> None:
        """
        Starts a download task for a file or directory.

        :param src: Remote source path to download.
        :param loc: Local destination path.
        :param co_num: Number of concurrent coroutines.
        :param pbar: Progress bar index in the UI.
        """
        dt = DownloadTransport(src, loc, co_num, self, pbar)
        dt.start()
        self.transport.append(dt)

    def upload(self, src: str, loc: str, co_num: int, pbar: int) -> None:
        """
        Starts an upload task for a file or directory.

        :param src: Local source path to upload.
        :param loc: Remote destination path.
        :param co_num: Number of concurrent coroutines.
        :param pbar: Progress bar index in the UI.
        """
        ut = UploadTransport(src, loc, co_num, self, pbar)
        ut.start()
        self.transport.append(ut)

    async def remove_dir(self, src: str) -> None:
        """
        Asynchronously deletes a directory on the remote server.

        :param src: Path to the directory to delete.
        """
        await self.ssh.run(f"rm -rf {src}")

    async def _run_command(self, com: str) -> asyncssh.SSHCompletedProcess:
        """
        Asynchronously executes an SSH command on the remote server.

        :param com: Command to execute.
        :return: SSH command execution result.
        """
        return await self.ssh.run(com)

    def run_command(self, com: str) -> asyncssh.SSHCompletedProcess:
        """
        Synchronously executes an SSH command on the remote server.

        :param com: Command to execute.
        :return: SSH command execution result.
        """
        return asyncio.run_coroutine_threadsafe(self._run_command(com), self.loop).result()

    def realpath(self, src: str) -> str:
        """
        Retrieves the real path of a file or directory on the remote server.

        :param src: Path to resolve.
        :return: Real path as a string.
        """
        return asyncio.run_coroutine_threadsafe(self.sftp.realpath(src.encode()), self.loop).result().decode()

    def move_file(self, old_path: str, new_path: str) -> None:
        """
        Moves a file or directory on the remote server.

        :param old_path: Current path of the file or directory.
        :param new_path: New path for the file or directory.
        """
        self.run_command(f"mv {old_path} {new_path}")

    def copy_file(self, src: str, dst: str) -> None:
        """
        Copies a file or directory on the remote server.

        :param src: Source path to copy.
        :param dst: Destination path for the copy.
        """
        self.run_command(f"cp -r {src} {dst}")


class CheckNewFile(QThread):
    def __init__(self, remote_file_display: 'RemoteFileDisplay'):
        super().__init__()
        self.remote_file_display = remote_file_display
        self.new_file_msg = self.remote_file_display.new_file_msg
        self.sub_file_msg = self.remote_file_display.sub_file_msg
        self.session = self.remote_file_display.session
        self.mutex = self.remote_file_display.mutex

    def check_new_file(self):
        if self.mutex.tryLock():
            now_file_list = self.session.read_dir(".")
            all_file_dict = self.remote_file_display.all_files_dict
            new_files = []
            for entry in now_file_list:
                if entry.filename in (".", ".."):
                    continue
                if entry.filename not in all_file_dict:
                    new_files.append(entry)
            self.new_file_msg.emit(new_files)
            self.mutex.unlock()

    def check_sub_file(self):
        if self.mutex.tryLock():
            now_file_list = set([entry.filename for entry in self.session.read_dir(".")])
            all_file_dict = self.remote_file_display.all_files_dict
            sub_files = []
            for file in all_file_dict:
                if file not in now_file_list:
                    sub_files.append(file)
            if sub_files:
                self.sub_file_msg.emit(sub_files)
            self.mutex.unlock()

    def run(self):
        while True:
            self.check_new_file()
            time.sleep(0.3)
            self.check_sub_file()
            time.sleep(0.3)


class RemoteFileDisplay(QWidget):
    """
    Remote file display interface, supporting file browsing, editing, deletion, moving, and copying.
    TODO: Add support for dragging files out.
    """
    new_file_msg = Signal(list)
    sub_file_msg = Signal(list)

    def __init__(self, sftp_main_window: 'SFTPMainWindow') -> None:
        """
        Initializes the RemoteFileDisplay widget for browsing remote files.

        :param sftp_main_window: Parent SFTPMainWindow instance.
        """
        super().__init__()
        self.sftp_main_window = sftp_main_window
        self.session = sftp_main_window.session
        self.main_window_path = self.session.getcwd()
        self.mutex = QMutex()
        self.move_paths = []  # Paths to move
        self.copy_paths = []  # Paths to copy
        self.edits = []
        self.all_files_dict: dict[str, QListWidgetItem] = dict()
        self.back_button = QPushButton("返回上层目录")
        self.select_button = QPushButton("选择")
        self.path_edit = QLineEdit()
        self.search_edit = QLineEdit()
        self.search_label = QLabel("搜索文件:")
        self.vbox = QVBoxLayout()
        self.tool_hbox = QHBoxLayout()
        self.display_file_list = QListWidget()
        self.checker = CheckNewFile(self)
        self.select_item = None
        self.setLayout(self.vbox)
        self.init_ui()

    @Slot(list)
    def display_new_file(self, new_files: list[asyncssh.SFTPName]):
        self.mutex.lock()
        for entry in new_files:
            filename = entry.filename
            if filename in (".", ".."):
                return
            item = QListWidgetItem(filename)
            icon = QStyle.StandardPixmap.SP_DirIcon if entry.attrs.type == 2 else QStyle.StandardPixmap.SP_FileIcon
            item.setIcon(QApplication.style().standardIcon(icon))
            if entry.attrs.type == 2:
                self.display_file_list.insertItem(0, item)
            else:
                self.display_file_list.addItem(item)
            self.all_files_dict[filename] = item
        self.mutex.unlock()

    @Slot(list)
    def del_sub_file(self, sub_files: list[str]):
        self.mutex.lock()
        for file in sub_files:
            if file not in self.all_files_dict:
                return
            item = self.all_files_dict[file]
            row = self.display_file_list.row(item)
            self.display_file_list.takeItem(row)
            self.all_files_dict.pop(file)
        self.mutex.unlock()

    def init_ui(self) -> None:
        """
        Initializes the UI layout and event bindings for the file display.
        """
        self.display_file_list.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        self.setAcceptDrops(True)  # Enable drag-and-drop support
        self.search_edit.textChanged.connect(self.search_edit_value)
        self.back_button.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ArrowBack))
        self.back_button.setStyleSheet("text-align: left;")
        hbox_search = QHBoxLayout()
        hbox_search.addWidget(self.search_label)
        hbox_search.addWidget(self.search_edit)
        self.tool_hbox.addWidget(self.back_button)
        self.tool_hbox.addWidget(self.path_edit)
        self.tool_hbox.addLayout(hbox_search)
        self.path_edit.setReadOnly(True)
        self.path_edit.setText(self.session.getcwd())
        self.vbox.addLayout(self.tool_hbox)
        self.vbox.addWidget(self.display_file_list)
        self.back_button.clicked.connect(lambda: self.double_item_clicked(QListWidgetItem("..")))
        self.display_file_list.itemDoubleClicked.connect(self.double_item_clicked)
        self.display_file_list.itemClicked.connect(self.item_clicked)
        self.display_file_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.display_file_list.customContextMenuRequested.connect(self.show_context_menu)
        self.new_file_msg.connect(self.display_new_file)
        self.sub_file_msg.connect(self.del_sub_file)
        self.checker.start()

    def search_edit_value(self, text: str) -> None:
        """
        Filters displayed files and directories based on search input.

        :param text: Search text to filter items.
        """

        if not text:
            for item in self.all_files_dict.values():
                item.setHidden(False)
            return
        for item in self.all_files_dict.values():
            item.setHidden(text not in item.text())

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        """
        Handles drag enter events for file uploads.

        :param event: Drag enter event object.
        """
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        """
        Handles drop events to upload dragged files.

        :param event: Drop event object containing file URLs.
        """
        for url in event.mimeData().urls():
            self.sftp_main_window.upload(url.toLocalFile(), self.session.getcwd(), 10)
        event.acceptProposedAction()

    def closeEvent(self, event: QCloseEvent) -> None:
        """
        Restores the initial directory when the widget is closed.

        :param event: Close event object.
        """
        self.session.change_dir(self.main_window_path)

    def show_context_menu(self, pos: QPoint) -> None:
        """
        Displays a context menu for file operations.

        :param pos: Position where the context menu is requested.
        """
        item = self.display_file_list.itemAt(pos)
        context_menu = QMenu(self)
        reload_action = context_menu.addAction("刷新")
        makedir_action = context_menu.addAction("新建文件夹")
        new_file_action = context_menu.addAction("新文件")
        reload_action.triggered.connect(self.reload_dir)
        makedir_action.triggered.connect(self.makedir)
        new_file_action.triggered.connect(self.new_file)
        if item:
            edit_action = context_menu.addAction("打开")
            del_action = context_menu.addAction("删除")
            move_action = context_menu.addAction("移动")
            copy_action = context_menu.addAction("复制")
            download_action = context_menu.addAction("下载")
            edit_action.triggered.connect(lambda: self.double_item_clicked(item))
            del_action.triggered.connect(self.del_items)
            move_action.triggered.connect(self.move_items)
            copy_action.triggered.connect(self.copy_items)
            download_action.triggered.connect(self.download_items)
        if self.move_paths:
            context_menu.addAction("放置").triggered.connect(self.put_items)
        if self.copy_paths:
            context_menu.addAction("粘贴").triggered.connect(self.paste_items)
        if len(self.display_file_list.selectedItems()) == 1:
            rename_action = context_menu.addAction("重命名")
            rename_action.triggered.connect(lambda: self.rename(item))
        context_menu.exec(self.display_file_list.mapToGlobal(pos))

    def download_items(self) -> None:
        """
        Downloads selected files or directories.
        """
        for item in self.display_file_list.selectedItems():
            self.download_item(item)

    def download_item(self, item: QListWidgetItem) -> None:
        """
        Downloads a single file or directory.

        :param item: List widget item representing the file or directory.
        """
        self.sftp_main_window.download(self.realpath(item.text()), "./tmp", 10)

    def paste_items(self) -> None:
        """
        Pastes copied files or directories to the current directory.
        """
        for old_path in self.copy_paths:
            self.session.copy_file(old_path, self.session.getcwd())
        self.copy_paths.clear()
        self.reload_dir()

    def put_items(self) -> None:
        """
        Places moved files or directories to the current directory.
        """
        for old_path in self.move_paths:
            self.session.move_file(old_path, self.session.getcwd())
        self.move_paths.clear()
        self.reload_dir()

    def reload_dir(self) -> None:
        """
        Refreshes the current directory display.
        """
        self.display_file_list.clear()

    def item_clicked(self, item: QListWidgetItem) -> None:
        """
        Records the clicked list item.

        :param item: Clicked list widget item.
        """
        self.select_item = item

    def double_item_clicked(self, item: QListWidgetItem) -> None:
        """
        Handles double-click events to open files or change directories.

        :param item: Double-clicked list widget item.
        """
        if not self.session.is_file(item.text()):
            self.mutex.lock()
            self.session.change_dir(item.text())
            self.display_file_list.clear()
            self.all_files_dict.clear()
            self.path_edit.setText(self.session.getcwd())
            self.mutex.unlock()
            return
        src = item.text()
        edit = Edit(self.session, src, self.session.read_file(src))
        self.edits.append(edit)

    def del_items(self) -> None:
        """
        Deletes selected files or directories after confirmation.
        """
        text = ""
        for item in self.display_file_list.selectedItems():
            text += item.text() + "\n"
        reply = QMessageBox.question(self, "删除", f"确认删除:\n{text}\n",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            for item in self.display_file_list.selectedItems():
                self.del_item(item)
            self.reload_dir()

    def del_item(self, item: QListWidgetItem) -> None:
        """
        Deletes a single file or directory.

        :param item: List widget item representing the file or directory.
        """
        src = self.realpath(item.text())
        if not self.session.is_file(src):
            self.session.del_dir(src)
        else:
            self.session.del_file(src)

    def makedir(self) -> None:
        """
        Creates a new directory with a user-specified name.
        """
        text, ok = QInputDialog.getText(self, "新建", "输入文件夹名")
        if ok:
            self.session.make_dir(str(text))
            self.reload_dir()

    def new_file(self) -> None:
        """
        Creates a new empty file with a user-specified name.
        """
        text, ok = QInputDialog.getText(self, "新建", "输入文件名")
        if ok:
            self.session.save_file(str(text), "")
            self.reload_dir()

    def rename(self, item: QListWidgetItem) -> None:
        """
        Renames a file or directory.

        :param item: List widget item representing the file or directory.
        """
        text, ok = QInputDialog.getText(self, "重命名", "输入新的文件名")
        if ok:
            self.session.rename(item.text(), str(text))
            self.reload_dir()

    def move_items(self) -> None:
        """
        Adds selected files or directories to the move list.
        """
        for item in self.display_file_list.selectedItems():
            self.move_item(item)

    def move_item(self, item: QListWidgetItem) -> None:
        """
        Adds a single file or directory to the move list.

        :param item: List widget item to move.
        """
        item.setHidden(True)
        self.move_paths.append(self.realpath(item.text()))

    def copy_items(self) -> None:
        """
        Adds selected files or directories to the copy list.
        """
        for item in self.display_file_list.selectedItems():
            self.copy_item(item)

    def copy_item(self, item: QListWidgetItem) -> None:
        """
        Adds a single file or directory to the copy list.

        :param item: List widget item to copy.
        """
        self.copy_paths.append(self.realpath(item.text()))

    def realpath(self, path: str) -> str:
        """
        Retrieves the real path of a file or directory.

        :param path: Path to resolve.
        :return: Real path as a string.
        """
        return self.session.realpath(path)


class GetTransportPathWidget(QWidget):
    """Base class for selecting transfer paths for upload and download."""

    def __init__(self, sftp_main_window: 'SFTPMainWindow') -> None:
        """
        Initializes the GetTransportPathWidget for path selection.

        :param sftp_main_window: Parent SFTPMainWindow instance.
        """
        super().__init__()
        self.sftp_main_window = sftp_main_window
        self.ok_button = QPushButton("开始")
        self.src_edit = QLineEdit()
        self.src_button = QPushButton("源文件")
        self.src_button_dir = QPushButton("源文件夹")
        self.dst_edit = QLineEdit()
        self.dst_button = QPushButton("目标地址")
        self.co_num_edit = QLineEdit()
        self.grid = QGridLayout()
        self.setLayout(self.grid)
        self.remote_file = RemoteFileDisplay(self.sftp_main_window)
        self.remote_file.display_file_list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.init_ui()

    def init_ui(self) -> None:
        """
        Initializes the UI layout for path selection.
        """
        self.src_edit.setReadOnly(True)
        self.dst_edit.setReadOnly(True)
        self.grid.addWidget(self.src_edit, 0, 0)
        self.grid.addWidget(self.src_button, 0, 1)
        self.grid.addWidget(self.src_button_dir, 0, 2)
        self.grid.addWidget(self.dst_edit, 1, 0)
        self.grid.addWidget(self.dst_button, 1, 1)
        self.grid.addWidget(self.co_num_edit, 2, 0)
        self.grid.addWidget(QLabel("协程数量"), 2, 1)
        self.grid.addWidget(self.ok_button, 3, 0)


class GetDownloadPathWidget(GetTransportPathWidget):
    """Widget for selecting download paths."""

    def __init__(self, sftp_main_window: 'SFTPMainWindow') -> None:
        """
        Initializes the GetDownloadPathWidget for download path selection.

        :param sftp_main_window: Parent SFTPMainWindow instance.
        """
        super().__init__(sftp_main_window)
        self.main_window = sftp_main_window
        self.src_button_dir.setVisible(False)
        self.remote_file.vbox.addWidget(self.remote_file.select_button)
        self.remote_file.select_button.clicked.connect(self.selected_file)
        self.src_button.clicked.connect(self.get_src_file)
        self.dst_button.clicked.connect(self.get_local_file)
        self.ok_button.clicked.connect(self.start_download)

    def selected_file(self) -> None:
        """
        Sets the selected remote file path in the source edit field.
        """
        self.src_edit.setText(self.remote_file.realpath(self.remote_file.select_item.text()))
        self.remote_file.close()

    def start_download(self) -> None:
        """
        Starts the download task if all parameters are provided.
        """
        if self.src_edit.text() and self.dst_edit.text() and self.co_num_edit.text():
            self.main_window.download(self.src_edit.text(), self.dst_edit.text(), int(self.co_num_edit.text()))
            self.close()
        else:
            QMessageBox.warning(self, "参数警告", "请参数不能为空", QMessageBox.StandardButton.Ok)

    def get_src_file(self) -> None:
        """
        Displays the remote file selection window.
        """
        self.remote_file.show()

    def get_local_file(self) -> None:
        """
        Opens a dialog to select a local destination directory.
        """
        file_path = QFileDialog.getExistingDirectory(self, "Open file")
        self.dst_edit.setText(file_path)


class GetUploadPathWidget(GetTransportPathWidget):
    """Widget for selecting upload paths."""

    def __init__(self, sftp_main_window: 'SFTPMainWindow') -> None:
        """
        Initializes the GetUploadPathWidget for upload path selection.

        :param sftp_main_window: Parent SFTPMainWindow instance.
        """
        super().__init__(sftp_main_window)
        self.main_window = sftp_main_window
        self.remote_file.vbox.addWidget(self.remote_file.select_button)
        self.remote_file.select_button.clicked.connect(self.selected_file)
        self.src_button.clicked.connect(self.get_src_file)
        self.dst_button.clicked.connect(self.get_local_file)
        self.ok_button.clicked.connect(self.start_upload)
        self.src_button_dir.clicked.connect(self.get_src_dir)

    def start_upload(self) -> None:
        """
        Starts the upload task if all parameters are provided.
        """
        if self.src_edit.text() and self.dst_edit.text() and self.co_num_edit.text():
            self.main_window.upload(self.src_edit.text(), self.dst_edit.text(), int(self.co_num_edit.text()))
            self.close()
        else:
            QMessageBox.warning(self, "参数警告", "请把所有参数填写完整", QMessageBox.StandardButton.Ok)

    def selected_file(self) -> None:
        """
        Sets the selected remote destination path in the destination edit field.
        """
        self.dst_edit.setText(self.remote_file.realpath(self.remote_file.select_item.text()))
        self.remote_file.close()

    def get_local_file(self) -> None:
        """
        Displays the remote file selection window for destination path.
        """
        self.remote_file.show()

    def get_src_dir(self):
        """
        Opens a dialog to select a local source directory.
        """
        dir_path = QFileDialog.getExistingDirectory(self, "Open dir")
        self.src_edit.setText(dir_path)

    def get_src_file(self):
        """
        Opens a dialog to select a local source file.
        """
        file_path = QFileDialog.getOpenFileName(self, "Open file")
        if file_path[0]:
            self.src_edit.setText(file_path[0])


class RemoteFileMainWindow(RemoteFileDisplay):
    def __init__(self, sftp_main_window: 'SFTPMainWindow') -> None:
        """
        Initializes the RemoteFileMainWindow with additional upload/download buttons.

        :param sftp_main_window: Parent SFTPMainWindow instance.
        """
        super().__init__(sftp_main_window)
        self.get_upload_widget = None
        self.get_download_widget = None
        self.download_button = QPushButton("下载")
        self.upload_button = QPushButton("上传")
        self.tool_hbox.addWidget(self.download_button)
        self.tool_hbox.addWidget(self.upload_button)
        self.download_button.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ArrowDown))
        self.upload_button.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ArrowUp))
        self.download_button.clicked.connect(self.get_download_path)
        self.upload_button.clicked.connect(self.get_upload_path)

    def get_upload_path(self):
        """
        Opens the upload path selection widget.
        """
        self.get_upload_widget = GetUploadPathWidget(self.sftp_main_window)
        self.get_upload_widget.show()

    def get_download_path(self):
        """
        Opens the download path selection widget.
        """
        self.get_download_widget = GetDownloadPathWidget(self.sftp_main_window)
        self.get_download_widget.show()


class ControlListWidget(QWidget):
    """Control panel for switching between SFTP file list, password management, and transfer management."""

    def __init__(self, sftp_main_window: 'SFTPMainWindow') -> None:
        """
        Initializes the ControlListWidget for navigation.

        :param sftp_main_window: Parent SFTPMainWindow instance.
        """
        super().__init__()
        self.sftp_main_window = sftp_main_window
        self.layout = QVBoxLayout()
        self.control_list = QListWidget()
        self.items = ["SFTP文件", "密码管理", "传输管理"]
        self.control_list.addItems(self.items)
        self.control_list.clicked.connect(self.clicked_item)
        self.layout.addWidget(self.control_list)
        self.setLayout(self.layout)
        self.function = {
            "SFTP文件": self.sftp_file_list,
            "密码管理": self.password_changed,
            "传输管理": self.transport
        }

    def clicked_item(self, index: QModelIndex) -> None:
        """
        Handles clicks on control panel options to switch interfaces.

        :param index: Index of the clicked list item.
        """
        text = self.control_list.item(index.row()).text()
        self.function[text]()

    def password_changed(self) -> None:
        """
        Switches to the password management interface.
        """
        self.sftp_main_window.password_control.add_all_user()
        self.sftp_main_window.stacked_widget.setCurrentIndex(2)

    def sftp_file_list(self) -> None:
        """
        Switches to the SFTP file list interface.
        """
        self.sftp_main_window.stacked_widget.setCurrentIndex(0)

    def transport(self) -> None:
        """
        Switches to the transfer management interface.
        """
        self.sftp_main_window.stacked_widget.setCurrentIndex(1)


class SFTPMainWindow(QWidget):
    """Main SFTP window, integrating file display, upload/download, password management, and progress bars."""

    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        """
        Initializes the SFTPMainWindow with connection details.

        :param host: Remote server host address.
        :param port: Port number for the SFTP connection.
        :param username: Username for authentication.
        :param password: Password for authentication.
        """
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.session = SFTPSession(host, port, username, password)
        self.session.msg.connect(self.update_progress)
        self.session.pbar_msg.connect(self.set_progress)
        self.session.err_msg.connect(self.display_error)
        self.session.start()
        self.stacked_widget = QStackedWidget()
        self.display_pbar_list = QListWidget()
        self.remote_file_widget = RemoteFileMainWindow(self)
        self.download_widget = GetDownloadPathWidget(self)
        self.upload_widget = GetUploadPathWidget(self)
        self.password_control = PasswordController()
        self.control_windows = ControlListWidget(self)
        self.hbox = QHBoxLayout()
        self.setLayout(self.hbox)
        self.splitter_control_transport = QSplitter(Qt.Orientation.Horizontal)
        self.pbars = []
        self.init_ui()

    def init_ui(self) -> None:
        """
        Initializes the main window layout.
        """
        self.setWindowTitle("SFTP Session")
        self.splitter_control_transport.addWidget(self.control_windows)
        self.splitter_control_transport.addWidget(self.stacked_widget)
        self.splitter_control_transport.setStretchFactor(0, 0)
        self.splitter_control_transport.setStretchFactor(1, 3)
        self.hbox.addWidget(self.splitter_control_transport)
        self.stacked_widget.addWidget(self.remote_file_widget)  # 0: File list
        self.stacked_widget.addWidget(self.display_pbar_list)  # 1: Transfer management
        self.stacked_widget.addWidget(self.password_control)  # 2: Password management

    def add_pbar(self, src: str, transport_type: str) -> int:
        """
        Adds a progress bar to the transfer management interface.

        :param src: Source path for the transfer.
        :param transport_type: Type of transfer ("上传" or "下载").
        :return: Index of the added progress bar.
        """
        icon = QStyle.StandardPixmap.SP_FileIcon if self.session.is_file(src) else QStyle.StandardPixmap.SP_DirIcon
        pbar = QProgressBar()
        item = QListWidgetItem(self.display_pbar_list)
        item_widget = QWidget()
        layout = QHBoxLayout(item_widget)
        text_label = QLabel(f"{transport_type}: {src}")
        picture_label = QLabel()
        picture_label.setPixmap(QApplication.style().standardIcon(icon).pixmap(16, 16))
        layout.addWidget(picture_label)
        layout.addWidget(text_label)
        layout.addWidget(pbar)
        layout.setContentsMargins(0, 0, 0, 0)
        self.display_pbar_list.setItemWidget(item, item_widget)
        self.display_pbar_list.addItem(item)
        self.pbars.append(pbar)
        return len(self.pbars) - 1

    def download(self, src: str, loc: str, co_num: int) -> None:
        """
        Starts a download task and adds a progress bar.

        :param src: Remote source path to download.
        :param loc: Local destination path.
        :param co_num: Number of concurrent coroutines.
        """
        pbar = self.add_pbar(src, "下载")
        self.session.download(src, loc, co_num, pbar)

    def upload(self, src: str, loc: str, co_num: int) -> None:
        """
        Starts an upload task and adds a progress bar.

        :param src: Local source path to upload.
        :param loc: Remote destination path.
        :param co_num: Number of concurrent coroutines.
        """
        pbar = self.add_pbar(src, "上传")
        self.session.upload(src, loc, co_num, pbar)

    @Slot(int, int)
    def update_progress(self, pbar: int, value: int) -> None:
        """
        Updates the progress bar value.

        :param pbar: Index of the progress bar to update.
        :param value: New progress value.
        """
        self.pbars[pbar].setValue(value)

    @Slot(int, int)
    def set_progress(self, pbar: int, value: int) -> None:
        """
        Sets the progress bar range.

        :param pbar: Index of the progress bar to set.
        :param value: Maximum value for the progress bar.
        """
        self.pbars[pbar].setRange(0, value)

    @Slot(str)
    def display_error(self, value: str) -> None:
        """
        Displays transfer error messages.

        :param value: Error message to display.
        """
        if value:
            QMessageBox.warning(self, "传输警告", f"{value}\n传输失败，注意检查权限和SFTP配置文件",
                                QMessageBox.StandardButton.Ok)


class LoginWindow(QWidget):
    """Login window for entering SFTP connection details."""

    def __init__(self, tab: QTabWidget, sftp_widget_list: list) -> None:
        """
        Initializes the LoginWindow for SFTP connection input.

        :param tab: Tab widget to add SFTP sessions to.
        :param sftp_widget_list: List to store SFTP session widgets.
        """
        super().__init__()
        self.sftp_widget_list = sftp_widget_list
        self.tab = tab
        self.setWindowTitle("Login")
        self.form = QFormLayout()
        self.combox = QComboBox()
        self.host_edit = QLineEdit()
        self.port_edit = QLineEdit()
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.login_button = QPushButton("登录")
        self.cancel_button = QPushButton("取消")
        self.checkbox = QCheckBox()
        self.userinfo = UserInfoData()
        self.sftp_main_window = SFTPMainWindow
        self.setLayout(self.form)
        self.idxs = []
        self.password_display = False
        self.init_ui()

    def init_ui(self) -> None:
        """
        Initializes the login window layout and event bindings.
        """
        self.combox.currentIndexChanged.connect(self.selected_item)
        self.checkbox.clicked.connect(self.set_password_mode)
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        users = [f"{query_value[1]}:{query_value[3]}" for query_value in self.userinfo.query_all()]
        self.idxs = [query_value[0] for query_value in self.userinfo.query_all()]
        self.combox.addItems(users)
        self.form.addRow(QLabel("存储IP"), self.combox)
        self.form.addRow(QLabel("服务器IP:"), self.host_edit)
        self.form.addRow(QLabel("端口号:"), self.port_edit)
        self.form.addRow(QLabel("用户名:"), self.username_edit)
        self.form.addRow(QLabel("密码:"), self.password_edit)
        self.form.addRow(QLabel("显示密码"), self.checkbox)
        self.form.addRow(self.login_button, self.cancel_button)
        self.login_button.clicked.connect(self.login)
        self.cancel_button.clicked.connect(self.close)

    def selected_item(self, idx: int) -> None:
        """
        Fills the input fields with selected user information.

        :param idx: Index of the selected user in the combo box.
        """
        value = self.userinfo.query_idx(self.idxs[idx])
        self.host_edit.setText(value[1])
        self.port_edit.setText(str(value[2]))
        self.username_edit.setText(value[3])
        self.password_edit.setText(value[4])

    def login(self) -> None:
        """
        Handles login logic and creates a new SFTP session.
        """
        host = self.host_edit.text()
        port = self.port_edit.text()
        username = self.username_edit.text()
        password = self.password_edit.text()
        try:
            if host and port and username and password:
                self.sftp_main_window = self.sftp_main_window(host, int(port), username, password)
                self.userinfo.insert(host, int(port), username, password)
                self.close()
                self.tab.addTab(self.sftp_main_window, host)
                self.sftp_widget_list.append(self.sftp_main_window)
            else:
                QMessageBox.warning(self, "参数警告", "请参数不能为空", QMessageBox.StandardButton.Ok)
        except:
            QMessageBox.warning(self, "密码", "请检查网络和用户名密码", QMessageBox.StandardButton.Ok)

    def set_password_mode(self) -> None:
        """
        Toggles password visibility in the password input field.
        """
        self.password_display = not self.password_display
        self.password_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if self.password_display else QLineEdit.EchoMode.Password)


class UserMainWindow(QMainWindow):
    """Main window for managing multiple SFTP sessions."""

    def __init__(self) -> None:
        """
        Initializes the UserMainWindow for managing SFTP sessions.
        """
        super().__init__()
        self.tab = QTabWidget()
        self.setCentralWidget(self.tab)
        self.login_windows = []
        self.sftp_widget = []
        self.init_ui()
        self.show()
        self.login()

    def init_ui(self) -> None:
        """
        Initializes the main window layout with a toolbar and tab widget.
        """
        self.tab.setTabsClosable(True)
        self.tab.tabCloseRequested.connect(self.close_tab)
        tool_bar = QToolBar()
        self.addToolBar(tool_bar)
        new_action = QAction("新建会话", self)
        new_action.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogNewFolder))
        new_action.triggered.connect(self.login)
        tool_bar.addAction(new_action)

    def login(self) -> None:
        """
        Opens a new login window for creating an SFTP session.
        """
        login_window = LoginWindow(self.tab, self.sftp_widget)
        login_window.show()
        self.login_windows.append(login_window)

    def close_tab(self, index: int) -> None:
        """
        Closes a specified tab and its associated SFTP session.

        :param index: Index of the tab to close.
        """
        self.tab.removeTab(index)
        self.sftp_widget[index].close()


if __name__ == '__main__':
    os.makedirs("tmp", exist_ok=True)
    app = QApplication(sys.argv)
    setup_theme("auto")
    us = UserMainWindow()
    sys.exit(app.exec())
