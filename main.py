import os
import sys
import asyncio
from typing import Sequence
import asyncssh
import asyncio_pool
from PySide6.QtGui import QAction, QDropEvent, QDragEnterEvent, QCloseEvent
from PySide6.QtCore import QThread, Signal, Slot, Qt, QPoint, QModelIndex
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
    QProgressBar, QLineEdit, QLabel, QPushButton, QStyle, QListWidget,
    QListWidgetItem, QTextEdit, QStackedWidget, QFileDialog, QMenu,
    QInputDialog, QMainWindow, QTabWidget, QComboBox, QCheckBox,
    QAbstractItemView, QSplitter, QMessageBox, QToolBar
)
from qdarktheme import setup_theme
from user_database import UserInfoData

try:
    import uvloop
except ImportError:
    import winuvloop as uvloop
finally:
    uvloop.install()


def path_stand(src: str, loc: str) -> tuple[str, str]:
    src = src.replace('\\', '/').rstrip('/')
    loc = loc.replace('\\', '/').rstrip('/')
    loc = '/'.join((loc, src.split('/')[-1]))
    return src, loc


class PasswordController(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.userinfo = UserInfoData()
        self.vbox = QVBoxLayout()
        self.user_list_widget = QListWidget()
        self.vbox.addWidget(self.user_list_widget)
        self.setLayout(self.vbox)
        self.idxs = []
        self.add_user_dict = {}
        self.user_list_widget.clicked.connect(self.item_clicked)

    def add_all_user(self) -> None:
        for value in self.userinfo.query_all():
            if self.add_user_dict.get(value):
                continue
            self.add_user_dict[value] = True
            self.add_item(*value)

    def add_item(self, idx: int, host: str, port: int, username: str, _password: str) -> None:
        self.idxs.append(idx)
        item = QListWidgetItem(f"IP地址: {host} 端口号:{port} 用户名:{username}")
        item.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DialogCancelButton))
        self.user_list_widget.addItem(item)

    def item_clicked(self, idx: QModelIndex) -> None:
        query = QMessageBox.question(
            self, "询问", "是否删除用户信息",
            QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if query == QMessageBox.StandardButton.Ok:
            self.user_list_widget.takeItem(idx.row())
            self.userinfo.del_idx(self.idxs[idx.row()])


class Edit(QWidget):
    def __init__(self, session: 'SFTPSession', src: str, text: str) -> None:
        super().__init__()
        self.setGeometry(0, 0, 500, 500)
        self.src = src
        self.session = session
        self.text = text
        self.vbox = QVBoxLayout()
        self.textEdit = QTextEdit()
        self.textEdit.setText(text)
        self.vbox.addWidget(self.textEdit)
        self.setLayout(self.vbox)
        self.show()

    def closeEvent(self, event: QCloseEvent) -> None:
        now_text = self.textEdit.toPlainText()
        if now_text == self.text:
            return
        reply = QMessageBox.question(self, "文件", "文件有改动，是否保存",
                                     QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
        if reply == QMessageBox.StandardButton.Ok:
            self.session.save_file(self.src, now_text)


class Transport:
    def __init__(self, src: str, loc: str, co_num: int, session: 'SFTPSession', pbar: int) -> None:
        super().__init__()
        self.src = src
        self.loc = loc
        self.co_num = co_num
        self.session = session
        self.sftp = session.sftp
        self.loop = session.loop
        self.task_core = []
        self.transport_fail_file = []
        self.now_progress_bar = 0
        self.pbar = pbar
        self.update_msg = session.update_msg
        self.pbar_msg = session.pbar_msg
        self.err_msg = session.err_msg

    async def start_core(self):
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
        pass

    def send_err(self, _future: asyncio.Future):
        err_src_str = "".join(self.transport_fail_file)
        self.err_msg.emit(err_src_str)

    def start(self):
        future = asyncio.run_coroutine_threadsafe(self.transport(), self.loop)
        future.add_done_callback(self.send_err)


class DownloadTransport(Transport):
    def __init__(self, src: str, loc: str, co_num: int, session: 'SFTPSession', pbar: int) -> None:
        super().__init__(src, loc, co_num, session, pbar)

    async def _transport_file(self, src: str, loc: str) -> None:
        last_size = 0

        def update(_src: bytes, _loc: bytes, now_size: int, _all_size: int) -> None:
            nonlocal last_size
            self.update_msg.emit(self.pbar, self.now_progress_bar + now_size - last_size)
            self.now_progress_bar += now_size - last_size
            last_size = now_size

        try:
            await self.sftp.get(src, loc, progress_handler=update)
        except (OSError, asyncssh.SFTPError):
            all_size = await self.sftp.getsize(src)
            self.update_msg.emit(self.pbar, self.now_progress_bar + all_size - last_size)
            self.now_progress_bar += all_size - last_size
            self.transport_fail_file.append(src + "\n")

    async def _transport_dir_init(self, src: str, loc: str) -> int:
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
        try:
            src, loc = path_stand(self.src, self.loc)
            if await self.sftp.isdir(src):
                all_size = await self._transport_dir_init(src, loc)
                self.pbar_msg.emit(self.pbar, all_size)
                await self.start_core()
            else:
                all_size = await self.sftp.getsize(src)
                self.pbar_msg.emit(self.pbar, all_size)
                await self._transport_file(src, loc)
            self.update_msg.emit(self.pbar, all_size)
        except asyncio.CancelledError:
            pass


class UploadTransport(Transport):
    def __init__(self, src: str, loc: str, co_num: int, session: 'SFTPSession', pbar: int) -> None:
        super().__init__(src, loc, co_num, session, pbar)
        self.task_list_mkdir = []

    async def _transport_file(self, src: str, loc: str) -> None:
        last_size = 0

        def update(_src: bytes, _loc: bytes, now_size: int, _all_size: int) -> None:
            nonlocal last_size
            self.update_msg.emit(self.pbar, self.now_progress_bar + now_size - last_size)
            self.now_progress_bar += now_size - last_size
            last_size = now_size

        try:
            await self.sftp.put(src, loc, progress_handler=update)
        except (OSError, asyncssh.SFTPError):
            all_size = os.path.getsize(src)
            self.update_msg.emit(self.pbar, self.now_progress_bar + all_size - last_size)
            self.now_progress_bar += all_size - last_size
            self.transport_fail_file.append(src + "\n")

    def _transport_dir_init(self, src: str, loc: str) -> int:
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
        try:
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
            self.update_msg.emit(self.pbar, all_size)
        except asyncio.CancelledError:
            pass


class SFTPSession(QThread):
    update_msg = Signal(int, int)  # Signal for progress bar updates
    pbar_msg = Signal(int, int)  # Signal for progress bar initialization
    err_msg = Signal(str)  # Signal for error messages

    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.loop = asyncio.new_event_loop()
        self.ssh = self.loop.run_until_complete(
            asyncssh.connect(host=host, port=port, username=username, password=password, known_hosts=None))
        self.sftp = self.loop.run_until_complete(self.ssh.start_sftp_client())

    def run(self) -> None:
        self.loop.run_forever()

    def getcwd(self) -> str:
        return asyncio.run_coroutine_threadsafe(self.sftp.getcwd(), self.loop).result()

    def read_dir(self, src: str) -> Sequence[asyncssh.SFTPName]:
        return asyncio.run_coroutine_threadsafe(self.sftp.readdir(src), self.loop).result()

    def change_dir(self, src: str) -> None:
        asyncio.run_coroutine_threadsafe(self.sftp.chdir(src), self.loop).result()

    def is_file(self, src: str) -> bool:
        return asyncio.run_coroutine_threadsafe(self.sftp.isfile(src), self.loop).result()

    async def _read_file(self, src: str) -> str:
        text = ""
        async with self.sftp.open(src, 'rb') as f:
            text += (await f.read()).decode()
        return text

    def read_file(self, src: str) -> str:
        return asyncio.run_coroutine_threadsafe(self._read_file(src), self.loop).result()

    async def _save_file(self, src: str, text: str) -> None:
        async with self.sftp.open(src, 'wb') as f:
            await f.write(text.encode())

    def save_file(self, src: str, text: str) -> None:
        asyncio.run_coroutine_threadsafe(self._save_file(src, text), self.loop).result()

    def del_file(self, src: str) -> None:
        asyncio.run_coroutine_threadsafe(self.sftp.remove(src), self.loop).result()

    def del_dir(self, src: str) -> None:
        asyncio.run_coroutine_threadsafe(self.remove_dir(src), self.loop).result()

    def make_dir(self, src: str) -> None:
        asyncio.run_coroutine_threadsafe(self.sftp.makedirs(src, exist_ok=True), self.loop).result()

    def rename(self, src: str, new: str) -> None:
        asyncio.run_coroutine_threadsafe(self.sftp.rename(src, new), self.loop).result()

    def download(self, src: str, loc: str, co_num: int, pbar: int) -> None:
        dt = DownloadTransport(src, loc, co_num, self, pbar)
        dt.start()

    def upload(self, src: str, loc: str, co_num: int, pbar: int) -> None:
        ut = UploadTransport(src, loc, co_num, self, pbar)
        ut.start()

    async def remove_dir(self, src: str) -> None:
        await self.ssh.run(f"rm -rf {src}")

    async def _run_command(self, com: str) -> asyncssh.SSHCompletedProcess:
        return await self.ssh.run(com)

    def run_command(self, com: str) -> asyncssh.SSHCompletedProcess:
        return asyncio.run_coroutine_threadsafe(self._run_command(com), self.loop).result()

    def realpath(self, src: str) -> str:
        return asyncio.run_coroutine_threadsafe(self.sftp.realpath(src.encode()), self.loop).result().decode()

    def move_file(self, old_path: str, new_path: str) -> None:
        self.run_command(f"mv {old_path} {new_path}")

    def copy_file(self, src: str, dst: str) -> None:
        self.run_command(f"cp -r {src} {dst}")


class CheckFileDynamically:
    def __init__(self, remote_file_display: 'RemoteFileDisplay'):
        super().__init__()
        self.remote_file_display = remote_file_display
        self.new_file_msg = self.remote_file_display.new_file_msg
        self.sub_file_msg = self.remote_file_display.sub_file_msg
        self.sftp = self.remote_file_display.session.sftp
        self.loop = self.remote_file_display.session.loop

    async def check_file_new(self):
        while True:
            now_file_list = await self.sftp.readdir(".")
            all_file_dict = self.remote_file_display.all_files_dict
            new_files = []
            for entry in now_file_list:
                if entry.filename in (".", ".."):
                    continue
                if entry.filename not in all_file_dict:
                    new_files.append(entry)
            if new_files:
                self.new_file_msg.emit(new_files)
            await asyncio.sleep(0.5)

    async def check_file_old(self):
        while True:
            now_file_list = set([entry.filename async for entry in self.sftp.scandir(".")])
            all_file_dict = self.remote_file_display.all_files_dict
            sub_files = []
            for file in all_file_dict:
                if file not in now_file_list:
                    sub_files.append(file)
            if sub_files:
                self.sub_file_msg.emit(sub_files)
            await asyncio.sleep(0.5)

    def run(self):
        asyncio.gather(self.check_file_new(), self.check_file_old(), loop=self.loop)


class RemoteFileDisplay(QWidget):
    new_file_msg = Signal(list)
    sub_file_msg = Signal(list)

    def __init__(self, sftp_main_window: 'SFTPMainWindow') -> None:
        super().__init__()
        self.sftp_main_window = sftp_main_window
        self.session = sftp_main_window.session
        self.main_window_path = self.session.getcwd()
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
        self.checker = CheckFileDynamically(self)
        self.select_item = None
        self.setLayout(self.vbox)
        self.init_ui()
        self.file_icon = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)
        self.dir_icon = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)

    @Slot(list)
    def display_new_file(self, new_files: list[asyncssh.SFTPName]):
        for entry in new_files:
            filename = entry.filename
            if filename in self.all_files_dict:
                continue
            item = QListWidgetItem(filename)
            if entry.attrs.type == 2:
                item.setIcon(self.dir_icon)
                self.display_file_list.insertItem(0, item)
            else:
                item.setIcon(self.file_icon)
                self.display_file_list.addItem(item)
            self.all_files_dict[filename] = item

    @Slot(list)
    def del_sub_file(self, sub_files: list[str]):
        for file in sub_files:
            if file not in self.all_files_dict:
                continue
            item = self.all_files_dict[file]
            row = self.display_file_list.row(item)
            self.display_file_list.takeItem(row)
            self.all_files_dict.pop(file)

    def init_ui(self) -> None:
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
        self.checker.run()

    def search_edit_value(self, text: str) -> None:
        if not text:
            for item in self.all_files_dict.values():
                item.setHidden(False)
            return
        for item in self.all_files_dict.values():
            item.setHidden(text not in item.text())

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        for url in event.mimeData().urls():
            os.makedirs("tmp", exist_ok=True)
            self.sftp_main_window.upload(url.toLocalFile(), self.session.getcwd(), 10)
        event.acceptProposedAction()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.session.change_dir(self.main_window_path)

    def refresh(self):
        self.display_file_list.clear()
        self.all_files_dict.clear()

    def show_context_menu(self, pos: QPoint) -> None:
        item = self.display_file_list.itemAt(pos)
        context_menu = QMenu(self)
        makedir_action = context_menu.addAction("新建文件夹")
        new_file_action = context_menu.addAction("新文件")
        refresh_action = context_menu.addAction("刷新")
        makedir_action.triggered.connect(self.makedir)
        new_file_action.triggered.connect(self.new_file)
        refresh_action.triggered.connect(self.refresh)
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
        for item in self.display_file_list.selectedItems():
            self.download_item(item)

    def download_item(self, item: QListWidgetItem) -> None:
        os.makedirs("tmp", exist_ok=True)
        self.sftp_main_window.download(self.realpath(item.text()), "./tmp", 10)

    def paste_items(self) -> None:
        for old_path in self.copy_paths:
            self.session.copy_file(old_path, self.session.getcwd())
        self.copy_paths.clear()

    def put_items(self) -> None:
        for item, old_path in self.move_paths:
            try:
                self.session.move_file(old_path, self.session.getcwd())
                item.setHidden(False)
            except:
                pass
        self.move_paths.clear()

    def item_clicked(self, item: QListWidgetItem) -> None:
        self.select_item = item

    def double_item_clicked(self, item: QListWidgetItem) -> None:
        if not self.session.is_file(item.text()):
            self.session.change_dir(item.text())
            self.path_edit.setText(self.session.getcwd())
            return
        src = item.text()
        edit = Edit(self.session, src, self.session.read_file(src))
        self.edits.append(edit)

    def del_items(self) -> None:
        text = ""
        for item in self.display_file_list.selectedItems():
            text += item.text() + "\n"
        reply = QMessageBox.question(self, "删除", f"确认删除:\n{text}\n",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            for item in self.display_file_list.selectedItems():
                self.del_item(item)

    def del_item(self, item: QListWidgetItem) -> None:
        src = self.realpath(item.text())
        if not self.session.is_file(src):
            self.session.del_dir(src)
        else:
            self.session.del_file(src)

    def makedir(self) -> None:
        text, ok = QInputDialog.getText(self, "新建", "输入文件夹名")
        if ok:
            self.session.make_dir(str(text))

    def new_file(self) -> None:
        text, ok = QInputDialog.getText(self, "新建", "输入文件名")
        if ok:
            self.session.save_file(str(text), "")

    def rename(self, item: QListWidgetItem) -> None:
        text, ok = QInputDialog.getText(self, "重命名", "输入新的文件名")
        if ok:
            self.session.rename(item.text(), str(text))

    def move_items(self) -> None:
        for item in self.display_file_list.selectedItems():
            self.move_item(item)

    def move_item(self, item: QListWidgetItem) -> None:
        item.setHidden(True)
        self.move_paths.append((item, self.realpath(item.text())))

    def copy_items(self) -> None:
        for item in self.display_file_list.selectedItems():
            self.copy_item(item)

    def copy_item(self, item: QListWidgetItem) -> None:
        self.copy_paths.append(self.realpath(item.text()))

    def realpath(self, path: str) -> str:
        return self.session.realpath(path)


class GetTransportPathWidget(QWidget):
    def __init__(self, sftp_main_window: 'SFTPMainWindow') -> None:
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
    def __init__(self, sftp_main_window: 'SFTPMainWindow') -> None:
        super().__init__(sftp_main_window)
        self.main_window = sftp_main_window
        self.src_button_dir.setVisible(False)
        self.remote_file.vbox.addWidget(self.remote_file.select_button)
        self.remote_file.select_button.clicked.connect(self.selected_file)
        self.src_button.clicked.connect(self.get_src_file)
        self.dst_button.clicked.connect(self.get_local_file)
        self.ok_button.clicked.connect(self.start_download)

    def selected_file(self) -> None:
        self.src_edit.setText(self.remote_file.realpath(self.remote_file.select_item.text()))
        self.remote_file.close()

    def start_download(self) -> None:
        if self.src_edit.text() and self.dst_edit.text() and self.co_num_edit.text():
            self.main_window.download(self.src_edit.text(), self.dst_edit.text(), int(self.co_num_edit.text()))
            self.close()
        else:
            QMessageBox.warning(self, "参数警告", "请参数不能为空", QMessageBox.StandardButton.Ok)

    def get_src_file(self) -> None:
        self.remote_file.show()

    def get_local_file(self) -> None:
        file_path = QFileDialog.getExistingDirectory(self, "Open file")
        self.dst_edit.setText(file_path)


class GetUploadPathWidget(GetTransportPathWidget):
    def __init__(self, sftp_main_window: 'SFTPMainWindow') -> None:
        super().__init__(sftp_main_window)
        self.main_window = sftp_main_window
        self.remote_file.vbox.addWidget(self.remote_file.select_button)
        self.remote_file.select_button.clicked.connect(self.selected_file)
        self.src_button.clicked.connect(self.get_src_file)
        self.dst_button.clicked.connect(self.get_local_file)
        self.ok_button.clicked.connect(self.start_upload)
        self.src_button_dir.clicked.connect(self.get_src_dir)

    def start_upload(self) -> None:
        if self.src_edit.text() and self.dst_edit.text() and self.co_num_edit.text():
            self.main_window.upload(self.src_edit.text(), self.dst_edit.text(), int(self.co_num_edit.text()))
            self.close()
        else:
            QMessageBox.warning(self, "参数警告", "请把所有参数填写完整", QMessageBox.StandardButton.Ok)

    def selected_file(self) -> None:
        self.dst_edit.setText(self.remote_file.realpath(self.remote_file.select_item.text()))
        self.remote_file.close()

    def get_local_file(self) -> None:
        self.remote_file.show()

    def get_src_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Open dir")
        self.src_edit.setText(dir_path)

    def get_src_file(self):
        file_path = QFileDialog.getOpenFileName(self, "Open file")
        if file_path[0]:
            self.src_edit.setText(file_path[0])


class RemoteFileMainWindow(RemoteFileDisplay):
    def __init__(self, sftp_main_window: 'SFTPMainWindow') -> None:
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
        self.get_upload_widget = GetUploadPathWidget(self.sftp_main_window)
        self.get_upload_widget.show()

    def get_download_path(self):
        self.get_download_widget = GetDownloadPathWidget(self.sftp_main_window)
        self.get_download_widget.show()


class ControlListWidget(QWidget):
    def __init__(self, sftp_main_window: 'SFTPMainWindow') -> None:
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
        text = self.control_list.item(index.row()).text()
        self.function[text]()

    def password_changed(self) -> None:
        self.sftp_main_window.password_control.add_all_user()
        self.sftp_main_window.stacked_widget.setCurrentIndex(2)

    def sftp_file_list(self) -> None:
        self.sftp_main_window.stacked_widget.setCurrentIndex(0)

    def transport(self) -> None:
        self.sftp_main_window.stacked_widget.setCurrentIndex(1)


class SFTPMainWindow(QWidget):
    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.session = SFTPSession(host, port, username, password)
        self.session.update_msg.connect(self.update_progress)
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
        self.file_icon = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)
        self.dir_icon = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)

    def init_ui(self) -> None:
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
        icon = self.file_icon if self.session.is_file(src) else self.dir_icon
        pbar = QProgressBar()
        item = QListWidgetItem(self.display_pbar_list)
        item_widget = QWidget()
        layout = QHBoxLayout(item_widget)
        text_label = QLabel(f"{transport_type}: {src}")
        picture_label = QLabel()
        picture_label.setPixmap(icon.pixmap(16, 16))
        layout.addWidget(picture_label)
        layout.addWidget(text_label)
        layout.addWidget(pbar)
        layout.setContentsMargins(0, 0, 0, 0)
        self.display_pbar_list.setItemWidget(item, item_widget)
        self.display_pbar_list.addItem(item)
        self.pbars.append(pbar)
        return len(self.pbars) - 1

    def download(self, src: str, loc: str, co_num: int) -> None:
        pbar = self.add_pbar(src, "下载")
        self.session.download(src, loc, co_num, pbar)

    def upload(self, src: str, loc: str, co_num: int) -> None:
        pbar = self.add_pbar(src, "上传")
        self.session.upload(src, loc, co_num, pbar)

    @Slot(int, int)
    def update_progress(self, pbar: int, value: int) -> None:
        self.pbars[pbar].setValue(value)

    @Slot(int, int)
    def set_progress(self, pbar: int, value: int) -> None:
        self.pbars[pbar].setRange(0, value)

    @Slot(str)
    def display_error(self, value: str) -> None:
        if value:
            QMessageBox.warning(self, "传输警告", f"{value}\n传输失败，注意检查权限和SFTP配置文件",
                                QMessageBox.StandardButton.Ok)


class LoginWindow(QWidget):
    def __init__(self, tab: QTabWidget, sftp_widget_list: list) -> None:
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
        value = self.userinfo.query_idx(self.idxs[idx])
        self.host_edit.setText(value[1])
        self.port_edit.setText(str(value[2]))
        self.username_edit.setText(value[3])
        self.password_edit.setText(value[4])

    def login(self) -> None:
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
        self.password_display = not self.password_display
        self.password_edit.setEchoMode(
            QLineEdit.EchoMode.Normal if self.password_display else QLineEdit.EchoMode.Password)


class UserMainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.tab = QTabWidget()
        self.setCentralWidget(self.tab)
        self.login_windows = []
        self.sftp_widget = []
        self.init_ui()
        self.show()
        self.login()

    def init_ui(self) -> None:
        self.tab.setTabsClosable(True)
        self.tab.tabCloseRequested.connect(self.close_tab)
        tool_bar = QToolBar()
        self.addToolBar(tool_bar)
        new_action = QAction("新建会话", self)
        new_action.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogNewFolder))
        new_action.triggered.connect(self.login)
        tool_bar.addAction(new_action)

    def login(self) -> None:
        login_window = LoginWindow(self.tab, self.sftp_widget)
        login_window.show()
        self.login_windows.append(login_window)

    def close_tab(self, index: int) -> None:
        self.tab.removeTab(index)
        self.sftp_widget[index].close()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    setup_theme("auto")
    us = UserMainWindow()
    sys.exit(app.exec())
