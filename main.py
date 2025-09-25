import os
import sys
import asyncio
from typing import Sequence

import asyncssh
import asyncio_pool

try:
    import uvloop
except ImportError:
    import winuvloop as uvloop
finally:
    uvloop.install()

from PyQt6.QtGui import QAction, QDropEvent, QDragEnterEvent, QCloseEvent
from PyQt6.QtCore import QThread, pyqtSignal, pyqtSlot, Qt, QPoint, QModelIndex
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QProgressBar, QLineEdit, QFormLayout, QLabel, \
    QPushButton, QHBoxLayout, QStyle, QListWidget, QListWidgetItem, QTextEdit, QStackedWidget, QFileDialog, QGridLayout, \
    QMenu, QInputDialog, QMainWindow, QTabWidget, QComboBox, QCheckBox, QAbstractItemView, QSplitter, QMessageBox, \
    QToolBar
from user_database import UserInfoData


def path_stand(src: str, loc: str) -> tuple[str, str]:
    """
    * 标准化目录形式，并把要传输的内容添加到loc末尾
    * src = c:\\path\\to\\src\\ -> c:/path/to/src
      loc = c:\\path\\to\\loc\\
      loc = c:\\path\\to\\loc\\src
    :param    src: 源文件(文件夹)地址
    :param    loc: 目标文件(文件夹)地址
    :return:  经过处理的 (src, loc)
    """
    src: str = src.replace('\\', '/')
    loc: str = loc.replace('\\', '/')
    src: str = src.removesuffix('/')
    loc: str = loc.removesuffix('/')
    loc: str = '/'.join((loc, src.split('/')[-1]))
    return src, loc


class PasswordController(QWidget):
    """
    * 利用host.db管理密码
    * 成功登陆时，就会记住用户名，密码
    """

    def __init__(self) -> None:
        super().__init__()
        self.userinfo: UserInfoData = UserInfoData()
        self.vbox: QVBoxLayout = QVBoxLayout()
        self.user_list_widget: QListWidget = QListWidget()
        self.vbox.addWidget(self.user_list_widget)
        self.setLayout(self.vbox)
        self.idxs: list[int] = list()
        self.user_list_widget.clicked.connect(self.item_clicked)
        self.add_user_dict: dict[tuple, bool] = dict()

    def add_all_user(self) -> None:
        for value in self.userinfo.query_all():
            if self.add_user_dict.get(value):
                continue
            self.add_user_dict[value] = True
            self.add_item(*value)

    def add_item(self, idx, host, port, username, _password) -> None:
        self.idxs.append(idx)
        item = QListWidgetItem(f"ip地址: {host} 端口号:{port} 用户名:{username}")
        item.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DialogCancelButton))
        self.user_list_widget.addItem(item)

    def item_clicked(self, idx: QModelIndex) -> None:
        """
        * 当用户点击item时先询问是否删除
        :param idx:
        :return:
        """
        query = QMessageBox.question(self, "询问", "是否删除用户信息",
                                     QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)
        if query == QMessageBox.StandardButton.Ok:
            self.user_list_widget.takeItem(idx.row())
            self.userinfo.del_idx(self.idxs[idx.row()])


class Edit(QWidget):
    """
    * 当用户点击SFTP窗口的文件时，打开这个窗口
    * 提供可以编辑文件
    """

    def __init__(self, src: str, text: str) -> None:
        super().__init__()
        self.setGeometry(0, 0, 500, 500)
        self.src: str = src
        self.button: QPushButton = QPushButton("保存")
        self.vbox: QVBoxLayout = QVBoxLayout()
        self.textEdit: QTextEdit = QTextEdit(text)
        self.vbox.addWidget(self.button)
        self.vbox.addWidget(self.textEdit)
        self.setLayout(self.vbox)
        self.show()


class Transport(QThread):
    def __init__(self, src: str, loc: str, co_num: int, session, pbar: int) -> None:
        super().__init__()
        self.src: str = src
        self.loc: str = loc
        self.co_num: int = co_num
        self.session = session
        self.sftp: asyncssh.SFTPClient = self.session.sftp
        self.loop: asyncio.AbstractEventLoop = self.session.loop
        self.task_core: list = []
        self.transport_fail_file: list[str] = []  # 记录传输失败的文件，往往由于权限，sftp服务器限制
        self.now_progress_bar: int = 0  # 记录目前进度条的长度
        self.pbar: int = pbar  # 进度条编号
        self.msg: pyqtSignal = session.msg  # 传输进度条的长度
        self.pbar_msg: pyqtSignal = session.pbar_msg  # 初始化进度条
        self.err_msg: pyqtSignal = session.err_msg  # 传输transport_fail_file的内容

    async def start_core(self):
        """
        * 下载小文件OI耗时很大，交替下载大小文件更好
        * l指针指向目前最大的文件，r指向目前最小的文件
        * 当最大的文件传输时，同时下载小文件
        :return:
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
        * 下载，上传不区分
        * self.src代表文件来源，self.loc表示文件目标地址
        :return:
        """
        pass

    def run(self):
        _ = asyncio.run_coroutine_threadsafe(self.transport(), self.loop).result()
        err_src_str = ""
        for src in self.transport_fail_file:
            err_src_str += src + "\n"
        self.err_msg.emit(err_src_str)


class DownloadTransport(Transport):
    def __init__(self, src: str, loc: str, co_num: int, session, pbar: int) -> None:
        super().__init__(src, loc, co_num, session, pbar)

    async def _transport_file(self, src: str, loc: str) -> None:
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
            self.transport_fail_file.append(src)

    async def _transport_dir_init(self, src: str, loc: str) -> int:
        if not os.path.exists(loc):
            os.mkdir(loc)
        task_list: list[asyncio.Task] = list()
        total: int = 0
        async for entry in self.sftp.scandir(src):
            filename: str = entry.filename
            if filename == '.' or filename == '..':
                continue
            next_src: str = "/".join((src, filename))
            next_loc: str = "/".join((loc, filename))
            if entry.attrs.type == 2:
                task_list.append(
                    asyncio.create_task(self._transport_dir_init(next_src, next_loc)))
            else:
                total += entry.attrs.size
                self.task_core.append((entry.attrs.size, self._transport_file(next_src, next_loc)))
        for future in asyncio.as_completed(task_list):
            total += await future
        return total

    async def transport(self) -> None:
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
    def __init__(self, src: str, loc: str, co_num: int, session, pbar: int) -> None:
        super().__init__(src, loc, co_num, session, pbar)
        self.task_list_mkdir = list()

    async def _transport_file(self, src: str, loc: str) -> None:
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
            self.transport_fail_file.append(src)

    def _transport_dir_init(self, src: str, loc: str) -> int:
        total_size: int = 0
        self.task_list_mkdir.append((self.sftp.makedirs(loc, exist_ok=True)))
        for entry in os.scandir(src):
            filename: str = entry.name
            next_src: str = "/".join((src, filename))
            next_loc: str = "/".join((loc, filename))
            if entry.is_dir():
                total_size += self._transport_dir_init(next_src, next_loc)
            else:
                self.task_core.append((entry.stat().st_size, self._transport_file(next_src, next_loc)))
                total_size += entry.stat().st_size
        return total_size

    async def transport(self) -> None:
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
    * 传输SFTP数据
    """
    msg = pyqtSignal(int, int)  # 更新进度条信号
    pbar_msg = pyqtSignal(int, int)
    err_msg = pyqtSignal(str)

    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        super().__init__()
        self.host: str = host
        self.port: int = port
        self.username: str = username
        self.password: str = password
        self.transport: list[Transport] = []
        self.loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        self.ssh: asyncssh.SSHClientConnection = self.loop.run_until_complete(
            asyncssh.connect(host=host, port=port, username=username, password=password, known_hosts=None))
        self.sftp: asyncssh.SFTPClient = self.loop.run_until_complete(self.ssh.start_sftp_client())

    def run(self) -> None:
        """
        让asyncio的事件循环在主线程中运行
        :return:
        """
        self.loop.run_forever()

    def getcwd(self) -> str:
        res = asyncio.run_coroutine_threadsafe(self.sftp.getcwd(), self.loop).result()
        return res

    def read_dir(self, src: str) -> Sequence[asyncssh.SFTPName]:
        res = asyncio.run_coroutine_threadsafe(self.sftp.readdir(src), self.loop).result()
        return res

    def change_dir(self, src: str) -> None:
        _ = asyncio.run_coroutine_threadsafe(self.sftp.chdir(src), self.loop).result()

    def is_file(self, src: str) -> bool:
        return asyncio.run_coroutine_threadsafe(self.sftp.isfile(src), self.loop).result()

    async def _read_file(self, src: str) -> str:
        text = ""
        async with self.sftp.open(src, 'rb') as f:
            text += (await f.read(1024)).decode()
        return text

    def read_file(self, src: str) -> str:
        return asyncio.run_coroutine_threadsafe(self._read_file(src), self.loop).result()

    async def _save_file(self, src: str, text: str) -> None:
        async with self.sftp.open(src, 'wb') as f:
            await f.write(text)

    def save_file(self, src: str, text: str) -> None:
        _ = asyncio.run_coroutine_threadsafe(self._save_file(src, text), self.loop).result()

    def del_file(self, src: str) -> None:
        _ = asyncio.run_coroutine_threadsafe(self.sftp.remove(src), self.loop).result()

    def del_dir(self, src: str) -> None:
        _ = asyncio.run_coroutine_threadsafe(self.remove_dir(src), self.loop).result()

    def make_dir(self, src: str) -> None:
        _ = asyncio.run_coroutine_threadsafe(self.sftp.makedirs(src, exist_ok=True), self.loop).result()

    def rename(self, src: str, new: str) -> None:
        _ = asyncio.run_coroutine_threadsafe(self.sftp.rename(src, new), self.loop).result()

    def download(self, src: str, loc: str, co_num: int, pbar: int) -> None:
        dt = DownloadTransport(src, loc, co_num, self, pbar)
        dt.start()
        self.transport.append(dt)

    def upload(self, src: str, loc: str, co_num: int, pbar: int) -> None:
        ut = UploadTransport(src, loc, co_num, self, pbar)
        ut.start()
        self.transport.append(ut)

    async def remove_dir(self, src: str) -> None:
        await self.ssh.run(f"rm -rf {src}")

    async def _run_command(self, com: str) -> asyncssh.SSHCompletedProcess:
        result = await self.ssh.run(com)
        return result

    def run_command(self, com: str) -> asyncssh.SSHCompletedProcess:
        return asyncio.run_coroutine_threadsafe(self._run_command(com), self.loop).result()

    def realpath(self, src: str) -> str:
        res = asyncio.run_coroutine_threadsafe(self.sftp.realpath(src.encode()), self.loop).result()
        return res.decode()

    def move_file(self, old_path: str, new_path: str) -> None:
        _ = self.run_command(f"mv {old_path} {new_path}")

    def copy_file(self, src: str, dst: str) -> None:
        _ = self.run_command(f"cp -r {src} {dst}")


class RemoteFileDisplay(QWidget):
    def __init__(self, sftp_main_window) -> None:
        super().__init__()
        self.dir_item: list[QListWidgetItem] = []
        self.file_item: list[QListWidgetItem] = []
        self.move_paths: list[str] = []
        self.copy_paths: list[str] = []
        self.sftp_main_window = sftp_main_window
        self.session: SFTPSession = self.sftp_main_window.session
        self.main_window_path: str = self.session.getcwd()
        self.back_button = QPushButton("返回上层目录")
        self.select_button = QPushButton("选择")
        self.no_button = QPushButton("取消")
        self.path_edit = QLineEdit()
        self.search_edit = QLineEdit()
        self.search_label = QLabel("搜索文件:")
        self.vbox = QVBoxLayout()
        self.setLayout(self.vbox)
        self.display_file_list = QListWidget()
        self.select_item = None
        self.init_ui()

    def search_edit_value(self, text) -> None:
        if text == "":
            for item in self.dir_item:
                item.setHidden(False)
            for item in self.file_item:
                item.setHidden(False)
            return
        for item in self.dir_item:
            if text not in item.text():
                item.setHidden(True)
        for item in self.file_item:
            if text not in item.text():
                item.setHidden(True)

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()  # 接受拖放事件

    def dropEvent(self, event: QDropEvent) -> None:
        urls = event.mimeData().urls()
        for url in urls:
            self.sftp_main_window.upload(url.toLocalFile(), self.session.getcwd(), 2)
        event.acceptProposedAction()

    def closeEvent(self, event: QCloseEvent) -> None:
        self.session.change_dir(self.main_window_path)

    def init_ui(self) -> None:
        self.display_file_list.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        self.setAcceptDrops(True)
        self.search_edit.textChanged.connect(self.search_edit_value)
        self.back_button.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ArrowBack))
        self.back_button.setStyleSheet("text-align: left;")
        hbox = QHBoxLayout()
        hbox_search = QHBoxLayout()
        hbox_search.addWidget(self.search_label)
        hbox_search.addWidget(self.search_edit)
        hbox.addWidget(self.back_button)
        hbox.addWidget(self.path_edit)
        hbox.addLayout(hbox_search)
        self.path_edit.setReadOnly(True)
        self.path_edit.setText(self.session.getcwd())
        self.vbox.addLayout(hbox)
        self.vbox.addWidget(self.display_file_list)
        self.back_button.clicked.connect(lambda: self.double_item_clicked(QListWidgetItem("..")))
        self.display_file_list.itemDoubleClicked.connect(self.double_item_clicked)
        self.display_file_list.itemClicked.connect(self.item_clicked)
        self.display_dir(".")
        self.display_file_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.display_file_list.customContextMenuRequested.connect(self.show_context_menu)

    def show_context_menu(self, pos: QPoint) -> None:
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
            rename_action = context_menu.addAction("重命名")
            move_action = context_menu.addAction("移动")
            copy_action = context_menu.addAction("复制")
            download_action = context_menu.addAction("下载")
            rename_action.triggered.connect(lambda: self.rename(item))
            edit_action.triggered.connect(lambda: self.double_item_clicked(item))
            del_action.triggered.connect(self.del_items)
            move_action.triggered.connect(self.move_items)
            copy_action.triggered.connect(self.copy_items)
            download_action.triggered.connect(self.download_items)
        if len(self.move_paths):
            put_file_action = context_menu.addAction("放置")
            put_file_action.triggered.connect(self.put_items)
            context_menu.addAction(put_file_action)
        if len(self.copy_paths):
            paste_action = context_menu.addAction("粘贴")
            paste_action.triggered.connect(self.paste_items)
            context_menu.addAction(paste_action)

        context_menu.exec(self.display_file_list.mapToGlobal(pos))

    def download_items(self) -> None:
        items = self.display_file_list.selectedItems()
        for item in items:
            self.download_item(item)

    def download_item(self, item: QListWidgetItem) -> None:
        self.sftp_main_window.download(self.realpath(item.text()), "./tmp", 2)

    def paste_items(self) -> None:
        for old_path in self.copy_paths:
            self.session.copy_file(old_path, self.session.getcwd())
        self.copy_paths.clear()
        self.reload_dir()

    def put_items(self) -> None:
        for old_path in self.move_paths:
            self.session.move_file(old_path, self.session.getcwd())
        self.move_paths.clear()
        self.reload_dir()

    def reload_dir(self) -> None:
        self.display_file_list.clear()
        self.display_dir()

    def item_clicked(self, item: QListWidgetItem) -> None:
        self.select_item = item

    def double_item_clicked(self, item: QListWidgetItem) -> None:
        if not self.session.is_file(item.text()):
            self.session.change_dir(item.text())
            self.display_file_list.clear()
            self.display_dir()
            self.path_edit.setText(self.session.getcwd())
            return
        src = item.text()
        edit = Edit(src, self.session.read_file(src))
        edit.button.clicked.connect(lambda: self.session.save_file(src, edit.textEdit.toPlainText()))

    def del_items(self) -> None:
        items = self.display_file_list.selectedItems()
        for item in items:
            self.del_item(item)
        self.reload_dir()

    def del_item(self, item: QListWidgetItem) -> None:
        src = self.realpath(item.text())
        if not self.session.is_file(src):
            self.session.del_dir(self.realpath(src))
            return
        self.session.del_file(src)

    def makedir(self) -> None:
        text, ok = QInputDialog.getText(self, "新建", "输入文件夹名")
        if ok:
            self.session.make_dir(str(text))
            self.reload_dir()

    def new_file(self) -> None:
        text, ok = QInputDialog.getText(self, "新建", "输入文件名")
        if ok:
            self.session.save_file(str(text), "")
            self.reload_dir()

    def rename(self, item: QListWidgetItem) -> None:
        text, ok = QInputDialog.getText(self, "重命名", "输入新的文件名")
        if ok:
            self.session.rename(item.text(), str(text))
            self.reload_dir()

    def display_dir(self, src: str = ".") -> None:
        self.dir_item.clear()
        self.file_item.clear()
        info = self.session.read_dir(src)
        for entry in info:
            if entry.filename == '.' or entry.filename == '..':
                continue
            icon = QStyle.StandardPixmap.SP_FileIcon if entry.attrs.type != 2 else QStyle.StandardPixmap.SP_DirIcon
            item = QListWidgetItem(entry.filename)
            item.setIcon(QApplication.style().standardIcon(icon))
            self.dir_item.append(item) if entry.attrs.type == 2 else self.file_item.append(item)
        for item in self.dir_item:
            self.display_file_list.addItem(item)
        for item in self.file_item:
            self.display_file_list.addItem(item)

    def move_items(self) -> None:
        items = self.display_file_list.selectedItems()
        for item in items:
            self.move_item(item)

    def move_item(self, item: QListWidgetItem) -> None:
        item.setHidden(True)
        path = self.realpath(item.text())
        self.move_paths.append(path)

    def copy_items(self) -> None:
        items = self.display_file_list.selectedItems()
        for item in items:
            self.copy_item(item)

    def copy_item(self, item: QListWidgetItem) -> None:
        path = self.realpath(item.text())
        self.copy_paths.append(path)

    def realpath(self, path: str):
        return self.session.realpath(path)


class GetTransportPathWidget(QWidget):
    def __init__(self, sftp_main_window) -> None:
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
        self.init_ui()

    def init_ui(self) -> None:
        self.grid.addWidget(self.src_edit, 0, 0)
        self.grid.addWidget(self.src_button, 0, 1)
        self.grid.addWidget(self.src_button_dir, 0, 2)
        self.grid.addWidget(self.dst_edit, 1, 0)
        self.grid.addWidget(self.dst_button, 1, 1)
        self.grid.addWidget(self.co_num_edit, 2, 0)
        self.grid.addWidget(QLabel("协程数量"), 2, 1)
        self.grid.addWidget(self.ok_button, 3, 0)


class GetDownloadPathWidget(GetTransportPathWidget):
    def __init__(self, sftp_main_window) -> None:
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
            return
        QMessageBox.warning(self, "参数警告", "请参数不能为空", QMessageBox.StandardButton.Ok)

    def get_src_file(self) -> None:
        self.remote_file.show()

    def get_local_file(self) -> None:
        file_path = QFileDialog.getExistingDirectory(self, "Open file")
        self.dst_edit.setText(file_path)


class GetUploadPathWidget(GetTransportPathWidget):
    def __init__(self, sftp_main_window) -> None:
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
            return
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


class ControlListWidget(QWidget):
    def __init__(self, sftp_main_window) -> None:
        super().__init__()
        self.sftp_main_window = sftp_main_window
        self.layout = QVBoxLayout()
        self.control_list = QListWidget()
        self.items = ["sftp", "密码管理", "传输管理"]
        self.control_list.addItems(self.items)
        self.control_list.clicked.connect(self.clicked_item)
        self.layout.addWidget(self.control_list)
        self.setLayout(self.layout)
        self.function = {"密码管理": self.password_changed,
                         "sftp": self.sftp_file_list,
                         "传输管理": self.transport
                         }

    def clicked_item(self, index: QModelIndex) -> None:
        row = index.row()
        item = self.control_list.item(row)
        text = item.text()
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
        self.session.msg.connect(self.update_progress)
        self.session.pbar_msg.connect(self.set_progress)
        self.session.err_msg.connect(self.display_error)
        self.session.start()
        self.stacked_widget = QStackedWidget()
        self.display_pbar_list = QListWidget()
        self.remote_file_widget = RemoteFileDisplay(self)
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
        self.setWindowTitle("SFTP Session")
        self.splitter_control_transport.addWidget(self.control_windows)
        self.splitter_control_transport.addWidget(self.stacked_widget)
        self.splitter_control_transport.setStretchFactor(0, 0)
        self.splitter_control_transport.setStretchFactor(1, 3)
        self.hbox.addWidget(self.splitter_control_transport)
        self.stacked_widget.addWidget(self.remote_file_widget)  # 0
        self.stacked_widget.addWidget(self.display_pbar_list)  # 1
        self.stacked_widget.addWidget(self.password_control)  # 2

    def add_pbar(self, src) -> int:
        icon = QStyle.StandardPixmap.SP_FileIcon if self.session.is_file(src) else QStyle.StandardPixmap.SP_DirIcon
        pbar = QProgressBar()
        item = QListWidgetItem(self.display_pbar_list)
        item_widget = QWidget()
        layout = QHBoxLayout(item_widget)
        text_label = QLabel(src)
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
        pbar = self.add_pbar(src)
        self.session.download(src, loc, co_num, pbar)

    def upload(self, src: str, loc: str, co_num: int) -> None:
        pbar = self.add_pbar(src)
        self.session.upload(src, loc, co_num, pbar)

    @pyqtSlot(int, int)
    def update_progress(self, pbar, value) -> None:
        self.pbars[pbar].setValue(value)

    @pyqtSlot(int, int)
    def set_progress(self, pbar, value) -> None:
        self.pbars[pbar].setRange(0, value)

    @pyqtSlot(str)
    def display_error(self, value) -> None:
        if value == "":
            return
        QMessageBox().warning(self, "传输警告", f"{value}传输失败，注意检查权限，和sftp配置文件",
                              QMessageBox.StandardButton.Ok)


class LoginWindow(QWidget):
    def __init__(self, tab: QTabWidget, sftp_widget_list: list) -> None:
        super().__init__()
        self.sftp_widget_list = sftp_widget_list
        self.form = QFormLayout()
        self.tab = tab
        self.setWindowTitle("Login")
        self.combox = QComboBox()
        self.host_edit = QLineEdit()
        self.port_edit = QLineEdit()
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.login_button = QPushButton("登陆")
        self.cancel_button = QPushButton("取消")
        self.checkbox = QCheckBox()
        self.userinfo = UserInfoData()
        self.sftp_main_window = SFTPMainWindow
        self.setLayout(self.form)
        self.idxs = []
        self.init_ui()
        self.password_display = False

    def init_ui(self) -> None:
        self.combox.currentIndexChanged.connect(self.selected_item)
        users = []
        for query_value in self.userinfo.query_all():
            idx = query_value[0]
            host = query_value[1]
            # port = query_value[2]
            username = query_value[3]
            display_info = f"{host}:{username}"
            self.idxs.append(idx)
            users.append(display_info)
        self.combox.addItems(users)
        self.checkbox.clicked.connect(self.set_password_mode)

        self.form.addRow(QLabel("存储ip"), self.combox)
        self.form.addRow(QLabel("服务器ip:"), self.host_edit)
        self.form.addRow(QLabel("端口号:"), self.port_edit)
        self.form.addRow(QLabel("用户名:"), self.username_edit)
        self.form.addRow(QLabel("密码:"), self.password_edit)
        self.form.addRow(QLabel("显示密码"), self.checkbox)
        self.password_edit.setEchoMode(self.password_edit.EchoMode.Password)
        self.form.addRow(self.login_button, self.cancel_button)
        self.login_button.clicked.connect(self.login)
        self.cancel_button.clicked.connect(self.close)

    def selected_item(self, idx: int) -> None:
        value = self.userinfo.query_idx(self.idxs[idx])
        host = value[1]
        port = value[2]
        username = value[3]
        password = value[4]
        self.host_edit.setText(host)
        self.port_edit.setText(str(port))
        self.username_edit.setText(username)
        self.password_edit.setText(password)

    def login(self) -> None:
        host = self.host_edit.text()
        port = int(self.port_edit.text())
        username = self.username_edit.text()
        password = self.password_edit.text()
        try:
            if host and port and username and password:
                self.sftp_main_window = self.sftp_main_window(host, port, username, password)
                self.userinfo.insert(host, port, username, password)
                self.close()
                self.tab.addTab(self.sftp_main_window, host)
                self.sftp_widget_list.append(self.sftp_main_window)
            else:
                QMessageBox.warning(self, "参数警告", "请参数不能为空", QMessageBox.StandardButton.Ok)
        except Exception as e:
            print(e)

    def set_password_mode(self) -> None:
        if self.password_display:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.password_display = False
        else:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self.password_display = True


class UserMainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.tab = QTabWidget()
        self.setCentralWidget(self.tab)
        self.init_ui()
        self.login_windows: list[LoginWindow] = []
        self.sftp_widget: list[SFTPMainWindow] = []
        self.get_transport_path_widget: list[GetTransportPathWidget] = []
        self.show()
        self.login()

    def init_ui(self) -> None:
        self.tab.setTabsClosable(True)
        self.tab.tabCloseRequested.connect(self.close_tab)
        tool_bar = QToolBar()
        self.addToolBar(tool_bar)
        new_action = QAction("新建回话", self)
        download_action = QAction("下载", self)
        upload_action = QAction("上传", self)
        new_action.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogNewFolder))
        download_action.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ArrowDown))
        upload_action.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ArrowUp))
        download_action.triggered.connect(self.download)
        upload_action.triggered.connect(self.upload)
        new_action.triggered.connect(self.login)
        tool_bar.addAction(new_action)
        tool_bar.addAction(download_action)
        tool_bar.addAction(upload_action)

    def upload(self) -> None:
        idx = self.tab.currentIndex()
        sftp_main_window = self.sftp_widget[idx]
        gp = GetUploadPathWidget(sftp_main_window)
        gp.show()
        self.get_transport_path_widget.append(gp)

    def download(self) -> None:
        idx = self.tab.currentIndex()
        sftp_main_window = self.sftp_widget[idx]
        gd = GetDownloadPathWidget(sftp_main_window)
        gd.show()
        self.get_transport_path_widget.append(gd)

    def login(self) -> None:
        login_window = LoginWindow(self.tab, self.sftp_widget)
        login_window.show()
        self.login_windows.append(login_window)

    def close_tab(self, index) -> None:
        self.tab.removeTab(index)
        self.sftp_widget[index].close()


if __name__ == '__main__':
    os.makedirs("tmp", exist_ok=True)
    app = QApplication(sys.argv)
    us = UserMainWindow()
    sys.exit(app.exec())
