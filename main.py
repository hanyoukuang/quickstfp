import asyncio
import sys
import asyncssh
import os
import threading

from PyQt6.QtGui import QAction
from asyncio_pool import AioPool
from PyQt6.QtCore import QThread, pyqtSignal, pyqtSlot, Qt, QPoint
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QProgressBar, QLineEdit, QFormLayout, QLabel, \
    QPushButton, QHBoxLayout, QStyle, QListWidget, QListWidgetItem, QTextEdit, QStackedWidget, QFileDialog, QGridLayout, \
    QMenu, QInputDialog, QMainWindow, QTabWidget


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


class Edit(QWidget):
    """
    * 当用户点击SFTP窗口的文件时，打开这个窗口
    * 提供可以编辑文件
    """

    def __init__(self, src, text):
        super().__init__()
        self.setGeometry(0, 0, 500, 500)
        self.src = src
        self.button = QPushButton("保存")
        self.vbox = QVBoxLayout()
        self.setLayout(self.vbox)
        self.textEdit = QTextEdit(text)
        self.vbox.addWidget(self.button)
        self.vbox.addWidget(self.textEdit)
        self.show()


class SFTPSession(QThread):
    """
    * 传输SFTP数据
    """
    msg = pyqtSignal(QProgressBar, int)  # 更新进度条信号

    def __init__(self, host: str, port: int, username: str, password: str):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.loop = asyncio.new_event_loop()
        self.ssh = self.loop.run_until_complete(
            asyncssh.connect(host=host, port=port, username=username, password=password, known_hosts=None))
        self.sftp = self.loop.run_until_complete(self.ssh.start_sftp_client())
        self.process = self.loop.run_until_complete(self.ssh.create_process())
        self.all_progress_list = []

    def run(self):
        """
        让asyncio的事件循环在主线程中运行
        :return:
        """
        self.loop.run_forever()

    def getcwd(self):
        res = asyncio.run_coroutine_threadsafe(self.sftp.getcwd(), self.loop).result()
        return res

    def read_dir(self, src: str):
        res = asyncio.run_coroutine_threadsafe(self.sftp.readdir(src), self.loop).result()
        return res

    def change_dir(self, src: str):
        asyncio.run_coroutine_threadsafe(self.sftp.chdir(src), self.loop).result()

    def is_file(self, src: str):
        return asyncio.run_coroutine_threadsafe(self.sftp.isfile(src), self.loop).result()

    async def _read_file(self, src: str):
        text = ""
        async with self.sftp.open(src, 'rb') as f:
            text += (await f.read(1024)).decode()
        return text

    def read_file(self, src: str):
        return asyncio.run_coroutine_threadsafe(self._read_file(src), self.loop).result()

    async def _save_file(self, src: str, text: str):
        async with self.sftp.open(src, 'wb') as f:
            await f.write(text)

    def save_file(self, src: str, text: str):
        asyncio.run_coroutine_threadsafe(self._save_file(src, text), self.loop).result()

    def del_file(self, src: str):
        asyncio.run_coroutine_threadsafe(self.sftp.remove(src), self.loop).result()

    def del_dir(self, src: str):
        asyncio.run_coroutine_threadsafe(self.remove_dir(src), self.loop).result()

    def make_dir(self, src: str):
        asyncio.run_coroutine_threadsafe(self.sftp.makedirs(src, exist_ok=True), self.loop).result()

    async def _download_file(self, src: str, loc: str, pbar: QProgressBar, pbar_idx: int) -> None:
        last_size = 0

        def update(_src: bytes, _loc: bytes, now_size: int, _all_size: int) -> None:
            nonlocal last_size
            self.msg.emit(pbar, self.all_progress_list[pbar_idx] + now_size - last_size)
            self.all_progress_list[pbar_idx] += now_size - last_size
            last_size = now_size

        try:
            await self.sftp.get(src, loc, progress_handler=update)
        except OSError:
            try:
                all_size = await self.sftp.getsize(src)
                self.msg.emit(pbar, self.all_progress_list[pbar_idx] + all_size - last_size)
            except asyncssh.SFTPError:
                self.msg.emit(pbar, self.all_progress_list[pbar_idx])
        except asyncssh.SFTPError:
            try:
                all_size = await self.sftp.getsize(src)
                self.msg.emit(pbar, self.all_progress_list[pbar_idx] + all_size - last_size)
            except asyncssh.SFTPError:
                self.msg(pbar, self.all_progress_list[pbar_idx])

    async def _download_init(self, task_core: list, src: str, loc: str, pbar: QProgressBar, pbar_idx: int) -> int:
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
                    asyncio.create_task(self._download_init(task_core, next_src, next_loc, pbar, pbar_idx)))
            else:
                total += entry.attrs.size
                task_core.append((entry.attrs.size, self._download_file(next_src, next_loc, pbar, pbar_idx)))
        for future in asyncio.as_completed(task_list):
            total += await future
        return total

    async def download(self, src: str, loc: str, co_num: int, pbar: QProgressBar) -> None:
        src, loc = path_stand(src, loc)
        self.all_progress_list.append(0)
        pbar_idx = len(self.all_progress_list) - 1
        if await self.sftp.isdir(src):
            task_core = []
            all_size = await self._download_init(task_core, src, loc, pbar, pbar_idx)
            pbar.setRange(0, all_size)
            task_core.sort(key=lambda item: item[0], reverse=True)
            task_core = [core for _, core in task_core]
            async with AioPool(co_num) as pool:
                for core in task_core:
                    await pool.spawn(core)
        else:
            all_size = await self.sftp.getsize(src)
            pbar.setRange(0, all_size)
            await self._download_file(src, loc, pbar, pbar_idx)
        pbar.setValue(all_size)

    async def _upload_file(self, src: str, loc: str, pbar: QProgressBar, pbar_idx: int) -> None:
        last_size = 0

        def update(_src: bytes, _loc: bytes, now_size: int, _all_size: int) -> None:
            nonlocal last_size
            self.msg.emit(pbar, self.all_progress_list[pbar_idx] + now_size - last_size)
            self.all_progress_list[pbar_idx] += now_size - last_size
            last_size = now_size

        try:
            await self.sftp.put(src, loc, progress_handler=update)
        except OSError:
            try:
                all_size = os.path.getsize(src)
                self.msg.emit(pbar, self.all_progress_list[pbar_idx] + all_size - last_size)
            except asyncssh.SFTPError:
                self.msg.emit(pbar, self.all_progress_list[pbar_idx])
        except asyncssh.SFTPError:
            try:
                all_size = os.path.getsize(src)
                self.msg.emit(pbar, self.all_progress_list[pbar_idx] + all_size - last_size)
            except asyncssh.SFTPError:
                self.msg(pbar, self.all_progress_list[pbar_idx])

    def _upload_init(self, task_list_mkdir: list, task_list_upload: list, src: str, loc: str,
                     pbar: QProgressBar, pbar_idx) -> int:
        total_size: int = 0
        task_list_mkdir.append(asyncio.create_task(self.sftp.mkdir(loc)))
        for entry in os.scandir(src):
            filename: str = entry.name
            next_src: str = "/".join((src, filename))
            next_loc: str = "/".join((loc, filename))
            if entry.is_dir():
                total_size += self._upload_init(task_list_mkdir, task_list_upload, next_src, next_loc, pbar, pbar_idx)
            else:
                task_list_upload.append((entry.stat().st_size, self._upload_file(next_src, next_loc, pbar, pbar_idx)))
                total_size += entry.stat().st_size
        return total_size

    async def upload(self, src: str, loc: str, co_num: int, pbar: QProgressBar) -> None:
        src, loc = path_stand(src, loc)
        self.all_progress_list.append(0)
        pbar_idx = len(self.all_progress_list) - 1
        if os.path.isdir(src):
            task_list_mkdir = []
            task_list_upload = []
            all_size = self._upload_init(task_list_mkdir, task_list_upload, src, loc, pbar, pbar_idx)
            pbar.setRange(0, all_size)
            for future in asyncio.as_completed(task_list_mkdir):
                try:
                    await future
                except asyncssh.SFTPError:
                    pass
            task_list_upload.sort(key=lambda x: x[0], reverse=True)
            task_list_upload = [core for _, core in task_list_upload]
            async with AioPool(co_num) as pool:
                for core in task_list_upload:
                    await pool.spawn(core)
        else:
            all_size = os.path.getsize(src)
            pbar.setRange(0, all_size)
            await self._upload_file(src, loc, pbar, pbar_idx)
        pbar.setValue(all_size)

    async def remove_dir(self, src: str):
        await self.ssh.run(f"rm -rf {src}")

    async def _run_command(self, com: str):
        result = await self.ssh.run(com)
        return result

    def run_command(self, com: str):
        return asyncio.run_coroutine_threadsafe(self._run_command(com), self.loop).result()

    def realpath(self, src: str):
        res = asyncio.run_coroutine_threadsafe(self.sftp.realpath(src.encode()), self.loop).result()
        return res.decode()


class RemoteFileDisplay(QWidget):
    def __init__(self, session: SFTPSession) -> None:
        super().__init__()
        self.session = session
        self.main_window_path = self.session.getcwd()
        self.back_button = QPushButton("返回")
        self.select_button = QPushButton("选择")
        self.no_button = QPushButton("取消")
        self.vbox = QVBoxLayout()
        self.setLayout(self.vbox)
        self.display_file_list = QListWidget()
        self.init_ui()
        self.select_item = None

    def closeEvent(self, event):
        self.session.change_dir(self.main_window_path)

    def init_ui(self):
        self.vbox.addWidget(self.back_button)
        self.vbox.addWidget(self.display_file_list)
        self.back_button.clicked.connect(lambda: self.double_item_clicked(QListWidgetItem("..")))
        self.display_file_list.itemDoubleClicked.connect(self.double_item_clicked)
        self.display_file_list.itemClicked.connect(self.item_clicked)
        self.display_dir(".")
        self.display_file_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.display_file_list.customContextMenuRequested.connect(self.show_context_menu)

    def show_context_menu(self, pos: QPoint):
        item = self.display_file_list.itemAt(pos)
        context_menu = QMenu(self)
        if item:
            edit_action = context_menu.addAction("打开")
            del_action = context_menu.addAction("删除")
            edit_action.triggered.connect(lambda: self.double_item_clicked(item))
            del_action.triggered.connect(lambda: self.del_item(item))
        else:
            reload_action = context_menu.addAction("刷新")
            makedir_action = context_menu.addAction("新建文件夹")
            new_file_action = context_menu.addAction("新文件")
            reload_action.triggered.connect(self.reload_dir)
            makedir_action.triggered.connect(self.makedir)
            new_file_action.triggered.connect(self.new_file)

        context_menu.exec(self.display_file_list.mapToGlobal(pos))

    def reload_dir(self):
        self.display_file_list.clear()
        self.display_dir()

    def item_clicked(self, item):
        self.select_item = item

    def double_item_clicked(self, item):
        if not self.session.is_file(item.text()):
            self.session.change_dir(item.text())
            self.display_file_list.clear()
            self.display_dir()
            return
        src = item.text()
        edit = Edit(src, self.session.read_file(src))
        edit.button.clicked.connect(lambda: self.session.save_file(src, edit.textEdit.toPlainText()))

    def del_item(self, item):
        if not self.session.is_file(item.text()):
            self.session.del_dir(item.text())
            self.reload_dir()
            return
        src = item.text()
        self.session.del_file(src)
        self.reload_dir()

    def makedir(self):
        text, ok = QInputDialog.getText(self, "新建", "输入文件夹名")
        if ok:
            self.session.make_dir(str(text))
            self.reload_dir()

    def new_file(self):
        text, ok = QInputDialog.getText(self, "新建", "输入文件名")
        if ok:
            self.session.save_file(str(text), "")
            self.reload_dir()

    def display_dir(self, src: str = "."):
        dir_item = []
        file_item = []
        info = self.session.read_dir(src)
        for entry in info:
            if entry.filename == '.' or entry.filename == '..':
                continue
            icon = QStyle.StandardPixmap.SP_FileIcon if entry.attrs.type != 2 else QStyle.StandardPixmap.SP_DirIcon
            item = QListWidgetItem(entry.filename)
            item.setIcon(QApplication.style().standardIcon(icon))
            dir_item.append(item) if entry.attrs.type == 2 else file_item.append(item)
        for item in dir_item:
            self.display_file_list.addItem(item)
        for item in file_item:
            self.display_file_list.addItem(item)

    def realpath(self, path: str):
        return self.session.realpath(path)


class GetTransportPathWidget(QWidget):
    def __init__(self, session) -> None:
        super().__init__()
        self.session = session
        self.ok_button = QPushButton("开始")
        self.no_button = QPushButton("退出")
        self.src_edit = QLineEdit()
        self.src_button = QPushButton("源文件")
        self.src_button_dir = QPushButton("源文件夹")
        self.dst_edit = QLineEdit()
        self.dst_button = QPushButton("目标地址")
        self.co_num_edit = QLineEdit()
        self.grid = QGridLayout()
        self.setLayout(self.grid)
        self.remote_file = RemoteFileDisplay(session)
        self.init_ui()

    def init_ui(self):
        self.grid.addWidget(self.src_edit, 0, 0)
        self.grid.addWidget(self.src_button, 0, 1)
        self.grid.addWidget(self.src_button_dir, 0, 2)
        self.grid.addWidget(self.dst_edit, 1, 0)
        self.grid.addWidget(self.dst_button, 1, 1)
        self.grid.addWidget(self.co_num_edit, 2, 0)
        self.grid.addWidget(QLabel("协程数量"), 2, 1)
        self.grid.addWidget(self.ok_button, 3, 0)
        self.grid.addWidget(self.no_button, 3, 1)


class GetDownloadPathWidget(GetTransportPathWidget):
    def __init__(self, session, main_window) -> None:
        super().__init__(session)
        self.main_window = main_window
        self.src_button_dir.setVisible(False)
        self.remote_file.vbox.addWidget(self.remote_file.select_button)
        self.remote_file.select_button.clicked.connect(
            lambda: self.src_edit.setText(self.remote_file.realpath(self.remote_file.select_item.text())))
        self.src_button.clicked.connect(self.get_src_file)
        self.dst_button.clicked.connect(self.get_local_file)
        self.no_button.clicked.connect(lambda: main_window.stacked_widget.setCurrentIndex(0))
        self.ok_button.clicked.connect(self.start_download)

    def start_download(self):
        self.main_window.download(self.src_edit.text(), self.dst_edit.text(), int(self.co_num_edit.text()))
        self.main_window.stacked_widget.setCurrentIndex(0)

    def get_src_file(self):
        self.remote_file.show()

    def get_local_file(self):
        file_path = QFileDialog.getExistingDirectory(self, "Open file")
        self.dst_edit.setText(file_path)


class GetUploadPathWidget(GetTransportPathWidget):
    def __init__(self, session, main_window) -> None:
        super().__init__(session)

        self.main_window = main_window
        self.remote_file.vbox.addWidget(self.remote_file.select_button)
        self.remote_file.select_button.clicked.connect(
            lambda: self.dst_edit.setText(self.remote_file.realpath(self.remote_file.select_item.text())))
        self.src_button.clicked.connect(self.get_src_file)
        self.dst_button.clicked.connect(self.get_local_file)
        self.no_button.clicked.connect(lambda: main_window.stacked_widget.setCurrentIndex(0))
        self.ok_button.clicked.connect(self.start_upload)
        self.src_button_dir.clicked.connect(self.get_src_dir)

    def start_upload(self):
        self.main_window.upload(self.src_edit.text(), self.dst_edit.text(), int(self.co_num_edit.text()))
        self.main_window.stacked_widget.setCurrentIndex(0)

    def get_local_file(self):
        self.remote_file.show()

    def get_src_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Open dir")
        if dir_path[0]:
            self.src_edit.setText(dir_path)

    def get_src_file(self):
        file_path = QFileDialog.getOpenFileName(self, "Open file")
        if file_path[0]:
            self.src_edit.setText(file_path)


class CommandDisplay(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.vbox = QVBoxLayout()
        self.edit = QTextEdit()
        self.edit.setReadOnly(True)
        self.clear_button = QPushButton("清理文字")
        self.clear_button.clicked.connect(lambda: self.edit.setText(""))
        self.setLayout(self.vbox)
        self.vbox.addWidget(self.clear_button)
        self.vbox.addWidget(self.edit)


class ControlWindow:
    def __init__(self, main_window):
        self.main_window = main_window
        self.display_hbox = QHBoxLayout()
        self.command_display = CommandDisplay()
        # self.command_display = MyTerminal(self.main_window.host, self.main_window.port, self.main_window.username,
        #                                   self.main_window.password)
        self.command_edit = QLineEdit()
        self.submit_button = QPushButton("提交命令")
        self.hbox_command = QHBoxLayout()
        self.transport_button = QPushButton("传输管理")
        self.back_main_window = QPushButton("返回主界面")
        self.hbox_transport = QHBoxLayout()
        self.download_button = QPushButton("下载")
        self.upload_button = QPushButton("上传")
        self.init_ui()

    def init_ui(self):
        self.command_edit.setFixedHeight(30)
        self.display_hbox.addWidget(self.command_display)
        self.display_hbox.addWidget(self.main_window.stacked_widget)
        self.main_window.vbox.addLayout(self.display_hbox)
        self.hbox_command.addWidget(self.command_edit)
        self.hbox_command.addWidget(self.submit_button)
        self.main_window.vbox.addLayout(self.hbox_command)
        self.main_window.vbox.addWidget(self.back_main_window)
        self.main_window.vbox.addWidget(self.transport_button)
        self.hbox_transport.addWidget(self.download_button)
        self.hbox_transport.addWidget(self.upload_button)
        self.main_window.vbox.addLayout(self.hbox_transport)
        self.back_main_window.clicked.connect(lambda: self.main_window.stacked_widget.setCurrentIndex(0))
        self.transport_button.clicked.connect(lambda: self.main_window.stacked_widget.setCurrentIndex(1))
        self.download_button.clicked.connect(lambda: self.main_window.stacked_widget.setCurrentIndex(2))
        self.upload_button.clicked.connect(lambda: self.main_window.stacked_widget.setCurrentIndex(3))
        self.submit_button.clicked.connect(self.run_command)

    def run_command(self):
        res = self.main_window.session.run_command(self.command_edit.text())
        self.command_display.edit.setPlainText(res.stdout + res.stderr)


class SFTPMainWindow(QWidget):
    def __init__(self, host: str, port: int, username: str, password: str):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.session = SFTPSession(host, port, username, password)
        self.session.msg.connect(self.update_progress)
        self.session.start()
        self.stacked_widget = QStackedWidget()
        self.display_pbar_list = QListWidget()
        self.remote_file_widget = RemoteFileDisplay(self.session)
        self.download_widget = GetDownloadPathWidget(self.session, self)
        self.upload_widget = GetUploadPathWidget(self.session, self)
        self.vbox = QVBoxLayout()
        self.setLayout(self.vbox)
        self.init_ui()
        ControlWindow(self)

    def init_ui(self):
        self.setWindowTitle("SFTP Session")
        # self.vbox.addWidget(self.stacked_widget)
        self.stacked_widget.addWidget(self.remote_file_widget)
        self.stacked_widget.addWidget(self.display_pbar_list)
        self.stacked_widget.addWidget(self.download_widget)
        self.stacked_widget.addWidget(self.upload_widget)

    def add_pbar(self, src) -> QProgressBar:
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
        return pbar

    def download(self, src: str, loc: str, co_num: int):
        pbar = self.add_pbar(src)
        threading.Thread(target=asyncio.run_coroutine_threadsafe,
                         args=(self.session.download(src, loc, co_num, pbar), self.session.loop)).start()

    def upload(self, src: str, loc: str, co_num: int):
        pbar = self.add_pbar(src)
        threading.Thread(target=asyncio.run_coroutine_threadsafe,
                         args=(self.session.upload(src, loc, co_num, pbar), self.session.loop)).start()

    @pyqtSlot(QProgressBar, int)
    def update_progress(self, pbar, value):
        pbar.setValue(value)


class LoginWindow(QWidget):
    def __init__(self, tab: QTabWidget, sftp_widget_list: list):
        super().__init__()
        self.sftp_widget_list = sftp_widget_list
        self.form = QFormLayout()
        self.tab = tab
        self.setWindowTitle("Login")
        self.host_edit = QLineEdit()
        self.port_edit = QLineEdit()
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.login_button = QPushButton("登陆")
        self.cancel_button = QPushButton("取消")
        self.sftp_main_window = SFTPMainWindow
        self.setLayout(self.form)
        self.init_ui()

    def init_ui(self):
        self.form.addRow(QLabel("服务器ip:"), self.host_edit)
        self.form.addRow(QLabel("端口号:"), self.port_edit)
        self.form.addRow(QLabel("用户名:"), self.username_edit)
        self.form.addRow(QLabel("密码:"), self.password_edit)
        self.password_edit.setEchoMode(self.password_edit.EchoMode.Password)
        self.form.addRow(self.login_button, self.cancel_button)
        self.login_button.clicked.connect(self.login)
        self.cancel_button.clicked.connect(self.close)

    def login(self):
        host = self.host_edit.text()
        port = int(self.port_edit.text())
        username = self.username_edit.text()
        password = self.password_edit.text()
        self.sftp_main_window = self.sftp_main_window(host, port, username, password)
        self.close()
        self.tab.addTab(self.sftp_main_window, "SFTP")
        self.sftp_widget_list.append(self.sftp_main_window)


class UserMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.tab = QTabWidget()
        self.setCentralWidget(self.tab)
        self.init_ui()
        self.login_windows = []
        self.sftp_widget: list[SFTPMainWindow] = []
        self.show()
        self.login()

    def init_ui(self):
        self.tab.setTabsClosable(True)
        self.tab.tabCloseRequested.connect(self.close_tab)
        menubar = self.menuBar()
        add_session_menu = menubar.addMenu("新建会话")
        new_action = QAction("new", self)
        new_action.triggered.connect(self.login)
        add_session_menu.addAction(new_action)

    def login(self):
        login_window = LoginWindow(self.tab, self.sftp_widget)
        login_window.show()
        self.login_windows.append(login_window)

    def close_tab(self, index):
        self.tab.removeTab(index)
        self.sftp_widget[index].close()


if __name__ == '__main__':
    app = QApplication(sys.argv)
    login_window = UserMainWindow()
    sys.exit(app.exec())
