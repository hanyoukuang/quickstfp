import asyncio
import os
import sys

from PySide6.QtCore import Qt, QModelIndex, Signal, Slot
from PySide6.QtGui import QAction, QCloseEvent
from PySide6.QtWidgets import QListWidget, QStyle, QApplication, QListWidgetItem, QPushButton, \
    QMessageBox, QSplitter, QHBoxLayout, QStackedWidget, QMainWindow, QLineEdit, \
    QFormLayout, QLabel, QToolBar, QCheckBox, QComboBox, QTabWidget, QVBoxLayout, QWidget, QTextEdit, QFileDialog, \
    QAbstractItemView, QMenu, QInputDialog, QSlider
from asyncssh import SFTPName

from session import SSHSFTPInfo
from sql import UserInfo, UserControl
from terminal import SSHPtyWidget
from transport import ProgressBar, GET, PUT

BINARY_EXTENSIONS = (
    # 图像
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.webp', '.ico',
    '.psd', '.ai', '.svgz',

    # 视频 & 音频
    '.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm',
    '.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a', '.mid', '.midi',

    # 文档（带格式的）
    '.pdf',
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.odt', '.ods', '.odp',

    # 压缩 & 归档
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.tgz', '.cab',
    '.iso', '.img', '.dmg',

    # 可执行 & 库
    '.exe', '.dll', '.sys', '.so', '.o', '.obj', '.lib', '.a',
    '.app',  # macOS 应用包（实际是目录，但通常视为二进制）

    # 数据库
    '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb', '.dbf',

    # 字体
    '.ttf', '.otf', '.woff', '.woff2', '.eot',

    # 其他常见二进制
    '.bin', '.dat', '.class', '.pyc', '.pyo',
    '.jar', '.apk', '.ipa',
    '.swf', '.elf', '.rom',
)


def is_binary(filename: str) -> bool:
    """根据扩展名快速判断是否为常见二进制文件"""
    _, ext = os.path.splitext(filename.lower())
    return ext in BINARY_EXTENSIONS


class MonitorRemoteFileChange:
    def __init__(self, remote_file_widget: 'RemoteFileWidget'):
        super().__init__()
        self.remote_file_widget = remote_file_widget
        self.sftp = remote_file_widget.info.sftp
        self.loop = remote_file_widget.info.loop
        self.new_file_msg = remote_file_widget.new_file_msg
        self.sub_file_msg = remote_file_widget.sub_file_msg
        self.now_remote_path = "."

    async def check_file_new(self):
        new_files = []
        while True:
            new_files.clear()
            async for entry in self.sftp.scandir(self.now_remote_path):
                if entry.filename in (".", ".."):
                    continue
                if entry.filename not in self.remote_file_widget.all_files_dict:
                    new_files.append(entry)
            if new_files:
                self.new_file_msg.emit(new_files)
            await asyncio.sleep(1)

    async def check_file_old(self):
        sub_files = []
        while True:
            sub_files.clear()
            now_file_list = set([entry.filename async for entry in self.sftp.scandir(self.now_remote_path)])
            for file in self.remote_file_widget.all_files_dict:
                if file not in now_file_list:
                    sub_files.append(file)
            if sub_files:
                self.sub_file_msg.emit(sub_files)
            await asyncio.sleep(1)

    def start(self):
        asyncio.run_coroutine_threadsafe(self.check_file_new(), self.loop)
        asyncio.run_coroutine_threadsafe(self.check_file_old(), self.loop)


class Edit(QTextEdit):
    def __init__(self, remote_file_widget: 'RemoteFileWidget', path: str, text: str):
        super().__init__(parent=remote_file_widget)
        self.path = path
        self.info = remote_file_widget.info
        self.original_text = text
        self.setText(text)
        self.setWindowFlags(Qt.WindowType.Tool)

    def closeEvent(self, event: QCloseEvent):
        now_text = self.toPlainText()
        if now_text == self.original_text:
            return
        reply = QMessageBox.question(self, "文件", "文件有改动，是否保存",
                                     QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
        if reply == QMessageBox.StandardButton.Ok:
            self.info.save_file(self.path, now_text)


class FileSelect(QWidget):
    def __init__(self, user_select_target_widget: 'UserSelectTargetWidget'):
        super().__init__(parent=user_select_target_widget)


class RemoteFileWidget(QListWidget):
    new_file_msg = Signal(list)
    sub_file_msg = Signal(list)
    path_change_msg = Signal(str)

    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(parent=sftp_tab_widget)
        self.sftp_tab_widget = sftp_tab_widget
        self.FILE_ICON = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)
        self.DIR_ICON = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        self.move_paths = []
        self.copy_paths = []
        self.info = sftp_tab_widget.info
        self.all_files_dict = dict()
        self.monitor = MonitorRemoteFileChange(self)
        self.init_ui()

    def set_menu(self):
        self.setSelectionMode(QAbstractItemView.SelectionMode.MultiSelection)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    def show_context_menu(self, pos):
        item = self.itemAt(pos)
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
            edit_action.triggered.connect(lambda: self.double_item(pos))
            del_action.triggered.connect(self.del_items)
            move_action.triggered.connect(self.move_items)
            copy_action.triggered.connect(self.copy_items)
            download_action.triggered.connect(self.download_items)
        if self.move_paths:
            context_menu.addAction("放置").triggered.connect(self.put_items)
        if self.copy_paths:
            context_menu.addAction("粘贴").triggered.connect(self.paste_items)
        if len(self.selectedItems()) == 1:
            rename_action = context_menu.addAction("重命名")
            rename_action.triggered.connect(lambda: self.rename(item))
        context_menu.exec(self.mapToGlobal(pos))

    def refresh(self):
        self.clear()
        self.all_files_dict.clear()

    def rename(self, item: QListWidgetItem) -> None:
        text, ok = QInputDialog.getText(self, "重命名", "输入新的文件名")
        if ok:
            self.info.rename(item.text(), str(text))

    def paste_items(self) -> None:
        for old_path in self.copy_paths:
            self.info.copy_file(old_path, self.info.getcwd())
        self.copy_paths.clear()

    def put_items(self) -> None:
        for item, old_path in self.move_paths:
            try:
                self.info.move_file(old_path, self.info.getcwd())
                item.setHidden(False)
            except:
                pass
        self.move_paths.clear()

    def download_items(self) -> None:
        for item in self.selectedItems():
            self.download_item(item)

    def download_item(self, item: QListWidgetItem) -> None:
        os.makedirs("tmp", exist_ok=True)
        self.sftp_tab_widget.transport_control_widget.get(self.info.realpath(item.text()), "./tmp", 20)

    def del_items(self) -> None:
        text = ""
        for item in self.selectedItems():
            text += item.text() + "\n"
        reply = QMessageBox.question(self, "删除", f"确认删除:\n{text}\n",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            for item in self.selectedItems():
                self.del_item(item)

    def del_item(self, item: QListWidgetItem) -> None:
        src = self.info.realpath(item.text())
        self.info.del_file(src)

    def makedir(self) -> None:
        text, ok = QInputDialog.getText(self, "新建", "输入文件夹名")
        if ok:
            self.info.makedirs(str(text))

    def new_file(self) -> None:
        text, ok = QInputDialog.getText(self, "新建", "输入文件名")
        if ok:
            self.info.save_file(str(text), "")

    def init_ui(self):
        self.new_file_msg.connect(self.add_new_file)
        self.sub_file_msg.connect(self.del_sub_file)
        self.doubleClicked.connect(self.double_item)
        self.monitor.start()

    @Slot(list)
    def add_new_file(self, new_files: list[SFTPName]):
        for entry in new_files:
            filename = entry.filename
            if filename in self.all_files_dict:
                continue
            item = QListWidgetItem(filename)
            if entry.attrs.type == 2:
                item.setIcon(self.DIR_ICON)
                self.insertItem(0, item)
            else:
                item.setIcon(self.FILE_ICON)
                self.addItem(item)
            self.all_files_dict[filename] = item

    @Slot(list)
    def del_sub_file(self, sub_files: list[SFTPName]):
        for file in sub_files:
            if file not in self.all_files_dict:
                continue
            item = self.all_files_dict[file]
            row = self.row(item)
            self.takeItem(row)
            self.all_files_dict.pop(file)

    def double_item(self, index: QModelIndex):
        item = self.item(index.row())
        path = item.text()
        try:
            if self.info.is_file(path) and (not is_binary(path)):
                text = self.info.read_file(path)
                edit = Edit(self, self.info.realpath(path), text)
                edit.show()
            else:
                self.path_change_msg.emit(self.info.realpath(path))
                self.info.chdir(path)
        except:
            pass

    def move_items(self) -> None:
        for item in self.selectedItems():
            self.move_item(item)

    def move_item(self, item: QListWidgetItem) -> None:
        item.setHidden(True)
        self.move_paths.append((item, self.info.realpath(item.text())))

    def copy_items(self) -> None:
        for item in self.selectedItems():
            self.copy_item(item)

    def copy_item(self, item: QListWidgetItem) -> None:
        self.copy_paths.append(self.info.realpath(item.text()))


class TransportTargetWidget(RemoteFileWidget):
    abspath: str = ""

    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(sftp_tab_widget)
        self.chdir(self.info.getcwd())

    def double_item(self, index: QModelIndex):
        item = self.item(index.row())
        path = item.text()
        try:
            if not self.info.is_file(path):
                new_path = os.path.join(self.abspath, path).replace("\\", "/")
                self.chdir(new_path)
        except Exception:
            pass

    def chdir(self, path: str):
        self.path_change_msg.emit(path)
        self.abspath = path
        self.monitor.now_remote_path = path


class SelectRemoteFileWidget(QWidget):
    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(parent=sftp_tab_widget)
        self.transport_target_widget = TransportTargetWidget(sftp_tab_widget)
        self.vbox = QVBoxLayout()
        self.hbox = QHBoxLayout()
        self.back_button = QPushButton("<<")
        self.path_edit = QLineEdit(sftp_tab_widget.info.getcwd())
        self.select_button = QPushButton("选择")
        self.init_ui()

    def init_ui(self):
        self.hbox.addWidget(self.back_button)
        self.hbox.addWidget(self.path_edit)
        self.vbox.addLayout(self.hbox)
        self.vbox.addWidget(self.transport_target_widget)
        self.vbox.addWidget(self.select_button)
        self.setLayout(self.vbox)
        self.transport_target_widget.path_change_msg.connect(self.path_change)
        self.back_button.clicked.connect(self.back_parent_path)
        self.setWindowFlags(Qt.WindowType.Tool)

    @Slot(str)
    def path_change(self, path):
        self.path_edit.setText(path)

    def back_parent_path(self):
        path = self.get_parent_path(self.transport_target_widget.abspath)
        self.transport_target_widget.chdir(path)

    def select_target(self) -> str:
        items = self.transport_target_widget.selectedItems()
        if items:
            item = items[0]
            select_path = f"{self.transport_target_widget.abspath}/{item.text()}"
            return select_path
        path = self.transport_target_widget.abspath
        if path != '/':
            return path
        return ""

    @staticmethod
    def get_parent_path(path: str):
        new_path = os.path.dirname(path)
        return new_path.replace("\\", "/")


class UserSelectTargetWidget(QWidget):
    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(parent=sftp_tab_widget)
        self.sftp_tab_widget = sftp_tab_widget
        self.transport_control_widget = sftp_tab_widget.transport_control_widget
        self.form = QFormLayout()
        self.select_remote_file_widget = SelectRemoteFileWidget(sftp_tab_widget)
        self.src_edit = QLineEdit()
        self.dst_edit = QLineEdit()
        self.coro_num_label = QLabel("协程数量:20")
        self.coro_num_slider = QSlider(Qt.Orientation.Horizontal)
        self.src_button = QPushButton()
        self.src_dir_button = QPushButton()
        self.dst_button = QPushButton()
        self.transport_button = QPushButton("开始传输")
        self.init_ui()
        self.main()

    def init_ui(self):
        hbox = QHBoxLayout()
        hbox.addWidget(self.src_button)
        hbox.addWidget(self.src_dir_button)
        self.form.addRow(self.src_edit, hbox)
        self.form.addRow(self.dst_edit, self.dst_button)
        self.form.addRow(self.coro_num_label, self.coro_num_slider)
        self.form.addRow(self.transport_button, QLabel())
        self.setLayout(self.form)
        self.src_edit.setReadOnly(True)
        self.dst_edit.setReadOnly(True)
        self.coro_num_slider.setRange(1, 1000)
        self.coro_num_slider.setValue(20)
        self.coro_num_slider.valueChanged.connect(lambda value: self.coro_num_label.setText(f"协程数量{value}"))
        self.setWindowFlags(Qt.WindowType.Tool)

    def main(self):
        pass


class UserSelectGetTargetWidget(UserSelectTargetWidget):
    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(sftp_tab_widget)

    def main(self):
        self.src_dir_button.setHidden(True)
        self.src_button.setText("选择远端文件")
        self.dst_button.setText("选择本地存储位置")
        self.src_button.clicked.connect(lambda: self.select_remote_file_widget.show())
        self.select_remote_file_widget.select_button.clicked.connect(self.select_file)
        self.transport_button.clicked.connect(self.start_get)
        self.dst_button.clicked.connect(self.get_local_file)

    def select_file(self):
        self.src_edit.setText(self.select_remote_file_widget.select_target())
        self.select_remote_file_widget.close()

    def get_local_file(self):
        file_path = QFileDialog.getExistingDirectory(self, "Open file")
        if file_path:
            self.dst_edit.setText(file_path)

    def start_get(self):
        if self.src_edit.text() and self.dst_edit.text():
            self.transport_control_widget.get(self.src_edit.text(), self.dst_edit.text(),
                                              self.coro_num_slider.value())
        else:
            QMessageBox.warning(self, "参数警告", "请把参数填完整")


class UserSelectPutTargetWidget(UserSelectTargetWidget):
    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(sftp_tab_widget)

    def main(self):
        self.src_button.setText("选择本地文件")
        self.src_dir_button.setText("选择本地文件夹")
        self.src_button.clicked.connect(self.get_local_file)
        self.src_dir_button.clicked.connect(self.get_local_dir)
        self.dst_button.setText("选择远端存储的位置")
        self.dst_button.clicked.connect(lambda: self.select_remote_file_widget.show())
        self.select_remote_file_widget.select_button.clicked.connect(self.select_file)
        self.transport_button.clicked.connect(self.start_put)

    def select_file(self):
        self.dst_edit.setText(self.select_remote_file_widget.select_target())
        self.select_remote_file_widget.close()

    def get_local_file(self):
        file_path = QFileDialog.getOpenFileName(self, "Open file")
        if file_path:
            self.src_edit.setText(file_path[0])

    def get_local_dir(self):
        file_path = QFileDialog.getExistingDirectory(self, "Open directory")
        if file_path:
            self.src_edit.setText(file_path)

    def start_put(self):
        if self.src_edit.text() and self.dst_edit.text():
            self.transport_control_widget.put(self.src_edit.text(), self.dst_edit.text(),
                                              self.coro_num_slider.value())
        else:
            QMessageBox.warning(self, "参数警告", "请把参数填完整")


class UserSFTPWidget(QWidget):
    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__()
        self.sftp_tab_widget = sftp_tab_widget
        self.info = sftp_tab_widget.info
        self.remote_file_widget = RemoteFileWidget(sftp_tab_widget)
        self.back_button = QPushButton("<<")
        self.get_button = QPushButton("下载")
        self.path_edit = QLineEdit(sftp_tab_widget.info.realpath("."))
        self.put_button = QPushButton("上传")
        self.vbox = QVBoxLayout()
        self.hbox = QHBoxLayout()
        self.init_ui()

    def init_ui(self):
        self.remote_file_widget.set_menu()
        self.remote_file_widget.path_change_msg.connect(self.display_path)
        self.hbox.addWidget(self.back_button)
        self.hbox.addWidget(self.path_edit)
        self.hbox.addWidget(self.get_button)
        self.hbox.addWidget(self.put_button)
        self.vbox.addLayout(self.hbox)
        self.vbox.addWidget(self.remote_file_widget)
        self.setLayout(self.vbox)
        self.path_edit.setReadOnly(True)
        self.back_button.clicked.connect(self.back_parent_path)
        self.get_button.clicked.connect(self.get)
        self.put_button.clicked.connect(self.put)

    def get(self):
        get_target_widget = UserSelectGetTargetWidget(self.sftp_tab_widget)
        get_target_widget.show()

    def put(self):
        put_target_widget = UserSelectPutTargetWidget(self.sftp_tab_widget)
        put_target_widget.show()

    def back_parent_path(self):
        self.path_edit.setText(self.info.realpath(".."))
        self.info.chdir("..")

    @Slot(str)
    def display_path(self, path: str):
        self.path_edit.setText(path)


class ControlWidget(QListWidget):
    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(parent=sftp_tab_widget)
        self.addItems(["SSH伪终端", "SFTP文件目录", "传输管理"])
        self.clicked.connect(lambda index: self.function[self.item(index.row()).text()]())
        self.function = {
            "SSH伪终端": lambda: sftp_tab_widget.stacked_widget.setCurrentIndex(0),
            "SFTP文件目录": lambda: sftp_tab_widget.stacked_widget.setCurrentIndex(1),
            "传输管理": lambda: sftp_tab_widget.stacked_widget.setCurrentIndex(2),
        }


class TransportControlWidget(QListWidget):
    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(parent=sftp_tab_widget)
        self.FILE_ICON = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)
        self.DIR_ICON = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        self.info = sftp_tab_widget.info

    def get(self, src: str, dst: str, coro_num: int):
        icon = self.FILE_ICON if self.info.is_file(src) else self.DIR_ICON
        pbar = ProgressBar(src, "下载", icon)
        item = QListWidgetItem(self)
        item.setSizeHint(pbar.sizeHint())
        self.setItemWidget(item, pbar)
        self.addItem(item)
        pbar.del_widget_msg.connect(lambda: self.removeItemWidget(item))
        GET(src, dst, coro_num, self.info, pbar)()

    def put(self, src: str, dst: str, coro_num: int):
        icon = self.FILE_ICON if os.path.isfile(src) else self.DIR_ICON
        pbar = ProgressBar(src, "上传", icon)
        item = QListWidgetItem(self)
        item.setSizeHint(pbar.sizeHint())
        self.setItemWidget(item, pbar)
        self.addItem(item)
        pbar.del_widget_msg.connect(lambda: self.removeItemWidget(item))
        PUT(src, dst, coro_num, self.info, pbar)()


class SFTPTabWidget(QWidget):
    def __init__(self, host: str, port: int, username: str, password: str = None, client_keys: list = None,
                 passphrase: str = None):
        super().__init__()
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.info = SSHSFTPInfo(host, port, username, password, client_keys, passphrase)
        self.info.start()
        self.control_widget = ControlWidget(self)
        self.transport_control_widget = TransportControlWidget(self)
        self.user_sftp_widget = UserSFTPWidget(self)
        self.ssh_pty_widget = SSHPtyWidget(self.info)
        self.stacked_widget = QStackedWidget()
        self.hbox = QHBoxLayout(self)
        self.init_ui()

    def init_ui(self):
        self.stacked_widget.addWidget(self.ssh_pty_widget)
        self.stacked_widget.addWidget(self.user_sftp_widget)
        self.stacked_widget.addWidget(self.transport_control_widget)
        self.splitter.addWidget(self.control_widget)
        self.splitter.addWidget(self.stacked_widget)
        self.splitter.setStretchFactor(0, 0)
        self.splitter.setStretchFactor(1, 3)
        self.hbox.addWidget(self.splitter)
        self.setLayout(self.hbox)

    def closeEvent(self, event, /):
        super().closeEvent(event)
        self.info.sftp.exit()
        self.info.process.close()
        self.info.connection.close()
        self.info.loop.stop()
        self.info.quit()
        self.info.wait(3000)


class LoginWidget(QWidget):
    def __init__(self, sftp_main_window: 'SFTPMainWindow'):
        super().__init__(parent=sftp_main_window)
        self.userinfo = UserInfo()
        self.sftp_main_widget = sftp_main_window
        self.form_layout = QFormLayout()
        self.remember_userinfo_combox = QComboBox()
        self.host_edit = QLineEdit()
        self.port_edit = QLineEdit()
        self.username_edit = QLineEdit()
        self.key_path_edit = QLineEdit()
        self.select_path_button = QPushButton("选择私钥文件")
        self.password_edit = QLineEdit()
        self.display_or_hide_password_checkbox = QCheckBox("显示密码")
        self.login_button = QPushButton("登录")
        self.user_info_value = []
        self.init_ui()

    def init_ui(self):
        # self.setWindowFlags(Qt.WindowType.Tool)
        self.setLayout(self.form_layout)
        self.display_or_hide_password_checkbox.stateChanged.connect(self.checkbox_change)
        self.login_button.clicked.connect(self.get_sftp_window)

    def get_sftp_window(self):
        pass

    def checkbox_change(self, state):
        if state == Qt.CheckState.Unchecked.value:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        else:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Normal)


class PasswordLoginWidget(LoginWidget):
    def __init__(self, sftp_main_window: 'SFTPMainWindow'):
        super().__init__(sftp_main_window)
        self.init_password()

    def init_password(self):
        self.form_layout.addRow("记住的账户", self.remember_userinfo_combox)
        self.form_layout.addRow("IP地址", self.host_edit)
        self.form_layout.addRow("端口", self.port_edit)
        self.form_layout.addRow("用户名", self.username_edit)
        self.form_layout.addRow("密码", self.password_edit)
        self.form_layout.addRow("显示密码", self.display_or_hide_password_checkbox)
        self.form_layout.addRow("", self.login_button)
        self.remember_userinfo_combox.currentIndexChanged.connect(self.fill_remember_userinfo)
        self.user_info_value = self.userinfo.query_all_password()
        self.remember_userinfo_combox.addItems([f"{value[1]}:{value[2]}:{value[3]}" for value in self.user_info_value])
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.display_or_hide_password_checkbox.stateChanged.connect(self.checkbox_change)

    def fill_remember_userinfo(self, index: int):
        value = self.user_info_value[index]
        self.host_edit.setText(value[1])
        self.port_edit.setText(str(value[2]))
        self.username_edit.setText(value[3])
        self.password_edit.setText(value[4])

    def get_sftp_window(self):
        try:
            host = self.host_edit.text()
            port = int(self.port_edit.text())
            username = self.username_edit.text()
            password = self.password_edit.text()
        except:
            QMessageBox.warning(self, "输入警告", "请按照规范输入信息")
            return
        if host and port and username and password:
            try:
                sftp_tab_widget = SFTPTabWidget(host, port, username, password=password)
                self.sftp_main_widget.tab_widget.addTab(sftp_tab_widget, f"{host}:{port}")
                self.userinfo.insert_password(host, int(port), username, password)
            except:
                QMessageBox.warning(self, "连接警告", "请检查网路环境")
            else:
                self.sftp_main_widget.sftp_tab_widget_list.append(sftp_tab_widget)
        else:
            QMessageBox.warning(self, "输入警告", "参数不得为空")

    def checkbox_change(self, state):
        if state == Qt.CheckState.Unchecked.value:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        else:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Normal)


class KeyLoginWidget(LoginWidget):
    def __init__(self, sftp_main_window: 'SFTPMainWindow'):
        super().__init__(sftp_main_window)
        self.init_key()

    def init_key(self):
        hbox = QHBoxLayout()
        hbox.addWidget(self.key_path_edit)
        hbox.addWidget(self.select_path_button)
        self.form_layout.addRow("记住的账户", self.remember_userinfo_combox)
        self.form_layout.addRow("IP地址", self.host_edit)
        self.form_layout.addRow("端口", self.port_edit)
        self.form_layout.addRow("用户名", self.username_edit)
        self.form_layout.addRow("私钥地址", hbox)
        self.form_layout.addRow("密码", self.password_edit)
        self.form_layout.addRow("显示密码", self.display_or_hide_password_checkbox)
        self.form_layout.addRow("", self.login_button)
        self.setLayout(self.form_layout)
        self.select_path_button.clicked.connect(self.select_path)
        self.key_path_edit.setReadOnly(True)
        self.remember_userinfo_combox.currentIndexChanged.connect(self.fill_remember_userinfo)
        self.user_info_value = self.userinfo.query_all_key()
        self.remember_userinfo_combox.addItems([f"{value[1]}:{value[2]}:{value[3]}" for value in self.user_info_value])
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.display_or_hide_password_checkbox.stateChanged.connect(self.checkbox_change)

    def select_path(self):
        filename = QFileDialog.getOpenFileName(self, "选择私钥文件")
        if filename:
            self.key_path_edit.setText(filename[0])

    def fill_remember_userinfo(self, index: int):
        value = self.user_info_value[index]
        self.host_edit.setText(value[1])
        self.port_edit.setText(str(value[2]))
        self.username_edit.setText(value[3])
        self.key_path_edit.setText(value[4])
        self.password_edit.setText(value[5])

    def get_sftp_window(self):
        try:
            host = self.host_edit.text()
            port = int(self.port_edit.text())
            username = self.username_edit.text()
            key_path = self.key_path_edit.text()
            password = self.password_edit.text()
        except:
            QMessageBox.warning(self, "输入警告", "请按照规范输入信息")
            return
        if host and port and username and key_path:
            try:
                sftp_tab_widget = SFTPTabWidget(host, port, username, client_keys=[key_path], passphrase=password)
                self.sftp_main_widget.tab_widget.addTab(sftp_tab_widget, f"{host}:{port}")
                self.userinfo.insert_key(host, int(port), username, key_path, password)
            except:
                QMessageBox.warning(self, "连接警告", "请检查网路环境")
            else:
                self.sftp_main_widget.sftp_tab_widget_list.append(sftp_tab_widget)
        else:
            QMessageBox.warning(self, "输入警告", "参数不得为空")

    def checkbox_change(self, state):
        if state == Qt.CheckState.Unchecked.value:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        else:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Normal)


class LoginTabWidget(QWidget):
    def __init__(self, sftp_main_window: 'SFTPMainWindow'):
        super().__init__(parent=sftp_main_window)
        self.layout = QVBoxLayout()
        self.tab_widget = QTabWidget()
        self.setWindowFlags(Qt.WindowType.Tool)
        self.password_login_widget = PasswordLoginWidget(sftp_main_window)
        self.key_login_widget = KeyLoginWidget(sftp_main_window)
        self.tab_widget.addTab(self.password_login_widget, "用户名密码登录")
        self.tab_widget.addTab(self.key_login_widget, "秘钥登录")
        self.layout.addWidget(self.tab_widget)
        self.setLayout(self.layout)


class SFTPMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.resize(500, 500)
        self.tab_widget = QTabWidget(self)
        self.setCentralWidget(self.tab_widget)
        self.sftp_tab_widget_list: list[SFTPTabWidget] = []
        self.toolbar = QToolBar()
        self.init_ui()

    def init_ui(self):
        self.addToolBar(self.toolbar)
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_sftp_tab)
        create_new_sftp_action = QAction("新建会话", self)
        control_userinfo_action = QAction("用户管理", self)
        create_new_sftp_action.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogNewFolder))
        control_userinfo_action.setIcon(QApplication.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        create_new_sftp_action.triggered.connect(lambda: LoginTabWidget(self).show())
        control_userinfo_action.triggered.connect(lambda: UserControl(self).show())
        self.toolbar.addAction(create_new_sftp_action)
        self.toolbar.addAction(control_userinfo_action)

    def close_sftp_tab(self, index: int):
        self.tab_widget.removeTab(index)
        self.sftp_tab_widget_list[index].close()

    def closeEvent(self, event, /):
        super().closeEvent(event)
        for sftp_tab_widget in self.sftp_tab_widget_list:
            sftp_tab_widget.close()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = SFTPMainWindow()
    main_window.show()
    sys.exit(app.exec())
