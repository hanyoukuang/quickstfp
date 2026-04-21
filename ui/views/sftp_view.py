# ui/views/sftp_view.py
import asyncio
import os

from PySide6.QtCore import Qt, QModelIndex, Signal, Slot
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QListWidget, QStyle, QApplication, QListWidgetItem, QPushButton,
    QMessageBox, QSplitter, QHBoxLayout, QStackedWidget, QLineEdit,
    QFormLayout, QLabel, QVBoxLayout, QWidget, QTextEdit, QFileDialog,
    QAbstractItemView, QMenu, QInputDialog, QSlider
)
from asyncssh import SFTPName

from core.session import SSHSFTPInfo
from core.transport import GET, PUT
from ui.components.progress_bar import ProgressBar
from ui.components.terminal_widget import SSHPtyWidget
from utils.file_utils import is_binary


class MonitorRemoteFileChange:
    def __init__(self, remote_file_widget: 'RemoteFileWidget'):
        super().__init__()
        self.remote_file_widget = remote_file_widget
        self.sftp = remote_file_widget.info.sftp
        self.loop = remote_file_widget.info.loop
        self.new_file_msg = remote_file_widget.new_file_msg
        self.sub_file_msg = remote_file_widget.sub_file_msg
        self.now_remote_path = "."

        # 新增：用于记录上一次扫描时目录的修改时间
        self.last_mtime = None

    async def check_file_changes(self):
        """合并新文件和旧文件的检查，并使用 stat 优化网络 I/O"""
        while True:
            try:
                # 1. 轻量级检查：只获取当前目录本身的元数据
                dir_attrs = await self.sftp.stat(self.now_remote_path)
                current_mtime = dir_attrs.mtime

                # 如果目录修改时间没变，说明没有文件增删，直接跳过本次完整扫描
                if self.last_mtime == current_mtime:
                    await asyncio.sleep(1)
                    continue

                self.last_mtime = current_mtime

                # 2. 只有时间变化时，才发起高成本的 scandir
                now_file_entries = []
                async for entry in self.sftp.scandir(self.now_remote_path):
                    if entry.filename not in (".", ".."):
                        now_file_entries.append(entry)

                now_filenames = {entry.filename for entry in now_file_entries}
                known_filenames = set(self.remote_file_widget.all_files_dict.keys())

                # 3. 集合运算：计算新增的文件
                new_files = [e for e in now_file_entries if e.filename not in known_filenames]
                if new_files:
                    self.new_file_msg.emit(new_files)

                # 4. 集合运算：计算被删除的文件
                sub_files = list(known_filenames - now_filenames)
                if sub_files:
                    self.sub_file_msg.emit(sub_files)

            except Exception:
                # 捕获异常：防止在切换目录 (chdir) 瞬间导致路径不存在而抛出异常崩溃
                self.last_mtime = None

            # 建议将此处稍微提高至 1.5 - 2 秒，肉眼感知的实时性差异不大，但能大幅降低压力
            await asyncio.sleep(1)

    def start(self):
        # 原本启动两个独立的任务，现在只需要启动合并后的单任务
        asyncio.run_coroutine_threadsafe(self.check_file_changes(), self.loop)


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
            self.dst_edit.setText(file_path)

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
    """
    传输任务管理面板
    负责调度 core.transport 任务，并生成 UI 进度条组件进行显示。
    完全解耦：使用 Signal / Slot 机制与后端业务分离。
    """

    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(parent=sftp_tab_widget)
        self.FILE_ICON = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)
        self.DIR_ICON = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        self.info = sftp_tab_widget.info
        self.task_list = []

    def clear_finish_task(self):
        self.task_list = [t for t in self.task_list if not t.is_cancel]

    def _create_task_ui(self, pbar: ProgressBar, task):
        """通用方法：绑定任务的信号与 UI"""
        item = QListWidgetItem(self)
        item.setSizeHint(pbar.sizeHint())
        self.setItemWidget(item, pbar)
        self.addItem(item)

        # 绑定核心层信号 -> UI 组件
        task.progress_updated.connect(pbar.set_progress_value)
        task.range_initialized.connect(pbar.set_progress_range)
        task.transport_failed.connect(pbar.warning_transport_fail_filename)

        # 绑定 UI 的取消操作 -> 核心层
        pbar.cancel_requested.connect(task.cancel)
        pbar.del_widget_msg.connect(lambda: self.takeItem(self.row(item)))

    def get(self, src: str, dst: str, coro_num: int):
        self.clear_finish_task()
        icon = self.FILE_ICON if self.info.is_file(src) else self.DIR_ICON
        pbar = ProgressBar(src, "下载", icon)

        # 创建纯逻辑传输对象，不再强塞 UI 对象
        task = GET(src, dst, coro_num, self.info)
        self._create_task_ui(pbar, task)
        self.task_list.append(task)
        task()  # 启动任务

    def put(self, src: str, dst: str, coro_num: int):
        self.clear_finish_task()
        icon = self.FILE_ICON if os.path.isfile(src) else self.DIR_ICON
        pbar = ProgressBar(src, "上传", icon)

        # 创建纯逻辑传输对象
        task = PUT(src, dst, coro_num, self.info)
        self._create_task_ui(pbar, task)
        self.task_list.append(task)
        task()  # 启动任务


class SFTPTabWidget(QWidget):
    """
    单个会话标签页的总控容器
    """

    def __init__(self, host: str, port: int, username: str, password: str = None, client_keys: list = None,
                 passphrase: str = None):
        super().__init__()
        self.splitter = QSplitter(Qt.Orientation.Horizontal)

        # 启动核心 Session
        self.info = SSHSFTPInfo(host, port, username, password, client_keys, passphrase)
        self.info.start()

        # 包含各项功能面板
        self.control_widget = ControlWidget(self)
        self.transport_control_widget = TransportControlWidget(self)
        self.user_sftp_widget = UserSFTPWidget(self)
        self.ssh_pty_widget = SSHPtyWidget(self.info)

        self.stacked_widget = QStackedWidget()
        self.hbox = QHBoxLayout(self)
        self.init_ui()

    def init_ui(self):
        # 组装面板
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
