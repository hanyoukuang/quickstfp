# ui/views/transport_widgets.py
import os

from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QLabel, \
    QListWidget, QListWidgetItem, QStyle, QApplication, QSlider, QSpinBox, QFormLayout, QFileDialog, \
    QMessageBox, QSlider

from core.transport import GET, PUT
from ui.components.progress_bar import ProgressBar
from ui.views.base_remote_tree import BaseRemoteTreeWidget


class TransportTargetWidget(BaseRemoteTreeWidget):
    """
    轻量级的远端目录选择器（用于传输配置弹窗）。
    仅允许查看目录和双击进入下级目录。严禁所有文件篡改操作。
    """
    abspath: str = ""

    def __init__(self, sftp_tab_widget):
        # 继承白板基础类
        super().__init__(sftp_tab_widget)

        # 只绑定纯净的"双击进入下级文件夹"功能
        self.doubleClicked.connect(self.double_item)

        # 初始化时加载当前工作目录
        self.chdir(self.info.getcwd())

    def double_item(self, index):
        """覆盖基类的行为，仅用于目录穿梭，不预览/编辑文件"""
        item = self.model.itemFromIndex(index)
        path = item.text()
        try:
            new_path = os.path.join(self.abspath, path).replace("\\", "/")
            self.chdir(new_path)
        except Exception as e:
            QMessageBox.warning(self, "访问失败", f"无法进入目标目录:\n{e}")

    def chdir(self, path: str):
        """进入目录并触发重绘"""
        self.path_change_msg.emit(path)
        self.abspath = path
        # 调用基类的刷新机制
        self.refresh()


class SelectRemoteFileWidget(QWidget):
    def __init__(self, sftp_tab_widget):
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


class TransferSetupWidget(QWidget):
    """
    统一的传输参数配置面板（替代原有的冗余继承关系）
    """

    def __init__(self, sftp_tab_widget, mode: str = "GET"):
        super().__init__(parent=sftp_tab_widget)
        self.sftp_tab_widget = sftp_tab_widget
        self.transport_control_widget = sftp_tab_widget.transport_control_widget
        self.mode = mode.upper()  # 'GET' or 'PUT'

        self.select_remote_file_widget = SelectRemoteFileWidget(sftp_tab_widget)

        self.src_edit = QLineEdit()
        self.src_edit.setReadOnly(True)
        self.dst_edit = QLineEdit()
        self.dst_edit.setReadOnly(True)

        self.coro_num_label = QLabel("协程数量:20")
        self.coro_num_slider = QSlider(Qt.Orientation.Horizontal)
        self.coro_num_slider.setRange(1, 1000)
        self.coro_num_slider.setValue(20)
        self.coro_num_slider.valueChanged.connect(lambda v: self.coro_num_label.setText(f"协程数量:{v}"))

        self.speed_limit_spin = QSpinBox()
        self.speed_limit_spin.setRange(0, 999999)
        self.speed_limit_spin.setSuffix(" KB/s (0为不限速)")

        self.src_btn = QPushButton()
        self.src_dir_btn = QPushButton("选择本地文件夹")
        self.dst_btn = QPushButton()
        self.transport_btn = QPushButton("开始传输")

        self.init_ui()
        self.setup_mode()

    def init_ui(self):
        form = QFormLayout(self)
        hbox = QHBoxLayout()
        hbox.addWidget(self.src_btn)
        hbox.addWidget(self.src_dir_btn)

        form.addRow(self.src_edit, hbox)
        form.addRow(self.dst_edit, self.dst_btn)
        form.addRow(self.coro_num_label, self.coro_num_slider)
        form.addRow(QLabel("传输限速:"), self.speed_limit_spin)
        form.addRow(self.transport_btn, QLabel())

        self.setWindowFlags(Qt.WindowType.Tool)

        # 绑定通用的远端选择面板回调
        self.select_remote_file_widget.select_button.clicked.connect(self.on_remote_selected)
        self.transport_btn.clicked.connect(self.start_transport)

    def setup_mode(self):
        """根据是上传还是下载，动态配置按钮文字和事件"""
        if self.mode == "GET":
            self.src_dir_btn.setHidden(True)
            self.src_btn.setText("选择远端文件")
            self.dst_btn.setText("选择本地存储位置")

            self.src_btn.clicked.connect(self.select_remote_file_widget.show)
            self.dst_btn.clicked.connect(self.get_local_dir)
        else:
            self.src_btn.setText("选择本地文件")
            self.dst_btn.setText("选择远端存储的位置")

            self.src_btn.clicked.connect(self.get_local_file)
            self.src_dir_btn.clicked.connect(self.get_local_dir_for_src)
            self.dst_btn.clicked.connect(self.select_remote_file_widget.show)

    def on_remote_selected(self):
        target = self.select_remote_file_widget.select_target()
        if self.mode == "GET":
            self.src_edit.setText(target)
        else:
            self.dst_edit.setText(target)
        self.select_remote_file_widget.close()

    def get_local_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if path: self.src_edit.setText(path)

    def get_local_dir(self):
        path = QFileDialog.getExistingDirectory(self, "选择文件夹")
        if path: self.dst_edit.setText(path)

    def get_local_dir_for_src(self):
        path = QFileDialog.getExistingDirectory(self, "选择文件夹")
        if path: self.src_edit.setText(path)

    def start_transport(self):
        src, dst = self.src_edit.text(), self.dst_edit.text()
        if not src or not dst:
            QMessageBox.warning(self, "参数警告", "请把源路径和目标路径填完整")
            return

        coro, speed = self.coro_num_slider.value(), self.speed_limit_spin.value()
        if self.mode == "GET":
            self.transport_control_widget.get(src, dst, coro, speed)
        else:
            self.transport_control_widget.put(src, dst, coro, speed)
            self.sftp_tab_widget.user_sftp_widget.remote_file_widget.refresh()

        self.close()


class TransportControlWidget(QListWidget):
    """
    传输任务管理面板
    负责调度 core.transport 任务，并生成 UI 进度条组件进行显示。
    完全解耦：使用 Signal / Slot 机制与后端业务分离。
    """

    def __init__(self, sftp_tab_widget):
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
        task.speed_updated.connect(pbar.set_speed_text)

        # 绑定 UI 操作 -> 核心层
        pbar.cancel_requested.connect(task.cancel)
        pbar.del_widget_msg.connect(lambda: self.takeItem(self.row(item)))

        # --- 新增：绑定 UI 的暂停信号到 Core 的控制阀门 ---
        pbar.pause_requested.connect(task.toggle_pause)

    def get(self, src: str, dst: str, coro_num: int, speed_limit: int = 0):
        self.clear_finish_task()
        icon = self.FILE_ICON if self.info.is_file(src) else self.DIR_ICON
        pbar = ProgressBar(src, "下载", icon)

        # 把 speed_limit 传给底层
        task = GET(src, dst, coro_num, speed_limit, self.info)
        self._create_task_ui(pbar, task)
        self.task_list.append(task)
        task()

    def put(self, src: str, dst: str, coro_num: int, speed_limit: int = 0):
        self.clear_finish_task()
        icon = self.FILE_ICON if os.path.isfile(src) else self.DIR_ICON
        pbar = ProgressBar(src, "上传", icon)

        task = PUT(src, dst, coro_num, speed_limit, self.info)
        self._create_task_ui(pbar, task)
        self.task_list.append(task)
        task()
