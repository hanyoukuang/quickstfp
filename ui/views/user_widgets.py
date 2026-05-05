# ui/views/user_widgets.py
from PySide6.QtCore import Qt, Slot
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QComboBox, \
    QSplitter, QListWidget, QLabel, QMessageBox

from ui.components.terminal_widget import SSHPtyWidget
from ui.views.local_widgets import LocalFileWidget
from ui.views.remote_file_widget import RemoteFileWidget
from ui.views.transport_widgets import TransferSetupWidget
from ui.views.snippets_widget import QuickSnippetsWidget


class ControlWidget(QListWidget):
    """
    左侧导航栏
    已彻底解耦，仅负责展示选项，不包含任何外部组件的调用逻辑
    """

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.addItems(["SSH伪终端", "SFTP文件目录", "传输管理"])
        # 默认选中第一项，使其与 QStackedWidget 默认的 0 索引对齐
        self.setCurrentRow(0)


class UserSFTPWidget(QWidget):
    def __init__(self, sftp_tab_widget):
        super().__init__()
        self.sftp_tab_widget = sftp_tab_widget
        self.info = sftp_tab_widget.info
        self.transfer_dialog = None

        # --- 左侧：全新的本地文件面板 ---
        self.local_file_widget = LocalFileWidget(self.sftp_tab_widget)

        # --- 右侧：原有的远端文件面板 ---
        self.remote_file_widget = RemoteFileWidget(sftp_tab_widget)
        self.back_button = QPushButton("返回上级")

        # 将 QLineEdit 改为可编辑的 QComboBox
        self.path_combo = QComboBox()
        self.path_combo.setEditable(True)  # 允许用户直接在框内输入路径

        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("🔍 搜索本目录 (回车)")
        self.search_edit.setClearButtonEnabled(True)  # 右侧自带清除 X 按钮
        self.search_edit.setFixedWidth(160)

        # 初始化当前路径
        current_path = self.info.realpath(".")
        self.path_combo.addItem(current_path)
        self.path_combo.setCurrentText(current_path)

        self.get_button = QPushButton("下载选定")
        self.put_button = QPushButton("高级上传")

        self.show_hidden_btn = QPushButton("👁️ 显示隐藏")
        self.show_hidden_btn.setCheckable(True)

        self.init_ui()
        self.remote_file_widget.refresh()

    def init_ui(self):
        self.remote_file_widget.set_menu()
        self.remote_file_widget.path_change_msg.connect(self.display_path)

        # 组装右侧（远端）的顶栏
        remote_hbox = QHBoxLayout()
        remote_hbox.addWidget(self.back_button)
        remote_hbox.addWidget(self.path_combo)
        remote_hbox.addWidget(self.search_edit)

        remote_hbox.addWidget(self.show_hidden_btn)

        remote_hbox.addWidget(self.get_button)
        remote_hbox.addWidget(self.put_button)

        remote_vbox = QVBoxLayout()
        remote_vbox.setContentsMargins(0, 0, 0, 0)
        remote_vbox.addLayout(remote_hbox)
        remote_vbox.addWidget(self.remote_file_widget)

        remote_container = QWidget()
        remote_container.setLayout(remote_vbox)

        # QSplitter 组装左右布局
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.addWidget(self.local_file_widget)
        self.splitter.addWidget(remote_container)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 1)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.splitter)
        self.setLayout(main_layout)

        # 信号绑定
        self.back_button.clicked.connect(self.back_parent_path)
        self.get_button.clicked.connect(self.get)
        self.put_button.clicked.connect(self.put)

        # 绑定 ComboBox 的激活信号（回车或点击下拉选项）
        self.path_combo.activated.connect(self.on_path_combo_activated)
        self.show_hidden_btn.toggled.connect(self.toggle_hidden_files)
        self.search_edit.returnPressed.connect(self.on_search)
        self.search_edit.textChanged.connect(self.on_search_text_changed)

    def on_search(self):
        """按下回车后触发"""
        keyword = self.search_edit.text().strip()
        if keyword:
            self.remote_file_widget.search(keyword)
        else:
            self.remote_file_widget.refresh()

    def on_search_text_changed(self, text):
        """用户点击清空按钮时，立即恢复当前目录的默认视图"""
        if not text.strip():
            self.remote_file_widget.refresh()

    def on_path_combo_activated(self):
        """当用户在输入框按回车，或在下拉列表中选择历史路径时触发"""
        path = self.path_combo.currentText().strip()
        if not path:
            return
        try:
            # 尝试切换底层目录
            self.info.chdir(path)
            # 获取进入后的绝对路径
            real_path = self.info.realpath(".")
            # 强制清空当前视图，触发底层全量扫描以获得极速刷新体验
            self.remote_file_widget.refresh()
            self.display_path(real_path)
        except Exception as e:
            QMessageBox.warning(self, "访问失败", f"无法进入该目录:\n{e}")
            # 失败后，恢复输入框为当前的实际合法路径
            self.display_path(self.info.getcwd())

    def toggle_hidden_files(self, checked: bool):
        self.remote_file_widget.show_hidden = checked
        self.remote_file_widget.refresh()

    def get(self):
        """打开下载参数配置面板"""
        if self.transfer_dialog is not None:
            self.transfer_dialog.close()
            self.transfer_dialog.deleteLater()

        self.transfer_dialog = TransferSetupWidget(self.sftp_tab_widget, mode="GET")
        self.transfer_dialog.show()

    def put(self):
        """打开上传参数配置面板"""
        if self.transfer_dialog is not None:
            self.transfer_dialog.close()
            self.transfer_dialog.deleteLater()

        self.transfer_dialog = TransferSetupWidget(self.sftp_tab_widget, mode="PUT")
        self.transfer_dialog.show()

    def back_parent_path(self):
        self.info.chdir("..")
        self.remote_file_widget.refresh()  # 返回上级时也强制刷新
        self.display_path(self.info.realpath("."))

    @Slot(str)
    def display_path(self, path: str):
        """当系统路径改变时，更新下拉框并沉淀历史记录"""
        self.path_combo.blockSignals(True)  # 暂时阻断信号，防止触发 activated 导致死循环

        # 如果路径不在历史记录里，则把它插入到最上面
        if self.path_combo.findText(path) == -1:
            self.path_combo.insertItem(0, path)

        self.path_combo.setCurrentText(path)
        self.path_combo.blockSignals(False)


class TerminalPanel(QWidget):
    """新的主容器：组合原有的 SSH 终端(左) 和 快捷命令面板(右)"""

    def __init__(self, info):
        super().__init__()
        self.info = info
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)

        # 1. 实例化原有终端组件
        self.ssh_pty_widget = SSHPtyWidget(self.info)

        # 2. 生成站点的唯一标识 (例如 root@192.168.1.10:22)
        site_id = f"{self.info.username}@{self.info.host}:{self.info.port}"

        # 3. 实例化新增的快捷面板 (传入站点标识)
        self.snippets_widget = QuickSnippetsWidget(site_id)

        # 4. 将命令写入到终端输入流
        self.snippets_widget.command_triggered.connect(self.ssh_pty_widget.bridge.on_input)

        self.splitter.addWidget(self.ssh_pty_widget)
        self.splitter.addWidget(self.snippets_widget)

        # 默认让终端占据比较大的空间
        self.splitter.setStretchFactor(0, 4)
        self.splitter.setStretchFactor(1, 1)

        layout.addWidget(self.splitter)



