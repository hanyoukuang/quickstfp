# ui/views/sftp_tab_widget.py
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QWidget, QSplitter, QHBoxLayout, QStackedWidget

from core.session import SSHSFTPInfo
from ui.views.user_widgets import ControlWidget, UserSFTPWidget, TerminalPanel
from ui.views.transport_widgets import TransportControlWidget


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
        self.info.wait_for_connection()

        # 包含各项功能面板
        self.control_widget = ControlWidget(self)
        self.transport_control_widget = TransportControlWidget(self)
        self.user_sftp_widget = UserSFTPWidget(self)
        self.terminal_panel = TerminalPanel(self.info)

        self.stacked_widget = QStackedWidget()
        self.hbox = QHBoxLayout(self)
        self.init_ui()

    def init_ui(self):
        # 组装面板
        self.stacked_widget.addWidget(self.terminal_panel)
        self.stacked_widget.addWidget(self.user_sftp_widget)
        self.stacked_widget.addWidget(self.transport_control_widget)

        self.splitter.addWidget(self.control_widget)
        self.splitter.addWidget(self.stacked_widget)
        self.splitter.setStretchFactor(0, 0)
        self.splitter.setStretchFactor(1, 3)
        self.hbox.addWidget(self.splitter)
        self.setLayout(self.hbox)
        self.control_widget.currentRowChanged.connect(self.stacked_widget.setCurrentIndex)

    def closeEvent(self, event, /):
        super().closeEvent(event)

        # 使用新增加的优雅退出方法清理所有连接和挂起的 Task
        self.user_sftp_widget.remote_file_widget.external_watcher.cleanup_temp_files()
        self.info.close_session()

        # 退出 QThread
        self.info.quit()
        # 最多等待 3 秒给后台线程做清理收尾工作
        self.info.wait(3000)
