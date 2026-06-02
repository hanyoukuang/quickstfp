# ui/views/sftp_tab_widget.py
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import QWidget, QSplitter, QHBoxLayout, QStackedWidget

from core.session import SSHSFTPInfo
from ui.views.user_widgets import ControlWidget, UserSFTPWidget, TerminalPanel
from ui.views.transport_widgets import TransportControlWidget


class SFTPTabWidget(QWidget):
    """
    单个会话标签页的总控容器
    """

    def __init__(self, host: str, port: int, username: str, password: str = None, client_keys: list = None,
                 passphrase: str = None, verify_host_key: bool = True):
        super().__init__()
        self.splitter = QSplitter(Qt.Orientation.Horizontal)

        self.info = SSHSFTPInfo(host, port, username, password, client_keys, passphrase, verify_host_key)
        self.info.start()
        self.info.wait_for_connection()

        self.control_widget = ControlWidget(self)
        self.transport_control_widget = TransportControlWidget(self)
        self.user_sftp_widget = UserSFTPWidget(self)
        self.terminal_panel = TerminalPanel(self.info)

        self.stacked_widget = QStackedWidget()
        self.hbox = QHBoxLayout(self)
        self.init_ui()

        self._health_timer = QTimer(self)
        self._health_timer.timeout.connect(self._check_health)
        self._health_timer.start(30000)
        self._health_status = True

    def _check_health(self):
        try:
            path = self.info.getcwd()
            if not self._health_status:
                self.window().tab_widget.setTabText(
                    self.window().tab_widget.indexOf(self),
                    self.window().tab_widget.tabText(self.window().tab_widget.indexOf(self)).replace("🔴", "🟢"))
                self._health_status = True
        except Exception:
            if self._health_status:
                idx = self.window().tab_widget.indexOf(self)
                name = self.window().tab_widget.tabText(idx).replace("🟢", "")
                self.window().tab_widget.setTabText(idx, f"🔴 {name}")
                self._health_status = False

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

        self._health_timer.stop()

        self.user_sftp_widget.remote_file_widget.external_watcher.cleanup_temp_files()
        self.info.close_session()

        # 退出 QThread
        self.info.quit()
        # 最多等待 3 秒给后台线程做清理收尾工作
        self.info.wait(3000)
