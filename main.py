import logging
import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QApplication, QMainWindow, QTabWidget, QMessageBox

# 导入核心会话界面
from ui.views.sftp_tab_widget import SFTPTabWidget
from ui.views.site_manager import SiteManagerWidget
from ui.views.port_forward_dialog import PortForwardDialog


class MainWindow(QMainWindow):
    """
    全局主窗口，承载多标签页的 SFTP/SSH 会话
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("QuickSFTP - 多会话终端")
        screen = QApplication.primaryScreen().availableGeometry()
        self.resize(int(screen.width() * 0.7), int(screen.height() * 0.65))

        # 1. 初始化中心 TabWidget
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)  # 允许标签页关闭
        self.tab_widget.tabCloseRequested.connect(self.close_tab)  # 绑定关闭事件
        self.setCentralWidget(self.tab_widget)

        # 2. 顶部工具栏 (随时唤出站点管理器)
        toolbar = self.addToolBar("主控制栏")
        new_session_action = QAction("🔌 新建连接", self)
        new_session_action.triggered.connect(self.open_site_manager)
        toolbar.addAction(new_session_action)

        self.dark_mode_action = QAction("🌙 暗色模式", self)
        self.dark_mode_action.setCheckable(True)
        self.dark_mode_action.triggered.connect(self._toggle_dark_mode)
        toolbar.addAction(self.dark_mode_action)

        port_fwd_action = QAction("🔗 端口转发", self)
        port_fwd_action.triggered.connect(self._open_port_forward)
        toolbar.addAction(port_fwd_action)

        self._dark_mode = False
        self._apply_theme()

        self.site_manager = None
        self._port_fwd_dialog = None

    def _open_port_forward(self):
        current = self.tab_widget.currentWidget()
        if not current or not hasattr(current, 'info'):
            return
        if self._port_fwd_dialog is None:
            self._port_fwd_dialog = PortForwardDialog(self, session=current.info)
        else:
            self._port_fwd_dialog._session = current.info
        self._port_fwd_dialog.show()
        self._port_fwd_dialog.raise_()
        self._port_fwd_dialog.activateWindow()

    def _toggle_dark_mode(self, checked: bool):
        self._dark_mode = checked
        self.dark_mode_action.setText("☀️ 亮色模式" if checked else "🌙 暗色模式")
        self._apply_theme()

    def _apply_theme(self):
        if not self._dark_mode:
            self.setStyleSheet("")
            return
        self.setStyleSheet("""
            QMainWindow, QWidget { background-color: #2b2b2b; color: #e0e0e0; }
            QTabWidget::pane { background: #333; border: 1px solid #555; }
            QTabBar::tab { background: #3c3c3c; color: #ccc; padding: 5px 12px; }
            QTabBar::tab:selected { background: #555; color: #fff; }
            QToolBar { background: #333; border: none; }
            QLineEdit, QComboBox, QSpinBox { background: #3c3c3c; color: #fff; border: 1px solid #555; }
            QPushButton { background: #444; color: #fff; padding: 4px 10px; border-radius: 3px; }
            QPushButton:hover { background: #555; }
            QListWidget, QTreeView { background: #333; color: #e0e0e0; }
            QListWidget::item:selected, QTreeView::item:selected { background: #4a6da7; }
            QHeaderView::section { background: #3c3c3c; color: #ccc; border: 1px solid #555; }
            QProgressBar { background: #3c3c3c; border: 1px solid #555; text-align: center; }
            QProgressBar::chunk { background: #4a9; }
            QSplitter::handle { background: #555; }
            QMenu { background: #333; color: #e0e0e0; border: 1px solid #555; }
            QMenu::item:selected { background: #4a6da7; }
            QDialog { background: #2b2b2b; }
        """)

        # 启动时自动打开一次站点管理器

    def open_site_manager(self):
        """打开或激活站点管理器"""
        # 1. 如果窗口已经存在且可见，说明用户正在操作，直接将其前置激活
        if self.site_manager is not None and self.site_manager.isVisible():
            self.site_manager.activateWindow()
            return

        # 2. 如果窗口实例存在但不可见（被用户点X关闭了），则彻底清理旧实例
        if self.site_manager is not None:
            self.site_manager.deleteLater()
        self.site_manager = None

        self._port_fwd_dialog = None

        # 3. 每次都重新实例化一个全新的站点管理器，确保数据库连接是全新且活跃的
        self.site_manager = SiteManagerWidget()
        self.site_manager.setParent(self)
        self.site_manager.setWindowFlags(Qt.WindowType.Window)
        self.site_manager.session_requested.connect(self.create_new_session)

        self.site_manager.show()
        self.site_manager.activateWindow()

    def create_new_session(self, params: dict):
        """
        接收到连接参数，创建新的 SFTPTabWidget 实例并加入标签页
        """
        host = params.get("host")
        username = params.get("username")
        tab_name = f"{username}@{host}"

        try:
            # 实例化会话 (这会启动新的 core.session 和 event_loop)
            new_sftp_tab = SFTPTabWidget(**params)

            # 将其添加为一个新的 Tab
            index = self.tab_widget.addTab(new_sftp_tab, tab_name)
            self.tab_widget.setCurrentIndex(index)  # 自动跳转到新开的标签页

            # (可选) 连接成功后自动隐藏站点管理器
            self.site_manager.hide()

        except Exception as e:
            QMessageBox.critical(self, "连接失败", f"无法连接到 {tab_name}:\n{e}")

    def closeEvent(self, event):
        """
        拦截主窗口关闭事件。在程序退出前，依次安全关闭所有标签页，
        确保后台的 SSH QThread 被正确终止，避免 "Destroyed while thread is still running" 错误。
        """
        # 只要还有标签页打开，就一直关闭第0个标签页
        while self.tab_widget.count() > 0:
            self.close_tab(0)

        # 如果站点管理器还开着，也一并清理
        if self.site_manager is not None:
            self.site_manager.close()
            self.site_manager.deleteLater()

        # 资源清理完毕，允许主窗口正常关闭
        event.accept()

    # ==========================================================

    def close_tab(self, index: int):
        """
        关闭指定的标签页，并释放底层网络资源
        """
        # 1. 获取该标签页对应的 SFTPTabWidget 实例
        widget = self.tab_widget.widget(index)

        if widget:
            # 2. 手动调用其 close()，触发 sftp_view.py 中你写好的 closeEvent 销毁连接资源
            widget.close()

            # 3. 从 UI 容器中移除并彻底清理内存
            self.tab_widget.removeTab(index)
            widget.deleteLater()


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    app = QApplication(sys.argv)

    # 全局样式：让界面看起来更紧凑专业 (可选)
    app.setStyle("Fusion")

    main_window = MainWindow()
    main_window.show()
    main_window.open_site_manager()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
