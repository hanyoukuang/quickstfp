import logging
import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QApplication, QMainWindow, QTabWidget, QMessageBox

# 导入核心会话界面
from ui.views.sftp_tab_widget import SFTPTabWidget
# 导入我们上一步做好的站点管理器
from ui.views.site_manager import SiteManagerWidget


class MainWindow(QMainWindow):
    """
    全局主窗口，承载多标签页的 SFTP/SSH 会话
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("QuickSFTP - 多会话终端")
        self.resize(1100, 700)

        # 1. 初始化中心 TabWidget
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)  # 允许标签页关闭
        self.tab_widget.tabCloseRequested.connect(self.close_tab)  # 绑定关闭事件
        self.setCentralWidget(self.tab_widget)

        # 2. 顶部工具栏 (随时唤出站点管理器)
        toolbar = self.addToolBar("主控制栏")
        new_session_action = QAction("新建连接 / 站点管理", self)
        new_session_action.triggered.connect(self.open_site_manager)
        toolbar.addAction(new_session_action)

        # 3. 存放站点管理器的引用，防止被垃圾回收
        self.site_manager = None

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
