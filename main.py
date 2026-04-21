# main.py
import sys

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QApplication, QMainWindow, QTabWidget, QToolBar, QStyle, QMessageBox

from ui.dialogs.user_manager import UserControl
# 导入拆分好的视图组件
from ui.views.login_view import LoginTabWidget
from ui.views.sftp_view import SFTPTabWidget


class SFTPMainWindow(QMainWindow):
    """
    主应用窗口
    负责管理顶层工具栏和会话标签页
    """

    def __init__(self):
        super().__init__()
        self.resize(800, 600)
        self.setWindowTitle("Quick SFTP Client")

        self.tab_widget = QTabWidget(self)
        self.setCentralWidget(self.tab_widget)
        self.sftp_tab_widget_list: list[SFTPTabWidget] = []

        self.toolbar = QToolBar()
        self.init_ui()

    def init_ui(self):
        self.addToolBar(self.toolbar)
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_sftp_tab)

        # 顶层动作
        create_new_sftp_action = QAction("新建会话", self)
        control_userinfo_action = QAction("用户管理", self)

        create_new_sftp_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_FileDialogNewFolder))
        control_userinfo_action.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))

        # 槽函数绑定：只打开独立的弹窗
        create_new_sftp_action.triggered.connect(self.show_login_dialog)
        control_userinfo_action.triggered.connect(self.show_user_manager_dialog)

        self.toolbar.addAction(create_new_sftp_action)
        self.toolbar.addAction(control_userinfo_action)

    def show_user_manager_dialog(self):
        """显示用户管理面板"""
        self.user_manager = UserControl()
        self.user_manager.show()

    def show_login_dialog(self):
        """显示登录面板并接收其会话请求信号"""
        self.login_dialog = LoginTabWidget()
        self.login_dialog.session_requested.connect(self.create_session_tab)
        self.login_dialog.show()

    def create_session_tab(self, session_params: dict):
        """
        接收来自登录面板的参数并建立新的会话标签
        """
        self.login_dialog.close()  # 登录成功后关闭弹窗
        host = session_params.get("host")
        port = session_params.get("port")

        try:
            # 实例化独立的会话视图
            sftp_tab_widget = SFTPTabWidget(**session_params)
            self.tab_widget.addTab(sftp_tab_widget, f"{host}:{port}")
            self.sftp_tab_widget_list.append(sftp_tab_widget)
            self.tab_widget.setCurrentWidget(sftp_tab_widget)
        except Exception as e:
            QMessageBox.warning(self, "连接警告", f"请检查网络环境或认证信息。\n错误信息: {e}")

    def close_sftp_tab(self, index: int):
        self.tab_widget.removeTab(index)
        widget = self.sftp_tab_widget_list.pop(index)
        widget.close()

    def closeEvent(self, event):
        super().closeEvent(event)
        for sftp_tab_widget in self.sftp_tab_widget_list:
            sftp_tab_widget.close()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    main_window = SFTPMainWindow()
    main_window.show()
    sys.exit(app.exec())
