# ui/views/login_view.py
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget, QFormLayout, QLineEdit, QPushButton,
    QCheckBox, QComboBox, QTabWidget, QVBoxLayout, QHBoxLayout,
    QFileDialog, QMessageBox
)

from database.user_model import UserInfoDB


class BaseLoginWidget(QWidget):
    """
    登录视图的基类，提取了共用的 UI 和逻辑
    """
    # 将需要的连接参数打包为字典发射出去
    session_requested = Signal(dict)

    def __init__(self):
        super().__init__()
        self.userinfo_db = UserInfoDB()
        self.form_layout = QFormLayout()

        # 共用控件
        self.remember_userinfo_combox = QComboBox()
        self.host_edit = QLineEdit()
        self.port_edit = QLineEdit()
        self.username_edit = QLineEdit()
        self.password_edit = QLineEdit()
        self.display_or_hide_password_checkbox = QCheckBox("显示密码")
        self.login_button = QPushButton("登录")

        self.user_info_value = []

        # 基础设置
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.setLayout(self.form_layout)

        # 信号连接
        self.display_or_hide_password_checkbox.stateChanged.connect(self.checkbox_change)
        self.login_button.clicked.connect(self.attempt_login)

    def checkbox_change(self, state):
        if state == Qt.CheckState.Unchecked.value:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        else:
            self.password_edit.setEchoMode(QLineEdit.EchoMode.Normal)

    def attempt_login(self):
        """子类需实现具体的登录参数收集逻辑"""
        raise NotImplementedError


class PasswordLoginWidget(BaseLoginWidget):
    """密码登录面板"""

    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.form_layout.addRow("记住的账户", self.remember_userinfo_combox)
        self.form_layout.addRow("IP地址", self.host_edit)
        self.form_layout.addRow("端口", self.port_edit)
        self.form_layout.addRow("用户名", self.username_edit)
        self.form_layout.addRow("密码", self.password_edit)
        self.form_layout.addRow("显示密码", self.display_or_hide_password_checkbox)
        self.form_layout.addRow("", self.login_button)

        self.user_info_value = self.userinfo_db.query_all_password()
        self.remember_userinfo_combox.addItems([f"{val[1]}:{val[2]}:{val[3]}" for val in self.user_info_value])
        self.remember_userinfo_combox.currentIndexChanged.connect(self.fill_remember_userinfo)

        # 【修复点】：如果数据库中有数据，初始化时主动调用一次填充逻辑
        if self.user_info_value:
            self.fill_remember_userinfo(0)

    def fill_remember_userinfo(self, index: int):
        # 增加越界保护
        if index < 0 or index >= len(self.user_info_value):
            return
        val = self.user_info_value[index]
        self.host_edit.setText(val[1])
        self.port_edit.setText(str(val[2]))
        self.username_edit.setText(val[3])
        self.password_edit.setText(val[4])

    def attempt_login(self):
        try:
            host = self.host_edit.text()
            port = int(self.port_edit.text())
            username = self.username_edit.text()
            password = self.password_edit.text()
        except ValueError:
            QMessageBox.warning(self, "输入警告", "请按照规范输入信息(例如端口需为数字)")
            return

        if host and port and username and password:
            self.userinfo_db.insert_password(host, port, username, password)
            self.session_requested.emit({
                "host": host, "port": port, "username": username, "password": password
            })
        else:
            QMessageBox.warning(self, "输入警告", "参数不得为空")


class KeyLoginWidget(BaseLoginWidget):
    """秘钥登录面板"""

    def __init__(self):
        super().__init__()
        self.key_path_edit = QLineEdit()
        self.select_path_button = QPushButton("选择私钥文件")
        self.init_ui()

    def init_ui(self):
        hbox = QHBoxLayout()
        hbox.addWidget(self.key_path_edit)
        hbox.addWidget(self.select_path_button)
        self.key_path_edit.setReadOnly(True)
        self.select_path_button.clicked.connect(self.select_path)

        self.form_layout.addRow("记住的账户", self.remember_userinfo_combox)
        self.form_layout.addRow("IP地址", self.host_edit)
        self.form_layout.addRow("端口", self.port_edit)
        self.form_layout.addRow("用户名", self.username_edit)
        self.form_layout.addRow("私钥地址", hbox)
        self.form_layout.addRow("密码(Passphrase)", self.password_edit)
        self.form_layout.addRow("显示密码", self.display_or_hide_password_checkbox)
        self.form_layout.addRow("", self.login_button)

        self.user_info_value = self.userinfo_db.query_all_key()
        self.remember_userinfo_combox.addItems([f"{val[1]}:{val[2]}:{val[3]}" for val in self.user_info_value])
        self.remember_userinfo_combox.currentIndexChanged.connect(self.fill_remember_userinfo)

        # 【修复点】：如果数据库中有数据，初始化时主动调用一次填充逻辑
        if self.user_info_value:
            self.fill_remember_userinfo(0)

    def select_path(self):
        filename, _ = QFileDialog.getOpenFileName(self, "选择私钥文件")
        if filename:
            self.key_path_edit.setText(filename)

    def fill_remember_userinfo(self, index: int):
        # 增加越界保护
        if index < 0 or index >= len(self.user_info_value):
            return
        val = self.user_info_value[index]
        self.host_edit.setText(val[1])
        self.port_edit.setText(str(val[2]))
        self.username_edit.setText(val[3])
        self.key_path_edit.setText(val[4])
        self.password_edit.setText(val[5])

    def attempt_login(self):
        try:
            host = self.host_edit.text()
            port = int(self.port_edit.text())
            username = self.username_edit.text()
            key_path = self.key_path_edit.text()
            password = self.password_edit.text()
        except ValueError:
            QMessageBox.warning(self, "输入警告", "请按照规范输入信息")
            return

        if host and port and username and key_path:
            self.userinfo_db.insert_key(host, port, username, key_path, password)
            self.session_requested.emit({
                "host": host, "port": port, "username": username,
                "client_keys": [key_path], "passphrase": password
            })
        else:
            QMessageBox.warning(self, "输入警告", "参数不得为空")


class LoginTabWidget(QWidget):
    """包含密码和秘钥两种登录方式的窗口"""
    session_requested = Signal(dict)

    def __init__(self):
        super().__init__()
        self.setWindowFlags(Qt.WindowType.Tool)
        self.setWindowTitle("新建会话")

        self.layout = QVBoxLayout(self)
        self.tab_widget = QTabWidget()

        self.password_login_widget = PasswordLoginWidget()
        self.key_login_widget = KeyLoginWidget()

        # 将子组件的请求直接转发出去
        self.password_login_widget.session_requested.connect(self.session_requested.emit)
        self.key_login_widget.session_requested.connect(self.session_requested.emit)

        self.tab_widget.addTab(self.password_login_widget, "用户名密码登录")
        self.tab_widget.addTab(self.key_login_widget, "秘钥登录")

        self.layout.addWidget(self.tab_widget)
