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
    登录视图的基类，提取了共用的 UI、账户加载和输入校验逻辑
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

    def load_remembered_users(self, query_func):
        """抽取公共的账户下拉框加载逻辑"""
        self.user_info_value = query_func()
        self.remember_userinfo_combox.addItems([f"{val[1]}:{val[2]}:{val[3]}" for val in self.user_info_value])
        self.remember_userinfo_combox.currentIndexChanged.connect(self.fill_remember_userinfo)

        # 如果数据库中有数据，初始化时主动调用一次填充逻辑
        if self.user_info_value:
            self.fill_remember_userinfo(0)

    def get_base_login_params(self):
        """抽取公共的参数获取与校验逻辑"""
        try:
            host = self.host_edit.text().strip()
            port_text = self.port_edit.text().strip()
            username = self.username_edit.text().strip()
            password = self.password_edit.text()

            # 统一拦截非法输入
            if not port_text:
                raise ValueError("端口不能为空")
            port = int(port_text)

            if not host or not username:
                raise ValueError("必填项不能为空")

            return host, port, username, password
        except ValueError:
            QMessageBox.warning(self, "输入警告", "请按照规范输入信息(例如端口需为数字，必要参数不得为空)")
            return None

    def fill_remember_userinfo(self, index: int):
        """由子类根据各自的字段数量来实现具体的填充"""
        raise NotImplementedError

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

        # 一行代码完成历史数据加载
        self.load_remembered_users(self.userinfo_db.query_all_password)

    def fill_remember_userinfo(self, index: int):
        if 0 <= index < len(self.user_info_value):
            val = self.user_info_value[index]
            self.host_edit.setText(val[1])
            self.port_edit.setText(str(val[2]))
            self.username_edit.setText(val[3])
            self.password_edit.setText(val[4])

    def attempt_login(self):
        params = self.get_base_login_params()

        # 密码登录：要求 password (params[3]) 不能为空
        if params and params[3]:
            self.userinfo_db.insert_password(*params)
            self.session_requested.emit({
                "host": params[0], "port": params[1], "username": params[2], "password": params[3]
            })
        elif params and not params[3]:
            QMessageBox.warning(self, "输入警告", "密码参数不得为空")


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

        # 一行代码完成历史数据加载
        self.load_remembered_users(self.userinfo_db.query_all_key)

    def select_path(self):
        filename, _ = QFileDialog.getOpenFileName(self, "选择私钥文件")
        if filename:
            self.key_path_edit.setText(filename)

    def fill_remember_userinfo(self, index: int):
        if 0 <= index < len(self.user_info_value):
            val = self.user_info_value[index]
            self.host_edit.setText(val[1])
            self.port_edit.setText(str(val[2]))
            self.username_edit.setText(val[3])
            self.key_path_edit.setText(val[4])
            self.password_edit.setText(val[5])

    def attempt_login(self):
        params = self.get_base_login_params()
        key_path = self.key_path_edit.text()

        # 秘钥登录：要求私钥地址不能为空（passphrase 可以为空）
        if params and key_path:
            self.userinfo_db.insert_key(params[0], params[1], params[2], key_path, params[3])
            self.session_requested.emit({
                "host": params[0], "port": params[1], "username": params[2],
                "client_keys": [key_path], "passphrase": params[3]
            })
        elif params and not key_path:
            QMessageBox.warning(self, "输入警告", "私钥地址不得为空")


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
