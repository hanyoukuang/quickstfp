# ui/dialogs/user_manager.py
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QListWidget, QListWidgetItem, QPushButton,
    QWidget, QLabel, QHBoxLayout, QMessageBox
)

# 引入独立的数据访问层
from database.user_model import UserInfoDB


class UserItem(QListWidgetItem):
    """自定义列表项，用于存储对应数据库记录的 ID"""

    def __init__(self, idx: int):
        super().__init__()
        self.sql_idx = idx


class UserControl(QListWidget):
    """
    用户管理弹窗面板。
    负责展示已保存的登录信息，并提供删除功能。
    """

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self.setWindowFlags(Qt.WindowType.Tool)
        self.setWindowTitle("用户管理")
        self.resize(400, 300)

        self.userinfo_db = UserInfoDB()
        self.add_all_user()

    def create_widget(self, idx: int, text: str) -> tuple[UserItem, QPushButton]:
        """创建列表项的通用 UI 结构"""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(5, 2, 5, 2)

        label = QLabel(text)
        button = QPushButton("删除")

        layout.addWidget(label)
        layout.addWidget(button)

        item = UserItem(idx)
        self.addItem(item)
        item.setSizeHint(widget.sizeHint())
        self.setItemWidget(item, widget)

        return item, button

    def create_user_item_password(self, idx: int, text: str):
        """创建密码类型记录的 UI 项并绑定删除逻辑"""
        item, button = self.create_widget(idx, text)

        def delete():
            query = QMessageBox.question(
                self, "询问", "是否删除该密码登录信息？",
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if query == QMessageBox.StandardButton.Ok:
                # 1. 删除 UI 元素
                self.takeItem(self.row(item))
                # 2. 删除数据库记录
                self.userinfo_db.del_idx_password(item.sql_idx)

        button.clicked.connect(delete)

    def create_user_item_key(self, idx: int, text: str):
        """创建秘钥类型记录的 UI 项并绑定删除逻辑"""
        item, button = self.create_widget(idx, text)

        def delete():
            query = QMessageBox.question(
                self, "询问", "是否删除该秘钥登录信息？",
                QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            if query == QMessageBox.StandardButton.Ok:
                # 1. 删除 UI 元素
                self.takeItem(self.row(item))
                # 2. 删除数据库记录
                self.userinfo_db.del_idx_key(item.sql_idx)

        button.clicked.connect(delete)

    def add_all_user(self):
        """从数据库读取并填充所有列表项"""
        self.clear()

        for value in self.userinfo_db.query_all_password():
            # value 格式为: (id, host, port, username, password)
            self.create_user_item_password(value[0], f"密码 | {value[1]}:{value[2]} | {value[3]}")

        for value in self.userinfo_db.query_all_key():
            # value 格式为: (id, host, port, username, key_path, passphrase)
            self.create_user_item_key(value[0], f"秘钥 | {value[1]}:{value[2]} | {value[3]} | {value[4]}")

    def closeEvent(self, event):
        """窗口关闭时确保数据库连接释放"""
        self.userinfo_db.close()
        super().closeEvent(event)
