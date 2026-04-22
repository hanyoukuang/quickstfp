# ui/views/site_manager.py
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QListWidget, QListWidgetItem,
    QFormLayout, QLineEdit, QPushButton, QComboBox, QStackedWidget,
    QMessageBox, QFileDialog, QLabel
)

from database.user_model import UserInfoDB


class SiteManagerWidget(QWidget):
    """
    专业的站点管理器：左侧显示站点列表，右侧编辑详情和发起连接
    """
    session_requested = Signal(dict)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("站点管理器 (Site Manager)")
        self.resize(700, 450)

        self.userinfo_db = UserInfoDB()
        self.current_item_data = None  # 记录当前选中的项字典：{"type": str, "id": int}

        self.init_ui()
        self.load_sites()

    def init_ui(self):
        main_layout = QHBoxLayout(self)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ========== 左侧：站点列表 ==========
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)

        self.site_list = QListWidget()
        self.site_list.itemClicked.connect(self.on_site_selected)

        btn_layout = QHBoxLayout()
        self.btn_new = QPushButton("新建站点")
        self.btn_delete = QPushButton("删除站点")
        self.btn_new.clicked.connect(self.create_new_site)
        self.btn_delete.clicked.connect(self.delete_site)
        btn_layout.addWidget(self.btn_new)
        btn_layout.addWidget(self.btn_delete)

        left_layout.addWidget(QLabel("<b>保存的会话</b>"))
        left_layout.addWidget(self.site_list)
        left_layout.addLayout(btn_layout)

        # ========== 右侧：详情编辑与连接 ==========
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(10, 0, 0, 0)

        # 基础表单
        form_layout = QFormLayout()
        self.host_edit = QLineEdit()
        self.port_edit = QLineEdit("22")
        self.username_edit = QLineEdit()
        self.auth_type_combo = QComboBox()
        self.auth_type_combo.addItems(["密码登录", "私钥登录"])
        self.auth_type_combo.currentIndexChanged.connect(self.on_auth_type_changed)

        form_layout.addRow("主机 (Host):", self.host_edit)
        form_layout.addRow("端口 (Port):", self.port_edit)
        form_layout.addRow("用户名 (User):", self.username_edit)
        form_layout.addRow("认证方式:", self.auth_type_combo)

        # 认证方式堆叠面板 (密码 / 私钥)
        self.auth_stacked_widget = QStackedWidget()

        # 密码面板
        pass_widget = QWidget()
        pass_layout = QFormLayout(pass_widget)
        pass_layout.setContentsMargins(0, 0, 0, 0)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        pass_layout.addRow("密码:", self.password_edit)

        # 私钥面板
        key_widget = QWidget()
        key_layout = QFormLayout(key_widget)
        key_layout.setContentsMargins(0, 0, 0, 0)
        self.key_path_edit = QLineEdit()
        self.btn_select_key = QPushButton("浏览...")
        self.btn_select_key.clicked.connect(self.select_key_file)

        key_hbox = QHBoxLayout()
        key_hbox.addWidget(self.key_path_edit)
        key_hbox.addWidget(self.btn_select_key)

        self.passphrase_edit = QLineEdit()
        self.passphrase_edit.setEchoMode(QLineEdit.EchoMode.Password)

        key_layout.addRow("私钥文件:", key_hbox)
        key_layout.addRow("Passphrase:", self.passphrase_edit)

        self.auth_stacked_widget.addWidget(pass_widget)
        self.auth_stacked_widget.addWidget(key_widget)

        # 底部操作按钮
        action_layout = QHBoxLayout()
        action_layout.addStretch()
        self.btn_save = QPushButton("保存")
        self.btn_connect = QPushButton("连接")
        self.btn_save.clicked.connect(self.save_site)
        self.btn_connect.clicked.connect(self.connect_site)
        action_layout.addWidget(self.btn_save)
        action_layout.addWidget(self.btn_connect)

        # 组装右侧
        right_layout.addWidget(QLabel("<b>连接详情</b>"))
        right_layout.addLayout(form_layout)
        right_layout.addWidget(self.auth_stacked_widget)
        right_layout.addStretch()
        right_layout.addLayout(action_layout)

        # 组装主界面
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        main_layout.addWidget(splitter)

        self.clear_form()

    def on_auth_type_changed(self, index):
        self.auth_stacked_widget.setCurrentIndex(index)

    def select_key_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "选择私钥文件")
        if filename:
            self.key_path_edit.setText(filename)

    def load_sites(self):
        """加载所有站点到列表"""
        self.site_list.clear()

        # 加载密码登录
        for val in self.userinfo_db.query_all_password():
            display_text = f"{val[1]} ({val[3]})"  # Host (Username)
            item = QListWidgetItem(display_text)
            item.setData(Qt.ItemDataRole.UserRole, {"type": "password", "id": val[0]})
            self.site_list.addItem(item)

        # 加载私钥登录
        for val in self.userinfo_db.query_all_key():
            display_text = f"[Key] {val[1]} ({val[3]})"
            item = QListWidgetItem(display_text)
            item.setData(Qt.ItemDataRole.UserRole, {"type": "key", "id": val[0]})
            self.site_list.addItem(item)

    def create_new_site(self):
        self.site_list.clearSelection()
        self.current_item_data = None
        self.clear_form()
        self.host_edit.setFocus()

    def clear_form(self):
        self.host_edit.clear()
        self.port_edit.setText("22")
        self.username_edit.clear()
        self.password_edit.clear()
        self.key_path_edit.clear()
        self.passphrase_edit.clear()
        self.auth_type_combo.setCurrentIndex(0)

    def on_site_selected(self, item: QListWidgetItem):
        data = item.data(Qt.ItemDataRole.UserRole)
        self.current_item_data = data

        if data["type"] == "password":
            record = self.userinfo_db.query_idx_password(data["id"])
            if record:
                self.host_edit.setText(record[1])
                self.port_edit.setText(str(record[2]))
                self.username_edit.setText(record[3])
                self.password_edit.setText(record[4])
                self.auth_type_combo.setCurrentIndex(0)

        elif data["type"] == "key":
            record = self.userinfo_db.query_idx_key(data["id"])
            if record:
                self.host_edit.setText(record[1])
                self.port_edit.setText(str(record[2]))
                self.username_edit.setText(record[3])
                self.key_path_edit.setText(record[4])
                self.passphrase_edit.setText(record[5])
                self.auth_type_combo.setCurrentIndex(1)

    def save_site(self):
        """保存或更新当前站点"""
        host = self.host_edit.text().strip()
        port = int(self.port_edit.text().strip() or 22)
        username = self.username_edit.text().strip()
        auth_type = "password" if self.auth_type_combo.currentIndex() == 0 else "key"

        if not host or not username:
            QMessageBox.warning(self, "错误", "主机和用户名不能为空！")
            return

        if self.current_item_data:
            # 更新已有的
            old_type = self.current_item_data["type"]
            idx = self.current_item_data["id"]

            # 如果修改了认证方式，先删除旧记录，再作为新记录插入
            if old_type != auth_type:
                if old_type == "password":
                    self.userinfo_db.del_idx_password(idx)
                else:
                    self.userinfo_db.del_idx_key(idx)
                self.insert_new_record(host, port, username, auth_type)
            else:
                # 正常更新
                if auth_type == "password":
                    self.userinfo_db.update_password(idx, host, port, username, self.password_edit.text())
                else:
                    self.userinfo_db.update_key(idx, host, port, username, self.key_path_edit.text(),
                                                self.passphrase_edit.text())
        else:
            # 全新插入
            self.insert_new_record(host, port, username, auth_type)

        self.load_sites()
        QMessageBox.information(self, "成功", "站点已保存。")

    def insert_new_record(self, host, port, username, auth_type):
        if auth_type == "password":
            self.userinfo_db.insert_password(host, port, username, self.password_edit.text())
        else:
            self.userinfo_db.insert_key(host, port, username, self.key_path_edit.text(), self.passphrase_edit.text())

    def delete_site(self):
        item = self.site_list.currentItem()
        if not item: return
        data = item.data(Qt.ItemDataRole.UserRole)

        reply = QMessageBox.question(self, "确认", "确定要删除该站点吗？")
        if reply == QMessageBox.StandardButton.Yes:
            if data["type"] == "password":
                self.userinfo_db.del_idx_password(data["id"])
            else:
                self.userinfo_db.del_idx_key(data["id"])
            self.load_sites()
            self.create_new_site()  # 清空右侧表单

    def connect_site(self):
        """发射登录信号，触发主程序的连接逻辑"""
        host = self.host_edit.text().strip()
        port = int(self.port_edit.text().strip() or 22)
        username = self.username_edit.text().strip()

        if not host or not username:
            QMessageBox.warning(self, "警告", "请填写完整主机与用户名")
            return

        # 检查是否未保存
        # self.save_site()

        if self.auth_type_combo.currentIndex() == 0:
            password = self.password_edit.text()
            if not password:
                QMessageBox.warning(self, "警告", "密码不能为空")
                return
            self.session_requested.emit({
                "host": host, "port": port, "username": username, "password": password
            })
        else:
            key_path = self.key_path_edit.text()
            if not key_path:
                QMessageBox.warning(self, "警告", "私钥路径不能为空")
                return
            self.session_requested.emit({
                "host": host, "port": port, "username": username,
                "client_keys": [key_path], "passphrase": self.passphrase_edit.text()
            })
