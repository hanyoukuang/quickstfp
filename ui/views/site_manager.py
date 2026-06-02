# ui/views/site_manager.py
import json
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter, QTreeWidget, QTreeWidgetItem,
    QFormLayout, QLineEdit, QPushButton, QComboBox, QCheckBox, QStackedWidget,
    QMessageBox, QFileDialog, QLabel, QInputDialog
)

from database.user_model import UserInfoDB
from ui.views.ssh_keygen_dialog import SSHKeygenDialog


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

        left_widget = self._init_left_panel()
        right_widget = self._init_right_panel()

        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        main_layout.addWidget(splitter)

        self.clear_form()

    def _init_left_panel(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)

        self.site_list = QTreeWidget()
        self.site_list.setHeaderHidden(True)
        self.site_list.setIndentation(16)
        self.site_list.itemClicked.connect(self.on_site_selected)

        self._folders = {}

        btn_layout = QHBoxLayout()
        self.btn_new = QPushButton("新建站点")
        self.btn_delete = QPushButton("删除站点")
        self.btn_new_folder = QPushButton("新建分组")
        self.btn_new.clicked.connect(self.create_new_site)
        self.btn_delete.clicked.connect(self.delete_site)
        self.btn_new_folder.clicked.connect(self._new_folder)
        btn_layout.addWidget(self.btn_new)
        btn_layout.addWidget(self.btn_delete)
        btn_layout.addWidget(self.btn_new_folder)

        io_layout = QHBoxLayout()
        self.btn_import = QPushButton("导入")
        self.btn_export = QPushButton("导出")
        self.btn_import.clicked.connect(self.import_sites)
        self.btn_export.clicked.connect(self.export_sites)
        io_layout.addWidget(self.btn_import)
        io_layout.addWidget(self.btn_export)

        layout.addWidget(QLabel("<b>保存的会话</b>"))
        layout.addWidget(self.site_list)
        layout.addLayout(btn_layout)
        layout.addLayout(io_layout)
        return widget

    def _init_right_panel(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 0, 0, 0)

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
        self.verify_host_checkbox = QCheckBox("验证主机密钥 (建议开启，防止MITM攻击)")
        self.verify_host_checkbox.setChecked(True)
        form_layout.addRow(self.verify_host_checkbox)

        self.auth_stacked_widget = self._init_auth_panel()

        action_layout = QHBoxLayout()
        action_layout.addStretch()
        self.btn_save = QPushButton("保存")
        self.btn_connect = QPushButton("连接")
        self.btn_save.clicked.connect(self.save_site)
        self.btn_connect.clicked.connect(self.connect_site)
        action_layout.addWidget(self.btn_save)
        action_layout.addWidget(self.btn_connect)

        layout.addWidget(QLabel("<b>连接详情</b>"))
        layout.addLayout(form_layout)
        layout.addWidget(self.auth_stacked_widget)
        layout.addStretch()
        layout.addLayout(action_layout)
        return widget

    def _init_auth_panel(self) -> QStackedWidget:
        stacked = QStackedWidget()

        pass_widget = QWidget()
        pass_layout = QFormLayout(pass_widget)
        pass_layout.setContentsMargins(0, 0, 0, 0)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        pass_layout.addRow("密码:", self.password_edit)
        stacked.addWidget(pass_widget)

        key_widget = QWidget()
        key_layout = QFormLayout(key_widget)
        key_layout.setContentsMargins(0, 0, 0, 0)
        self.key_path_edit = QLineEdit()
        self.btn_select_key = QPushButton("浏览...")
        self.btn_select_key.clicked.connect(self.select_key_file)
        key_hbox = QHBoxLayout()
        key_hbox.addWidget(self.key_path_edit)
        key_hbox.addWidget(self.btn_select_key)
        self.btn_gen_key = QPushButton("生成密钥")
        self.btn_gen_key.clicked.connect(self.generate_key)
        key_hbox.addWidget(self.btn_gen_key)
        self.passphrase_edit = QLineEdit()
        self.passphrase_edit.setEchoMode(QLineEdit.EchoMode.Password)
        key_layout.addRow("私钥文件:", key_hbox)
        key_layout.addRow("Passphrase:", self.passphrase_edit)
        stacked.addWidget(key_widget)

        return stacked

    def closeEvent(self, event):
        if hasattr(self, 'userinfo_db') and self.userinfo_db:
            self.userinfo_db.close()
        super().closeEvent(event)

    def export_sites(self):
        """将当前的站点配置导出为 JSON 文件"""
        # 二次确认：明文密码泄露风险
        reply = QMessageBox.warning(
            self, "⚠️ 安全警告",
            "导出文件将包含明文密码和密钥口令！\n\n"
            "如果此文件泄露，攻击者可以直接获取你的所有 SSH 凭证。\n\n"
            "建议：\n"
            "• 导出后立即将文件保存到安全位置\n"
            "• 使用完毕后尽快删除导出文件\n"
            "• 不要通过不安全的渠道分享该文件\n\n"
            "确定要继续导出吗？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        filename, _ = QFileDialog.getSaveFileName(self, "导出站点配置", "sftp_sites.json", "JSON Files (*.json)")
        if not filename:
            return

        export_data = {"passwords": [], "keys": []}

        # 获取并序列化密码登录站点
        # query_all_password 返回: (id, host, port, username, password)
        for r in self.userinfo_db.query_all_password():
            export_data["passwords"].append({
                "host": r[1],
                "port": r[2],
                "username": r[3],
                "password": r[4]
            })

        # 获取并序列化私钥登录站点
        # query_all_key 返回: (id, host, port, username, key_path, passphrase)
        for r in self.userinfo_db.query_all_key():
            export_data["keys"].append({
                "host": r[1],
                "port": r[2],
                "username": r[3],
                "key_path": r[4],
                "passphrase": r[5]
            })

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=4)
            QMessageBox.information(self, "导出成功",
                                    "站点配置已成功导出！\n\n"
                                    "⚠️ 导出的 JSON 文件中包含明文密码，请妥善保管！\n"
                                    "导出文件路径：" + filename)
        except Exception as e:
            QMessageBox.warning(self, "导出失败", f"导出过程中发生错误：\n{e}")

    def import_sites(self):
        """从 JSON 文件导入站点配置"""
        filename, _ = QFileDialog.getOpenFileName(self, "导入站点配置", "", "JSON Files (*.json)")
        if not filename:
            return

        try:
            with open(filename, 'r', encoding='utf-8') as f:
                import_data = json.load(f)

            # 导入密码登录站点
            passwords = import_data.get("passwords", [])
            for p in passwords:
                self.userinfo_db.insert_password(
                    p.get("host", ""),
                    p.get("port", 22),
                    p.get("username", ""),
                    p.get("password", "")
                )

            # 导入私钥登录站点
            keys = import_data.get("keys", [])
            for k in keys:
                self.userinfo_db.insert_key(
                    k.get("host", ""),
                    k.get("port", 22),
                    k.get("username", ""),
                    k.get("key_path", ""),
                    k.get("passphrase", "")
                )

            self.load_sites()
            QMessageBox.information(self, "成功", "站点配置导入成功！相同的配置已被自动去重。")
        except Exception as e:
            QMessageBox.warning(self, "导入失败", f"导入过程中发生错误（可能文件格式不正确）：\n{e}")

    def on_auth_type_changed(self, index):
        self.auth_stacked_widget.setCurrentIndex(index)

    def select_key_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "选择私钥文件")
        if filename:
            self.key_path_edit.setText(filename)

    def generate_key(self):
        dialog = SSHKeygenDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            pass  # 用户可自行将公钥部署到服务器

    def _new_folder(self):
        text, ok = QInputDialog.getText(self, "新建分组", "输入分组名称")
        if ok and text:
            self._folders[text] = QTreeWidgetItem(self.site_list, [text])
            self._folders[text].setFlags(Qt.ItemFlag.ItemIsEnabled)
            self.site_list.expandAll()

    def load_sites(self):
        self.site_list.clear()
        self._folders.clear()
        root_folder = QTreeWidgetItem(self.site_list, ["📂 未分组"])
        root_folder.setFlags(Qt.ItemFlag.ItemIsEnabled)
        self._folders["未分组"] = root_folder

        for val in self.userinfo_db.query_all_password():
            display_text = f"{val[1]} ({val[3]})"
            item = QTreeWidgetItem(root_folder, [display_text])
            item.setData(0, Qt.ItemDataRole.UserRole, {"type": "password", "id": val[0]})

        for val in self.userinfo_db.query_all_key():
            display_text = f"[Key] {val[1]} ({val[3]})"
            item = QTreeWidgetItem(root_folder, [display_text])
            item.setData(0, Qt.ItemDataRole.UserRole, {"type": "key", "id": val[0]})

        self.site_list.expandAll()

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

    def on_site_selected(self, item: QTreeWidgetItem, column: int = 0):
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data or "type" not in data:
            return
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

    @staticmethod
    def _parse_port(text: str) -> int:
        """安全解析端口号，返回整数；无效输入返回 None"""
        text = text.strip()
        if not text:
            return 22
        try:
            return int(text)
        except ValueError:
            return None

    def save_site(self):
        """保存或更新当前站点"""
        host = self.host_edit.text().strip()
        port = self._parse_port(self.port_edit.text())
        if port is None:
            QMessageBox.warning(self, "错误", "端口号必须为有效数字！")
            return
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

    def insert_new_record(self, host: str, port: int, username: str, auth_type: str) -> None:
        if auth_type == "password":
            self.userinfo_db.insert_password(host, port, username, self.password_edit.text())
        else:
            self.userinfo_db.insert_key(host, port, username, self.key_path_edit.text(), self.passphrase_edit.text())

    def delete_site(self):
        item = self.site_list.currentItem()
        if not item: return
        data = item.data(0, Qt.ItemDataRole.UserRole)
        if not data or "type" not in data: return

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
        port = self._parse_port(self.port_edit.text())
        if port is None:
            QMessageBox.warning(self, "警告", "端口号必须为有效数字！")
            return
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
                "host": host, "port": port, "username": username, "password": password,
                "verify_host_key": self.verify_host_checkbox.isChecked()
            })
        else:
            key_path = self.key_path_edit.text()
            if not key_path:
                QMessageBox.warning(self, "警告", "私钥路径不能为空")
                return
            self.session_requested.emit({
                "host": host, "port": port, "username": username,
                "client_keys": [key_path], "passphrase": self.passphrase_edit.text(),
                "verify_host_key": self.verify_host_checkbox.isChecked()
            })
