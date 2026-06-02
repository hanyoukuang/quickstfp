from pathlib import Path

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QFormLayout, QHBoxLayout, QLineEdit, QPushButton,
    QComboBox, QSpinBox, QDialogButtonBox, QFileDialog, QMessageBox, QLabel,
    QTextEdit
)

import asyncssh


class SSHKeygenDialog(QDialog):
    """SSH 密钥对生成对话框，支持生成并可选部署到远端"""

    KEY_TYPES = {
        "Ed25519 (推荐)": "ssh-ed25519",
        "RSA 2048": "ssh-rsa",
        "RSA 4096": "ssh-rsa-large",
    }

    def __init__(self, parent=None, default_path: str = None):
        super().__init__(parent)
        self.setWindowTitle("生成 SSH 密钥对")
        self.resize(450, 280)

        home = str(Path.home())
        self._default_dir = default_path or f"{home}/.ssh"

        layout = QVBoxLayout(self)

        form = QFormLayout()
        self._type_combo = QComboBox()
        self._type_combo.addItems(self.KEY_TYPES.keys())
        self._type_combo.setCurrentIndex(0)
        form.addRow("密钥类型:", self._type_combo)

        path_layout = QHBoxLayout()
        self._path_edit = QLineEdit(f"{self._default_dir}/id_ed25519")
        browse_btn = QPushButton("浏览...")
        browse_btn.clicked.connect(self._browse_path)
        path_layout.addWidget(self._path_edit)
        path_layout.addWidget(browse_btn)
        form.addRow("保存路径:", path_layout)

        self._comment_edit = QLineEdit()
        self._comment_edit.setPlaceholderText("your_email@example.com")
        form.addRow("备注 (Comment):", self._comment_edit)

        self._passphrase_edit = QLineEdit()
        self._passphrase_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._passphrase_edit.setPlaceholderText("可选")
        form.addRow("Passphrase:", self._passphrase_edit)

        layout.addLayout(form)

        self._deploy_check = QPushButton("生成密钥")
        self._deploy_check.clicked.connect(self._generate)
        layout.addWidget(self._deploy_check)

        self._output = QTextEdit()
        self._output.setReadOnly(True)
        self._output.setMaximumHeight(100)
        self._output.setPlaceholderText("生成的公钥将显示在这里...")
        layout.addWidget(self._output)

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        btn_box.accepted.connect(self.accept)
        layout.addWidget(btn_box)

        self._public_key = ""

    def _browse_path(self):
        path, _ = QFileDialog.getSaveFileName(self, "保存密钥文件", self._default_dir)
        if path:
            self._path_edit.setText(path)

    def _generate(self):
        key_type_name = self._type_combo.currentText()
        save_path = self._path_edit.text().strip()
        comment = self._comment_edit.text().strip() or "quickstfp-generated"
        passphrase = self._passphrase_edit.text() or None

        if not save_path:
            QMessageBox.warning(self, "错误", "请指定密钥保存路径")
            return

        try:
            key_type = self.KEY_TYPES[key_type_name]
            if key_type == "ssh-rsa-large":
                key = asyncssh.generate_private_key("ssh-rsa", key_size=4096)
            elif key_type == "ssh-rsa":
                key = asyncssh.generate_private_key("ssh-rsa")
            else:
                key = asyncssh.generate_private_key("ssh-ed25519")

            private_key = key.export_private_key()
            public_key = key.export_public_key()

            if passphrase:
                private_key = key.export_private_key(
                    format_name="openssh",
                    passphrase=passphrase,
                )

            encryption_note = "🔒 Passphrase 已加密" if passphrase else "⚠️ 无密码保护"
            private_pem = private_key.decode("utf-8") if isinstance(private_key, bytes) else str(private_key)
            public_text = f"ssh-ed25519 {public_key.decode('utf-8')} {comment}" if isinstance(public_key, bytes) else f"{key_type} {public_key} {comment}"

            with open(save_path, "w") as f:
                f.write(private_pem)
            Path(save_path).chmod(0o600)

            pub_path = f"{save_path}.pub"
            with open(pub_path, "w") as f:
                f.write(public_text + "\n")

            self._public_key = public_text
            self._output.setText(
                f"✅ 密钥对已生成！\n"
                f"私钥: {save_path}\n"
                f"公钥: {pub_path}\n"
                f"{encryption_note}"
            )

            QMessageBox.information(self, "成功",
                f"密钥对已生成!\n\n私钥: {save_path}\n公钥: {pub_path}\n\n"
                f"如需部署到服务器，请在站点管理器中选择该私钥文件。")

        except Exception as e:
            QMessageBox.critical(self, "生成失败", str(e))

    def get_public_key(self) -> str:
        return self._public_key
