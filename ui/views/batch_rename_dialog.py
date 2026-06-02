import re
from typing import List

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit, QPushButton,
    QComboBox, QTextEdit, QLabel, QDialogButtonBox, QMessageBox
)


class BatchRenameDialog(QDialog):
    """批量重命名对话框，支持正则替换、序号插入、前后缀"""

    def __init__(self, parent=None, filenames: List[str] = None):
        super().__init__(parent)
        self.setWindowTitle("批量重命名")
        self.resize(500, 400)
        self._filenames = filenames or []
        self._preview: List[str] = []

        layout = QVBoxLayout(self)

        self._mode_combo = QComboBox()
        self._mode_combo.addItems(["正则替换", "序号插入 {n}", "大小写转换"])
        self._mode_combo.currentIndexChanged.connect(self._on_mode_changed)
        layout.addWidget(self._mode_combo)

        self._find_edit = QLineEdit()
        self._find_edit.setPlaceholderText("查找 (正则)")
        self._replace_edit = QLineEdit()
        self._replace_edit.setPlaceholderText("替换为 (支持 {n} {n:03})")

        form = QFormLayout()
        form.addRow("查找:", self._find_edit)
        form.addRow("替换:", self._replace_edit)
        layout.addLayout(form)

        preview_btn = QPushButton("预览")
        preview_btn.clicked.connect(self._do_preview)
        layout.addWidget(preview_btn)

        self._preview_text = QTextEdit()
        self._preview_text.setReadOnly(True)
        layout.addWidget(QLabel("预览 (原名 → 新名):"))
        layout.addWidget(self._preview_text)

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def _on_mode_changed(self, idx: int):
        if idx == 0:
            self._find_edit.setPlaceholderText("查找 (正则)")
            self._replace_edit.setPlaceholderText("替换为 (支持 {n} {n:03})")
        elif idx == 1:
            self._find_edit.setPlaceholderText("前缀 (可选)")
            self._replace_edit.setPlaceholderText("后缀 (可选)")
        else:
            self._find_edit.setPlaceholderText("")
            self._replace_edit.setPlaceholderText("")

    def _do_preview(self):
        mode = self._mode_combo.currentIndex()
        self._preview = []
        self._preview_text.clear()

        for i, name in enumerate(self._filenames):
            if mode == 0:
                pattern = self._find_edit.text()
                repl = self._replace_edit.text().replace("{n}", str(i + 1)).replace("{n:03}", f"{i+1:03d}")
                if pattern:
                    try:
                        new_name = re.sub(pattern, repl, name)
                    except re.error:
                        new_name = name
                else:
                    new_name = name
            elif mode == 1:
                prefix = self._find_edit.text()
                suffix = self._replace_edit.text()
                new_name = f"{prefix}{name}{suffix}"
            else:
                upper = self._find_edit.text() == "upper"
                lower = self._find_edit.text() == "lower"
                if upper:
                    new_name = name.upper()
                elif lower:
                    new_name = name.lower()
                else:
                    new_name = name

            self._preview.append(new_name)
            self._preview_text.append(f"{name}  →  {new_name}")

    def get_rename_map(self) -> dict:
        if len(self._preview) != len(self._filenames):
            self._do_preview()
        return {old: new for old, new in zip(self._filenames, self._preview) if old != new}
