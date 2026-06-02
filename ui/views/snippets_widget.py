# ui/views/snippets_widget.py
import json
import logging
import os
import re
from datetime import datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTreeWidget, \
    QTreeWidgetItem, QMenu, QInputDialog, QMessageBox, QLineEdit, QFormLayout, QDialog, \
    QDialogButtonBox, QComboBox

from core.config import get_data_path

logger = logging.getLogger(__name__)


class SnippetDialog(QDialog):
    """用于添加/编辑快捷命令的弹窗，支持作用域选择"""

    def __init__(self, parent=None, name="", cmd="", scope="global"):
        super().__init__(parent)
        self.setWindowTitle("快捷命令")
        self.resize(350, 150)
        layout = QFormLayout(self)

        self.name_edit = QLineEdit(name)
        self.name_edit.setPlaceholderText("如: 查看Docker日志")
        self.cmd_edit = QLineEdit(cmd)
        self.cmd_edit.setPlaceholderText("如: docker logs -f xxx")

        self.scope_combo = QComboBox()
        self.scope_combo.addItem("🌐 全局 (所有服务器可见)", "global")
        self.scope_combo.addItem("💻 本站 (仅当前服务器可见)", "site")

        # 默认选中对应的作用域
        if scope == "site":
            self.scope_combo.setCurrentIndex(1)

        layout.addRow("名称:", self.name_edit)
        layout.addRow("命令:", self.cmd_edit)
        layout.addRow("可见范围:", self.scope_combo)

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btn_box.accepted.connect(self.accept)
        btn_box.rejected.connect(self.reject)
        layout.addRow(btn_box)

    def get_data(self):
        return self.name_edit.text().strip(), self.cmd_edit.text().strip(), self.scope_combo.currentData()


class QuickSnippetsWidget(QWidget):
    """快捷命令侧边栏组件 (支持全局与站点区分 + 右键菜单)"""
    command_triggered = Signal(str)

    def __init__(self, site_id: str):
        super().__init__()
        self.site_id = site_id
        self.snippets_file = get_data_path("quick_snippets_v2.json")
        self.data = {
            "global": [],
            "sites": {}
        }
        self._history_file = get_data_path("quickstfp_command_history.json")
        self._history: list[dict] = []
        self._load_history()
        self.init_ui()
        self.load_snippets()

    def _substitute_template(self, cmd: str, remote_path: str = "", session_url: str = "") -> str:
        """FEAT-17: 替换命令模板变量"""
        result = cmd

        def _prompt_replacer(match):
            prompt_text = match.group(1)
            text, ok = QInputDialog.getText(self, "命令参数", prompt_text)
            if ok and text:
                return text
            return match.group(0)

        result = re.sub(r'!\?(.+?)!', _prompt_replacer, result)
        result = result.replace("!S", session_url or f"{self.site_id}")
        result = result.replace("!", remote_path)
        return result

    def _load_history(self):
        if os.path.exists(self._history_file):
            try:
                with open(self._history_file, 'r', encoding='utf-8') as f:
                    self._history = json.load(f)
            except Exception:
                self._history = []

    def _save_history(self):
        with open(self._history_file, 'w', encoding='utf-8') as f:
            json.dump(self._history[-500:], f, ensure_ascii=False, indent=2)

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        title = QLabel("⚡ 快捷命令 (双击执行)")
        title.setStyleSheet("font-weight: bold; color: #555;")
        layout.addWidget(title)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(15)
        self.tree.itemDoubleClicked.connect(self.execute_item)

        # 开启自定义右键菜单支持
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)

        layout.addWidget(self.tree)

        # 底部按钮区
        btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("添加")
        self.edit_btn = QPushButton("编辑")
        self.del_btn = QPushButton("删除")

        self.add_btn.clicked.connect(self.add_snippet)
        self.edit_btn.clicked.connect(self.edit_snippet)
        self.del_btn.clicked.connect(self.del_snippet)

        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.edit_btn)
        btn_layout.addWidget(self.del_btn)
        layout.addLayout(btn_layout)

    def show_context_menu(self, pos):
        item = self.tree.itemAt(pos)
        menu = QMenu(self)

        # 智能推断添加命令的默认作用域
        default_scope = "global"
        if item:
            meta = item.data(0, Qt.ItemDataRole.UserRole)
            if meta:
                default_scope = meta["type"]
            else:
                if "本站" in item.text(0):
                    default_scope = "site"

        add_action = menu.addAction("➕ 添加命令")
        add_action.triggered.connect(lambda _, s=default_scope: self.add_snippet(s))

        if item and item.data(0, Qt.ItemDataRole.UserRole):
            menu.addSeparator()

            exec_action = menu.addAction("🚀 立刻执行")
            exec_action.triggered.connect(lambda _, i=item: self.execute_item(i, 0))

            edit_action = menu.addAction("✏️ 编辑")
            edit_action.triggered.connect(self.edit_snippet)

            del_action = menu.addAction("🗑️ 删除")
            del_action.triggered.connect(self.del_snippet)

        menu.exec(self.tree.mapToGlobal(pos))

    def add_snippet(self, default_scope="global"):
        # 兼容处理：底部的"添加"按钮点击时，clicked 信号默认会传一个布尔值 False 过来
        if isinstance(default_scope, bool):
            default_scope = "global"

        dialog = SnippetDialog(self, scope=default_scope)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            name, cmd, scope = dialog.get_data()
            if name and cmd:
                target_list = self._get_target_list(scope)
                target_list.append({"name": name, "cmd": cmd})
                self.save_snippets()
                self.refresh_tree()

    def load_snippets(self):
        if os.path.exists(self.snippets_file):
            try:
                with open(self.snippets_file, 'r', encoding='utf-8') as f:
                    loaded_data = json.load(f)
                    self.data["global"] = loaded_data.get("global", [])
                    self.data["sites"] = loaded_data.get("sites", {})
            except Exception as e:
                logger.error(f"解析快捷命令配置失败: {e}")

        if self.site_id not in self.data["sites"]:
            self.data["sites"][self.site_id] = []

        self.refresh_tree()

    def save_snippets(self):
        try:
            with open(self.snippets_file, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, ensure_ascii=False, indent=4)
        except Exception as e:
            QMessageBox.warning(self, "保存失败", str(e))

    def refresh_tree(self):
        self.tree.clear()

        global_root = QTreeWidgetItem(self.tree, ["🌐 全局命令"])
        global_root.setFlags(Qt.ItemFlag.ItemIsEnabled)
        for idx, snip in enumerate(self.data["global"]):
            item = QTreeWidgetItem(global_root, [f"{snip['name']}\n> {snip['cmd']}"])
            item.setToolTip(0, snip['cmd'])
            item.setData(0, Qt.ItemDataRole.UserRole, {"type": "global", "index": idx, "data": snip})

        site_root = QTreeWidgetItem(self.tree, ["💻 本站命令"])
        site_root.setFlags(Qt.ItemFlag.ItemIsEnabled)
        for idx, snip in enumerate(self.data["sites"][self.site_id]):
            item = QTreeWidgetItem(site_root, [f"{snip['name']}\n> {snip['cmd']}"])
            item.setToolTip(0, snip['cmd'])
            item.setData(0, Qt.ItemDataRole.UserRole, {"type": "site", "index": idx, "data": snip})

        self.tree.expandAll()

    def _get_target_list(self, scope: str):
        if scope == "global":
            return self.data["global"]
        else:
            return self.data["sites"][self.site_id]

    def edit_snippet(self):
        item = self.tree.currentItem()
        if not item or not item.data(0, Qt.ItemDataRole.UserRole): return

        meta = item.data(0, Qt.ItemDataRole.UserRole)
        old_scope = meta["type"]
        snip = meta["data"]

        dialog = SnippetDialog(self, snip['name'], snip['cmd'], old_scope)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            name, cmd, new_scope = dialog.get_data()
            if not (name and cmd): return

            if old_scope != new_scope:
                self._get_target_list(old_scope).pop(meta["index"])
                self._get_target_list(new_scope).append({"name": name, "cmd": cmd})
            else:
                target_list = self._get_target_list(old_scope)
                target_list[meta["index"]] = {"name": name, "cmd": cmd}

            self.save_snippets()
            self.refresh_tree()

    def del_snippet(self):
        item = self.tree.currentItem()
        if not item or not item.data(0, Qt.ItemDataRole.UserRole): return

        reply = QMessageBox.question(self, "确认删除", "确定要删除该快捷命令吗？")
        if reply == QMessageBox.StandardButton.Yes:
            meta = item.data(0, Qt.ItemDataRole.UserRole)
            target_list = self._get_target_list(meta["type"])
            target_list.pop(meta["index"])

            self.save_snippets()
            self.refresh_tree()

    def execute_item(self, item, column, remote_path: str = ""):
        meta = item.data(0, Qt.ItemDataRole.UserRole)
        if not meta: return

        snip = meta["data"]
        cmd = self._substitute_template(snip['cmd'], remote_path)
        self._history.append({
            "cmd": cmd.strip(),
            "name": snip.get("name", ""),
            "time": datetime.now().isoformat(),
            "site": self.site_id,
        })
        self._save_history()
        self.command_triggered.emit(cmd + '\r')
