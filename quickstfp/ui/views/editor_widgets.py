# ui/views/editor_widgets.py
import logging
import os
import re
import shutil
import stat
import tempfile

from PySide6.QtCore import Qt, QUrl, QObject, Slot
from PySide6.QtCore import QFileSystemWatcher
from PySide6.QtGui import QCloseEvent
from PySide6.QtGui import QDesktopServices
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PySide6.QtWidgets import QTextEdit, QMessageBox, QDialog, QVBoxLayout, QGridLayout, QLabel, QCheckBox, \
    QDialogButtonBox

logger = logging.getLogger(__name__)


class SimpleHighlighter(QSyntaxHighlighter):
    """一个简单的语法高亮器（支持常见关键字、字符串和注释高亮）"""

    def __init__(self, document):
        super().__init__(document)

        # 1. 关键字高亮样式 (蓝色加粗)
        self.keyword_format = QTextCharFormat()
        self.keyword_format.setForeground(QColor("darkBlue"))
        self.keyword_format.setFontWeight(QFont.Weight.Bold)

        keywords = [
            r'\bdef\b', r'\bclass\b', r'\bimport\b', r'\bfrom\b', r'\bas\b',
            r'\bif\b', r'\belif\b', r'\belse\b', r'\bwhile\b', r'\bfor\b', r'\bin\b',
            r'\breturn\b', r'\bpass\b', r'\bbreak\b', r'\bcontinue\b', r'\byield\b',
            r'\bTrue\b', r'\bFalse\b', r'\bNone\b', r'\band\b', r'\bor\b', r'\bnot\b',
            r'\btry\b', r'\bexcept\b', r'\bfinally\b', r'\bwith\b', r'\basync\b', r'\bawait\b',
            r'\bint\b', r'\bfloat\b', r'\bdouble\b', r'\bchar\b', r'\bvoid\b', r'\bbool\b',
            r'\bauto\b', r'\bconst\b', r'\bstruct\b', r'\bnamespace\b', r'\busing\b'
        ]
        self.rules = [(re.compile(kw), self.keyword_format) for kw in keywords]

        # 2. 注释高亮样式 (灰色斜体)
        self.comment_format = QTextCharFormat()
        self.comment_format.setForeground(QColor("gray"))
        self.comment_format.setFontItalic(True)
        self.comment_rule = re.compile(r'#.*')

        # 3. 字符串高亮样式 (深绿色)
        self.string_format = QTextCharFormat()
        self.string_format.setForeground(QColor("darkGreen"))
        self.string_rule = re.compile(r'".*?"|\'.*?\'')

    def highlightBlock(self, text):
        # 匹配关键字
        for pattern, fmt in self.rules:
            for match in pattern.finditer(text):
                self.setFormat(match.start(), match.end() - match.start(), fmt)
        # 匹配字符串
        for match in self.string_rule.finditer(text):
            self.setFormat(match.start(), match.end() - match.start(), self.string_format)
        # 匹配单行注释
        for match in self.comment_rule.finditer(text):
            self.setFormat(match.start(), match.end() - match.start(), self.comment_format)


class Edit(QTextEdit):
    def __init__(self, remote_file_widget, path: str, text: str):
        super().__init__(parent=remote_file_widget)
        self.path = path
        self.info = remote_file_widget.info
        self.original_text = text
        self.setText(text)
        self.setWindowFlags(Qt.WindowType.Tool)

        # === 附加语法高亮 ===
        self.highlighter = SimpleHighlighter(self.document())

    def keyPressEvent(self, event):
        # === 捕获 Ctrl + S 并执行保存逻辑 ===
        if (event.modifiers() & Qt.KeyboardModifier.ControlModifier) and event.key() == Qt.Key.Key_S:
            self.save_file_action()
        else:
            # 否则执行默认键盘事件
            super().keyPressEvent(event)

    def save_file_action(self):
        """单独抽离的保存逻辑"""
        now_text = self.toPlainText()
        if now_text == self.original_text:
            # 未修改无需保存
            return

        try:
            self.info.save_file(self.path, now_text)
            self.original_text = now_text  # 覆盖原始记录
            QMessageBox.information(self, "成功", "文件已快捷保存！")
        except Exception as e:
            QMessageBox.warning(self, "错误", f"保存失败:\n{e}")

    def closeEvent(self, event: QCloseEvent):
        now_text = self.toPlainText()
        if now_text == self.original_text:
            return

        reply = QMessageBox.question(self, "文件", "文件有改动，是否保存",
                                     QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
        if reply == QMessageBox.StandardButton.Ok:
            self.save_file_action()


class ExternalEditorWatcher(QObject):
    """
    外部编辑器监控类：
    负责将远端文件写入本地临时目录，调用系统默认程序打开，
    并监控文件的修改事件（Ctrl+S），一旦触发则自动同步回远端服务器。
    """

    def __init__(self, sftp_info):
        super().__init__()
        self.info = sftp_info
        self.watcher = QFileSystemWatcher()
        self.watcher.fileChanged.connect(self.on_file_changed)

        # 映射：本地临时路径 -> 远端实际路径
        self.file_map = {}
        # 创建根级临时目录
        self.temp_dir = tempfile.mkdtemp(prefix="quickstfp_ext_")

    def cleanup_temp_files(self):
        """清理当前会话产生的所有外部编辑临时文件"""
        if os.path.exists(self.temp_dir):
            try:
                shutil.rmtree(self.temp_dir)
                logger.info(f"已清理外部编辑临时目录: {self.temp_dir}")
            except Exception as e:
                logger.error(f"清理临时目录失败: {e}")

    def open_in_external_editor(self, remote_path: str, content: str):
        filename = os.path.basename(remote_path)
        # 为每个文件创建一个独立的临时子目录，防止多开同名文件造成冲突
        sub_dir = tempfile.mkdtemp(dir=self.temp_dir)
        local_path = os.path.join(sub_dir, filename)

        # 1. 写入本地临时文件
        with open(local_path, 'w', encoding='utf-8') as f:
            f.write(content)

        # 2. 记录映射关系并加入文件系统监控
        self.file_map[local_path] = remote_path
        self.watcher.addPath(local_path)

        # 3. 唤起操作系统默认程序 (例如 .py 会唤起 VSCode 或 PyCharm)
        QDesktopServices.openUrl(QUrl.fromLocalFile(local_path))

    @Slot(str)
    def on_file_changed(self, local_path: str):
        if local_path in self.file_map:
            remote_path = self.file_map[local_path]
            try:
                # 检查文件是否依然存在（防止某些编辑器保存时的删除行为导致报错）
                if not os.path.exists(local_path):
                    return

                # 读取本地最新修改的内容
                with open(local_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                # 触发底层同步回远端
                self.info.save_file(remote_path, content)
                logger.info(f"[{os.path.basename(remote_path)}] 外部修改已自动同步到远端！")

            except Exception as e:
                logger.error(f"同步远端文件失败: {e}")
            finally:
                # 【核心修复】：许多现代编辑器（如 VSCode, Vim）在保存时是"原子保存"
                # 即先写入一个新文件，再替换旧文件。这会导致 QFileSystemWatcher 丢失对 inode 的监控。
                # 解决方案：如果在保存后发现监控丢失，重新将其加回 watcher
                if local_path not in self.watcher.files() and os.path.exists(local_path):
                    self.watcher.addPath(local_path)


class PermissionDialog(QDialog):
    """文件/文件夹权限修改弹窗"""

    def __init__(self, parent, filename: str, current_perms: int):
        super().__init__(parent)
        self.setWindowTitle(f"属性/权限 - {filename}")
        self.current_perms = current_perms
        self.checkboxes = {}

        layout = QVBoxLayout(self)
        grid = QGridLayout()

        # 表头
        grid.addWidget(QLabel("读取 (R)"), 0, 1, alignment=Qt.AlignmentFlag.AlignCenter)
        grid.addWidget(QLabel("写入 (W)"), 0, 2, alignment=Qt.AlignmentFlag.AlignCenter)
        grid.addWidget(QLabel("执行 (X)"), 0, 3, alignment=Qt.AlignmentFlag.AlignCenter)

        # 权限映射表 (描述, 读位, 写位, 执行位)
        roles = [
            ("所有者 (Owner)", stat.S_IRUSR, stat.S_IWUSR, stat.S_IXUSR),
            ("所属组 (Group)", stat.S_IRGRP, stat.S_IWGRP, stat.S_IXGRP),
            ("公共 (Others)", stat.S_IROTH, stat.S_IWOTH, stat.S_IXOTH)
        ]

        # 渲染 3x3 复选框阵列
        for row, (role_name, r_flag, w_flag, x_flag) in enumerate(roles, start=1):
            grid.addWidget(QLabel(role_name), row, 0)

            for col, flag in enumerate([r_flag, w_flag, x_flag], start=1):
                cb = QCheckBox()
                # 通过按位与运算判断当前是否拥有该权限
                cb.setChecked(bool(current_perms & flag))
                grid.addWidget(cb, row, col, alignment=Qt.AlignmentFlag.AlignCenter)
                self.checkboxes[flag] = cb

        layout.addLayout(grid)

        # 确认与取消按钮
        self.buttonBox = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        self.buttonBox.accepted.connect(self.accept)
        self.buttonBox.rejected.connect(self.reject)
        layout.addWidget(self.buttonBox)

    def get_new_permissions(self) -> int:
        """收集面板上勾选的状态，计算成新的八进制权限数字"""
        new_perms = 0
        # 必须保留文件的高位类型（说明它是普通文件、文件夹还是软链接）
        new_perms |= stat.S_IFMT(self.current_perms)

        # 叠加面板上的新权限
        for flag, cb in self.checkboxes.items():
            if cb.isChecked():
                new_perms |= flag
        return new_perms



