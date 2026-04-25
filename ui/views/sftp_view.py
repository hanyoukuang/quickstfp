# ui/views/sftp_view.py
import asyncio
import datetime
import json
import os
import re  # 新增
import shutil
import stat
import tempfile
from PySide6.QtCore import QFileInfo  # 新增
from PySide6.QtWidgets import QFileIconProvider  # 新增
from PySide6.QtCore import QFileSystemWatcher, QUrl, QObject
from PySide6.QtCore import Qt, QModelIndex, Signal, Slot, QDir, QMimeData, QByteArray, QRect, QPoint
from PySide6.QtGui import QCloseEvent, QDrag, QPixmap, QPainter
from PySide6.QtGui import QDesktopServices
from PySide6.QtGui import QStandardItemModel, QStandardItem
# 在原来的 PySide6.QtGui 导入中增加以下类:
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PySide6.QtWidgets import (
    QListWidget, QStyle, QApplication, QListWidgetItem, QPushButton,
    QMessageBox, QSplitter, QHBoxLayout, QStackedWidget, QLineEdit,
    QFormLayout, QLabel, QVBoxLayout, QWidget, QTextEdit, QFileDialog,
    QAbstractItemView, QMenu, QInputDialog, QSlider, QTreeView, QFileSystemModel,
    QCheckBox, QDialogButtonBox, QDialog, QGridLayout, QComboBox
)
from PySide6.QtWidgets import QSpinBox

from core.session import SSHSFTPInfo
from core.transport import GET, PUT
from ui.components.progress_bar import ProgressBar
from ui.components.terminal_widget import SSHPtyWidget
from utils.file_utils import is_binary


# 在原来的 PySide6.QtGui 导入中增加以下类:


class LocalFileTreeView(QTreeView):
    """
    自定义本地树形视图，拦截远端拖拽过来的自定义 MIME 数据进行下载处理
    """

    def __init__(self, sftp_tab_widget):
        super().__init__()
        self.sftp_tab_widget = sftp_tab_widget
        # 开启拖放与本地文件移动支持
        self.setAcceptDrops(True)
        self.setDragEnabled(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setDefaultDropAction(Qt.DropAction.MoveAction)

    def dragEnterEvent(self, event):
        # 允许远端拖拽数据进入
        if event.mimeData().hasFormat("application/x-quickstfp-remote-paths"):
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasFormat("application/x-quickstfp-remote-paths"):
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):
        if event.mimeData().hasFormat("application/x-quickstfp-remote-paths"):
            event.acceptProposedAction()
            # 解析远端传来的路径
            remote_paths = json.loads(
                event.mimeData().data("application/x-quickstfp-remote-paths").data().decode('utf-8'))

            # 获取当前鼠标放开的位置所在的本地目录
            index = self.indexAt(event.position().toPoint())
            model = self.model()
            if index.isValid() and model.isDir(index):
                dst_dir = model.filePath(index)
            else:
                # 默认放到当前根视图目录
                dst_dir = model.filePath(self.rootIndex())

            # 触发批量下载
            for remote_path in remote_paths:
                self.sftp_tab_widget.transport_control_widget.get(remote_path, dst_dir, 20)
        else:
            # 走原生逻辑，实现本地到本地的拖拽移动
            super().dropEvent(event)


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
            r'\btry\b', r'\bexcept\b', r'\bfinally\b', r'\bwith\b', r'\basync\b', r'\bawait\b'
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
    def __init__(self, remote_file_widget: 'RemoteFileWidget', path: str, text: str):
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
                print(f"已清理外部编辑临时目录: {self.temp_dir}")
            except Exception as e:
                print(f"清理临时目录失败: {e}")

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
                print(f"[{os.path.basename(remote_path)}] 外部修改已自动同步到远端！")

            except Exception as e:
                print(f"同步远端文件失败: {e}")
            finally:
                # 【核心修复】：许多现代编辑器（如 VSCode, Vim）在保存时是“原子保存”
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


class FileSelect(QWidget):
    def __init__(self, user_select_target_widget: 'UserSelectTargetWidget'):
        super().__init__(parent=user_select_target_widget)


class LocalFileWidget(QWidget):
    """
    本地文件系统浏览器。
    已适配本地文件内部拖动，并接收远端文件的下载拖放，新增本地右键菜单功能。
    """

    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__()
        self.sftp_tab_widget = sftp_tab_widget

        # 1. 初始化本地文件系统模型
        self.model = QFileSystemModel()
        self.model.setRootPath(QDir.rootPath())
        self.model.setReadOnly(False)  # 关闭只读模式以支持原生本地文件的操作

        # 2. 初始化树形视图 (使用修改后的自定义 View)
        self.tree = LocalFileTreeView(self.sftp_tab_widget)
        self.tree.setModel(self.model)
        self.tree.setRootIndex(self.model.index(QDir.homePath()))

        # 优化显示：隐藏多余的列
        for i in range(1, 4): self.tree.hideColumn(i)

        # 3. 顶部路径与控制栏
        self.path_edit = QLineEdit(QDir.homePath())
        self.path_edit.setReadOnly(True)
        self.up_button = QPushButton("返回上级")

        # --- 新增：剪贴板变量 ---
        self.copy_paths = []
        self.move_paths = []

        self.init_ui()

    def init_ui(self):
        hbox = QHBoxLayout()
        hbox.addWidget(self.up_button)
        hbox.addWidget(self.path_edit)

        vbox = QVBoxLayout()
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addLayout(hbox)
        vbox.addWidget(self.tree)
        self.setLayout(vbox)

        self.tree.doubleClicked.connect(self.on_double_click)
        self.up_button.clicked.connect(self.go_up)

        # --- 新增：开启多选和右键菜单支持 ---
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)

    def on_double_click(self, index: QModelIndex):
        path = self.model.filePath(index)
        if self.model.isDir(index):
            self.tree.setRootIndex(index)
            self.path_edit.setText(path)

    def go_up(self):
        current_path = self.path_edit.text()
        parent_dir = QDir(current_path)
        if parent_dir.cdUp():
            new_path = parent_dir.absolutePath()
            self.tree.setRootIndex(self.model.index(new_path))
            self.path_edit.setText(new_path)

    # ==================== 右键菜单与功能实现 ====================
    def show_context_menu(self, pos):
        index = self.tree.indexAt(pos)
        menu = QMenu(self)

        new_folder_action = menu.addAction("新建文件夹")
        new_folder_action.triggered.connect(lambda *args: self.new_folder(index))

        new_file_action = menu.addAction("新建文件")
        new_file_action.triggered.connect(lambda *args: self.new_file(index))

        if index.isValid():
            menu.addSeparator()
            rename_action = menu.addAction("重命名")
            rename_action.triggered.connect(lambda *args: self.rename(index))

            del_action = menu.addAction("删除")
            del_action.triggered.connect(lambda *args: self.delete_items())

            menu.addSeparator()
            copy_action = menu.addAction("复制")
            copy_action.triggered.connect(lambda *args: self.copy_items())

            move_action = menu.addAction("移动")
            move_action.triggered.connect(lambda *args: self.move_items())

        if self.copy_paths or self.move_paths:
            menu.addSeparator()
            paste_action = menu.addAction("粘贴")
            paste_action.triggered.connect(lambda *args: self.paste_items(index))

        menu.exec(self.tree.mapToGlobal(pos))

    def new_file(self, index: QModelIndex):
        # 确定新建文件的目标目录
        if index.isValid() and self.model.isDir(index):
            target_dir = self.model.filePath(index)
        else:
            parent_dir = os.path.dirname(self.model.filePath(index)) if index.isValid() else self.model.filePath(
                self.tree.rootIndex())
            target_dir = parent_dir

        text, ok = QInputDialog.getText(self, "新建文件", "输入带有扩展名的文件名 (如 test.txt)")
        if ok and text:
            new_path = os.path.join(target_dir, text)
            try:
                # 在本地创建一个空文件
                with open(new_path, 'w', encoding='utf-8') as f:
                    pass
            except Exception as e:
                QMessageBox.warning(self, "失败", f"新建文件失败:\n{e}")

    def new_folder(self, index: QModelIndex):
        # 确定新建文件夹的目标目录
        if index.isValid() and self.model.isDir(index):
            target_dir = self.model.filePath(index)
        else:
            target_dir = self.model.filePath(self.tree.rootIndex())

        text, ok = QInputDialog.getText(self, "新建", "输入文件夹名")
        if ok and text:
            new_dir = os.path.join(target_dir, text)
            try:
                os.makedirs(new_dir, exist_ok=True)
            except Exception as e:
                QMessageBox.warning(self, "失败", f"新建文件夹失败:\n{e}")

    def rename(self, index: QModelIndex):
        old_path = self.model.filePath(index)
        old_name = self.model.fileName(index)
        text, ok = QInputDialog.getText(self, "重命名", "输入新的名称", QLineEdit.EchoMode.Normal, old_name)
        if ok and text and text != old_name:
            new_path = os.path.join(os.path.dirname(old_path), text)
            try:
                os.rename(old_path, new_path)
            except Exception as e:
                QMessageBox.warning(self, "失败", f"重命名失败:\n{e}")

    def delete_items(self):
        indexes = self.tree.selectionModel().selectedRows()
        if not indexes:
            return
        paths = [self.model.filePath(idx) for idx in indexes]

        text = "\n".join([os.path.basename(p) for p in paths])
        reply = QMessageBox.question(self, "删除", f"确认删除以下项 (不可恢复)？\n{text}\n",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            for path in paths:
                try:
                    if os.path.isdir(path):
                        shutil.rmtree(path)
                    else:
                        os.remove(path)
                except Exception as e:
                    QMessageBox.warning(self, "删除失败", f"{path} 删除失败:\n{e}")

    def copy_items(self):
        indexes = self.tree.selectionModel().selectedRows()
        self.copy_paths = [self.model.filePath(idx) for idx in indexes]
        self.move_paths.clear()

    def move_items(self):
        indexes = self.tree.selectionModel().selectedRows()
        self.move_paths = [self.model.filePath(idx) for idx in indexes]
        self.copy_paths.clear()

    def paste_items(self, index: QModelIndex):
        # 确定粘贴的目标目录
        if index.isValid() and self.model.isDir(index):
            target_dir = self.model.filePath(index)
        else:
            # 如果右击到了普通文件，或者在空白处右击，默认粘贴到它所在的同级目录/当前根目录
            parent_dir = os.path.dirname(self.model.filePath(index)) if index.isValid() else self.model.filePath(
                self.tree.rootIndex())
            target_dir = parent_dir

        failed_msgs = []

        if self.copy_paths:
            for path in self.copy_paths:
                try:
                    basename = os.path.basename(path)
                    dest = os.path.join(target_dir, basename)
                    # 处理同名文件/文件夹重叠
                    if os.path.exists(dest):
                        if os.path.isdir(path):
                            dest += " - 副本"
                        else:
                            base, ext = os.path.splitext(dest)
                            dest = f"{base} - 副本{ext}"

                    if os.path.isdir(path):
                        if dest.startswith(path):
                            failed_msgs.append(f"{basename} -> 不能复制到自身的子目录")
                            continue
                        shutil.copytree(path, dest)
                    else:
                        shutil.copy2(path, dest)
                except Exception as e:
                    failed_msgs.append(f"{os.path.basename(path)} -> {e}")

        elif self.move_paths:
            for path in self.move_paths:
                try:
                    dest = os.path.join(target_dir, os.path.basename(path))
                    if dest.startswith(path):
                        failed_msgs.append(f"{os.path.basename(path)} -> 不能移动到自身的子目录")
                        continue
                    shutil.move(path, target_dir)
                except Exception as e:
                    failed_msgs.append(f"{os.path.basename(path)} -> {e}")
            # 移动完成后清空剪贴板
            self.move_paths.clear()

        if failed_msgs:
            QMessageBox.warning(self, "部分操作失败", "以下项操作失败:\n" + "\n".join(failed_msgs))


class NumericSortItem(QStandardItem):
    """
    支持按数值排序的 QStandardItem
    """

    def __init__(self, text: str, sort_value: float):
        super().__init__(text)
        self.sort_value = sort_value

    def __lt__(self, other):
        if isinstance(other, NumericSortItem):
            return self.sort_value < other.sort_value
        return super().__lt__(other)


class RemoteFileWidget(QTreeView):
    # 【修改】：删除了原有的 new_file_msg 和 sub_file_msg
    current_folder_loaded_msg = Signal(list)
    path_change_msg = Signal(str)
    sub_folder_loaded_msg = Signal(QModelIndex, list)

    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(parent=sftp_tab_widget)
        self.sftp_tab_widget = sftp_tab_widget
        self.FILE_ICON = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)
        self.DIR_ICON = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        self.icon_provider = QFileIconProvider()
        self.icon_cache = {}

        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(["名称", "大小", "类型", "修改时间", "权限"])
        self.setModel(self.model)

        self.setHeaderHidden(False)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSortingEnabled(True)
        self.header().setSortIndicator(0, Qt.SortOrder.AscendingOrder)
        self.setColumnWidth(0, 200)

        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setExpandsOnDoubleClick(False)  # 关闭双击自动展开

        self.move_paths = []
        self.copy_paths = []
        self.info = sftp_tab_widget.info
        self.all_files_dict = dict()
        self.show_hidden = False
        self.external_watcher = ExternalEditorWatcher(self.info)
        self.init_ui()

    def init_ui(self):
        # 【修改】：绑定拉取当前文件夹内容的信号
        self.current_folder_loaded_msg.connect(self.add_new_file)
        self.doubleClicked.connect(self.double_item)
        self.expanded.connect(self.on_item_expanded)
        self.sub_folder_loaded_msg.connect(self.on_sub_folder_loaded)

        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.viewport().setAcceptDrops(True)

    def get_file_icon(self, filename: str):
        """获取系统关联的文件图标：通过真实创建临时文件来骗过系统获取图标"""
        # os.path.splitext 对于 ".gitignore" 或 "Dockerfile" 这种文件，切出来的 ext 是空的
        name, ext = os.path.splitext(filename)
        ext = ext.lower()

        # 如果有后缀名，则以后缀名作为缓存键（如 .cpp）
        # 如果没有后缀名（或者本身就是隐藏文件如 .gitignore），则以完整文件名作为缓存键
        cache_key = ext if ext else filename.lower()

        if cache_key not in self.icon_cache:
            # 在临时目录创建一个专属文件夹
            temp_dir = tempfile.mkdtemp(prefix="quickstfp_icon_")

            # 还原一个带精确后缀或精确文件名的文件
            temp_filename = f"dummy{cache_key}" if ext else cache_key
            temp_file_path = os.path.join(temp_dir, temp_filename)

            try:
                # 触摸 (Touch) 创建一个真实存在于硬盘上的空文件
                with open(temp_file_path, 'w', encoding='utf-8') as f:
                    pass

                # 此时文件真实存在，系统会老老实实交出它关联的图标
                icon = self.icon_provider.icon(QFileInfo(temp_file_path))

                # 存入缓存
                self.icon_cache[cache_key] = icon if not icon.isNull() else self.FILE_ICON
            except Exception:
                self.icon_cache[cache_key] = self.FILE_ICON
            finally:
                # 取完图标后立刻“毁尸灭迹”，不留垃圾文件
                try:
                    if os.path.exists(temp_file_path):
                        os.remove(temp_file_path)
                    if os.path.exists(temp_dir):
                        os.rmdir(temp_dir)
                except Exception:
                    pass

        return self.icon_cache[cache_key]

    def get_item_path(self, item: QStandardItem) -> str:
        path = item.data(Qt.ItemDataRole.UserRole)
        return path if path else self.info.realpath(item.text())

    def selectedItems(self):
        indexes = self.selectionModel().selectedIndexes()
        return [self.model.itemFromIndex(idx) for idx in indexes if idx.column() == 0]

    def set_menu(self):
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    def show_context_menu(self, pos):
        index = self.indexAt(pos)
        item = self.model.itemFromIndex(index) if index.isValid() else None

        context_menu = QMenu(self)
        makedir_action = context_menu.addAction("新建文件夹")
        new_file_action = context_menu.addAction("新文件")
        refresh_action = context_menu.addAction("刷新")
        makedir_action.triggered.connect(self.makedir)
        new_file_action.triggered.connect(self.new_file)
        refresh_action.triggered.connect(self.refresh)

        if item:
            # === 修改这里：区分内置和外部编辑器 ===
            edit_action = context_menu.addAction("内置编辑器打开")
            ext_edit_action = context_menu.addAction("外部程序编辑")
            del_action = context_menu.addAction("删除")
            move_action = context_menu.addAction("移动")
            copy_action = context_menu.addAction("复制")
            download_action = context_menu.addAction("下载")

            edit_action.triggered.connect(lambda: self.double_item(index))
            ext_edit_action.triggered.connect(lambda: self.open_external(index))
            del_action.triggered.connect(self.del_items)
            move_action.triggered.connect(self.move_items)
            copy_action.triggered.connect(self.copy_items)
            download_action.triggered.connect(self.download_items)

        def trigger_put(*args):
            self.put_items(item)

        def trigger_paste(*args):
            self.paste_items(item)

        if self.move_paths:
            context_menu.addAction("放置").triggered.connect(trigger_put)
        if self.copy_paths:
            context_menu.addAction("粘贴").triggered.connect(trigger_paste)

        if len(self.selectedItems()) == 1 and item:
            rename_action = context_menu.addAction("重命名")
            rename_action.triggered.connect(lambda: self.rename(item))

            chmod_action = context_menu.addAction("属性/权限")
            chmod_action.triggered.connect(lambda: self.change_permissions(item))

        context_menu.exec(self.mapToGlobal(pos))

    def open_external(self, index: QModelIndex):
        if index.column() != 0:
            index = index.siblingAtColumn(0)
        item = self.model.itemFromIndex(index)
        path = self.get_item_path(item)
        MAX_PREVIEW_SIZE = 5 * 1024 * 1024

        try:
            if self.info.is_file(path) and (not is_binary(path)):
                file_size = self.info.get_file_size(path)
                if file_size > MAX_PREVIEW_SIZE:
                    reply = QMessageBox.question(
                        self, "文件过大", f"文件较大（{file_size / 1024 / 1024:.2f} MB），建议直接下载，是否继续拉取？",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                    )
                    if reply == QMessageBox.StandardButton.No:
                        return

                # 获取文件文本并交由 ExternalEditorWatcher 处理
                text = self.info.read_file(path)
                self.external_watcher.open_in_external_editor(path, text)
            else:
                QMessageBox.warning(self, "无法编辑", "外部编辑目前仅支持文本代码文件。")
        except Exception as e:
            QMessageBox.warning(self, "操作失败", f"无法操作外部编辑器:\n{e}")

    # ==================== 核心修改：手动拉取与事件驱动 ====================
    def refresh(self):
        """完全清空当前列表，并调度后台协程拉取最新内容"""
        self.model.removeRows(0, self.model.rowCount())
        self.all_files_dict.clear()
        # 兼容 TransportTargetWidget 使用 abspath
        target_path = getattr(self, 'abspath', self.info.getcwd())
        asyncio.run_coroutine_threadsafe(self.fetch_current_dir(target_path), self.info.loop)

    async def fetch_current_dir(self, path: str):
        """在后台执行 scandir 网络请求"""
        try:
            entries = []
            async for entry in self.info.sftp.scandir(path):
                if entry.filename not in (".", ".."):
                    if not self.show_hidden and entry.filename.startswith("."):
                        continue
                    entries.append(entry)
            self.current_folder_loaded_msg.emit(entries)
        except Exception as e:
            print(f"拉取目录失败 (权限不足或路径不存在): {e}")

    def rename(self, item: QStandardItem) -> None:
        text, ok = QInputDialog.getText(self, "重命名", "输入新的文件名", QLineEdit.EchoMode.Normal, item.text())
        if ok and text:
            try:
                self.info.rename(item.text(), str(text))
                self.refresh()  # 操作成功后手动刷新
            except Exception as e:
                QMessageBox.warning(self, "失败", f"重命名失败:\n{e}")

    def makedir(self) -> None:
        text, ok = QInputDialog.getText(self, "新建", "输入文件夹名")
        if ok and text:
            try:
                self.info.makedirs(str(text))
                self.refresh()
            except Exception as e:
                QMessageBox.warning(self, "失败", f"新建文件夹失败:\n{e}")

    def new_file(self) -> None:
        text, ok = QInputDialog.getText(self, "新建", "输入文件名")
        if ok and text:
            try:
                self.info.save_file(str(text), "")
                self.refresh()
            except Exception as e:
                QMessageBox.warning(self, "失败", f"新建文件失败:\n{e}")

    def del_item(self, item: QStandardItem) -> None:
        src = self.get_item_path(item)
        try:
            self.info.del_file(src)

            # 【核心修复】：在 UI 中移除前，先保存它的文本名，防止 C++ 对象被销毁后访问报错
            item_name = item.text()

            # 删除成功后，从 UI 抹除这一行
            parent_item = item.parent()
            if parent_item:
                # 属于下拉展开的子文件/文件夹
                parent_item.removeRow(item.row())
            else:
                # 顶层节点
                self.model.removeRow(item.row())

            # 使用保存好的纯字符串进行字典清理
            if item_name in self.all_files_dict:
                self.all_files_dict.pop(item_name)

        except Exception as e:
            QMessageBox.warning(self, "失败", f"删除失败:\n{e}")

    # =======================================================================

    def get_target_dir(self, item: QStandardItem) -> str:
        """根据右键所在的 item，获取正确的粘贴/放置目标目录"""
        base_path = getattr(self, 'abspath', self.info.getcwd())
        if not item:
            return base_path

        index = item.index()
        type_item = self.model.itemFromIndex(index.siblingAtColumn(2))

        # 如果右键落在文件夹上，就放在这个文件夹内
        if type_item and type_item.text() == "文件夹":
            return self.get_item_path(item)
        else:
            # 如果落在文件上，就放在该文件所在的层级（父节点目录）
            parent_item = item.parent()
            if parent_item:
                return self.get_item_path(parent_item)
            else:
                return base_path

    def change_permissions(self, item: QStandardItem):
        path = self.get_item_path(item)
        try:
            current_perms = self.info.get_permissions(path)
            dialog = PermissionDialog(self, item.text(), current_perms)
            if dialog.exec() == QDialog.DialogCode.Accepted:
                new_perms = dialog.get_new_permissions()
                if new_perms != current_perms:
                    self.info.chmod(path, new_perms)
                    QMessageBox.information(self, "成功", f"【{item.text()}】权限修改成功！")
                    self.refresh()
        except Exception as e:
            QMessageBox.warning(self, "操作失败", f"无法获取或修改文件权限:\n{e}")

    def paste_items(self, target_item: QStandardItem = None) -> None:
        target_dir = self.get_target_dir(target_item)
        for old_path in self.copy_paths:
            self.info.copy_file(old_path, target_dir)
        self.copy_paths.clear()
        self.refresh()

    def put_items(self, target_item: QStandardItem = None) -> None:
        failed_msgs = []
        target_dir = self.get_target_dir(target_item)

        for moved_item, old_path in self.move_paths:
            # 取出 UI 节点所在的父层级用于恢复显示
            parent_idx = moved_item.parent().index() if moved_item.parent() else QModelIndex()
            try:
                self.info.move_file(old_path, target_dir)
                self.setRowHidden(moved_item.row(), parent_idx, False)
            except Exception as e:
                failed_msgs.append(f"{old_path} -> {str(e)}")
                self.setRowHidden(moved_item.row(), parent_idx, False)

        if failed_msgs:
            QMessageBox.warning(self, "移动失败", "以下文件移动失败，可能权限不足:\n" + "\n".join(failed_msgs))
        self.move_paths.clear()
        self.refresh()

    def download_items(self) -> None:
        for item in self.selectedItems():
            self.download_item(item)

    def download_item(self, item: QStandardItem) -> None:
        os.makedirs("tmp", exist_ok=True)
        self.sftp_tab_widget.transport_control_widget.get(self.get_item_path(item), "./tmp", 20)

    def del_items(self) -> None:
        text = "\n".join([item.text() for item in self.selectedItems()])
        reply = QMessageBox.question(self, "删除", f"确认删除:\n{text}\n",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            for item in self.selectedItems():
                self.del_item(item)

    def on_item_expanded(self, index: QModelIndex):
        name_index = index.siblingAtColumn(0)
        item = self.model.itemFromIndex(name_index)

        if not item or not item.hasChildren(): return
        child = item.child(0, 0)
        if child and child.text() == "加载中...":
            path = self.get_item_path(item)
            asyncio.run_coroutine_threadsafe(self.fetch_sub_dir(name_index, path), self.info.loop)

    async def fetch_sub_dir(self, parent_index: QModelIndex, path: str):
        try:
            entries = []
            async for entry in self.info.sftp.scandir(path):
                if entry.filename not in (".", ".."):
                    if not self.show_hidden and entry.filename.startswith("."):
                        continue
                    entries.append(entry)
            self.sub_folder_loaded_msg.emit(parent_index, entries)
        except Exception:
            self.sub_folder_loaded_msg.emit(parent_index, [])

    @Slot(QModelIndex, list)
    def on_sub_folder_loaded(self, parent_index: QModelIndex, entries: list):
        item = self.model.itemFromIndex(parent_index)
        if not item: return

        item.removeRows(0, item.rowCount())
        parent_path = self.get_item_path(item)

        entries.sort(key=lambda x: (x.attrs.type != 2, x.filename))

        for entry in entries:
            is_dir = (entry.attrs.type == 2)
            name_item = QStandardItem(entry.filename)
            # === 修改：如果是文件，去获取关联的系统外部程序图标 ===
            name_item.setIcon(self.DIR_ICON if is_dir else self.get_file_icon(entry.filename))
            full_path = f"{parent_path}/{entry.filename}".replace("//", "/")
            name_item.setData(full_path, Qt.ItemDataRole.UserRole)

            size_val = getattr(entry.attrs, 'size', 0)
            size_item = NumericSortItem("", -1) if is_dir else NumericSortItem(self.format_size(size_val), size_val)
            type_item = QStandardItem("文件夹" if is_dir else "文件")

            mtime_val = getattr(entry.attrs, 'mtime', 0)
            mtime_str = datetime.datetime.fromtimestamp(mtime_val).strftime('%Y-%m-%d %H:%M:%S') if mtime_val else ""
            mtime_item = NumericSortItem(mtime_str, mtime_val)

            perms_val = getattr(entry.attrs, 'permissions', 0)
            perm_str = stat.filemode(perms_val) if perms_val else ""
            perm_item = QStandardItem(perm_str)

            row_items = [name_item, size_item, type_item, mtime_item, perm_item]
            if is_dir:
                dummy = QStandardItem("加载中...")
                name_item.appendRow([dummy, QStandardItem(""), QStandardItem(""), QStandardItem(""), QStandardItem("")])

            item.appendRow(row_items)

    @Slot(list)
    def add_new_file(self, new_files: list):
        """收到最新目录拉取的结果后进行渲染"""
        for entry in new_files:
            filename = entry.filename
            if filename in self.all_files_dict:
                continue

            is_dir = (entry.attrs.type == 2)
            name_item = QStandardItem(filename)
            # === 修改：如果是文件，去获取关联的系统外部程序图标 ===
            name_item.setIcon(self.DIR_ICON if is_dir else self.get_file_icon(filename))

            # 兼容：如果设置了 abspath 说明是在 TargetWidget 里
            base_path = getattr(self, 'abspath', self.info.getcwd())
            full_path = f"{base_path}/{filename}".replace("//", "/")
            name_item.setData(full_path, Qt.ItemDataRole.UserRole)

            size_val = getattr(entry.attrs, 'size', 0)
            size_item = NumericSortItem("", -1) if is_dir else NumericSortItem(self.format_size(size_val), size_val)
            type_item = QStandardItem("文件夹" if is_dir else "文件")

            mtime_val = getattr(entry.attrs, 'mtime', 0)
            mtime_str = datetime.datetime.fromtimestamp(mtime_val).strftime('%Y-%m-%d %H:%M:%S') if mtime_val else ""
            mtime_item = NumericSortItem(mtime_str, mtime_val)

            perms_val = getattr(entry.attrs, 'permissions', 0)
            perm_str = stat.filemode(perms_val) if perms_val else ""
            perm_item = QStandardItem(perm_str)

            row_items = [name_item, size_item, type_item, mtime_item, perm_item]
            if is_dir:
                dummy = QStandardItem("加载中...")
                name_item.appendRow([dummy, QStandardItem(""), QStandardItem(""), QStandardItem(""), QStandardItem("")])
                self.model.insertRow(0, row_items)
            else:
                self.model.appendRow(row_items)

            self.all_files_dict[filename] = name_item

    @staticmethod
    def format_size(size: int) -> str:
        if not size: return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024: return f"{size:.2f} {unit}" if unit != 'B' else f"{size} B"
            size /= 1024
        return f"{size:.2f} PB"

    def double_item(self, index: QModelIndex):
        if index.column() != 0: index = index.siblingAtColumn(0)
        item = self.model.itemFromIndex(index)
        path = self.get_item_path(item)
        MAX_PREVIEW_SIZE = 5 * 1024 * 1024

        try:
            if self.info.is_file(path) and (not is_binary(path)):
                file_size = self.info.get_file_size(path)
                if file_size > MAX_PREVIEW_SIZE:
                    reply = QMessageBox.question(
                        self, "文件过大", f"文件较大（{file_size / 1024 / 1024:.2f} MB），是否下载？",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                    )
                    if reply == QMessageBox.StandardButton.Yes: self.download_item(item)
                    return
                text = self.info.read_file(path)
                edit = Edit(self, self.info.realpath(path), text)
                edit.show()
            else:
                self.path_change_msg.emit(self.info.realpath(path))
                self.info.chdir(path)
                self.refresh()  # 进入新目录后主动拉取刷新
        except Exception as e:
            QMessageBox.warning(self, "操作失败", f"无法操作:\n{e}")

    def move_items(self) -> None:
        for item in self.selectedItems():
            self.setRowHidden(item.row(), item.parent().index() if item.parent() else QModelIndex(), True)
            self.move_paths.append((item, self.get_item_path(item)))

    def copy_items(self) -> None:
        for item in self.selectedItems():
            self.copy_paths.append(self.get_item_path(item))

    # --- 拖拽与缩略图逻辑保持之前的增强版本即可 ---
    def startDrag(self, supportedActions):
        items = self.selectedItems()
        if not items: return
        drag = QDrag(self)
        mime_data = QMimeData()
        paths = [self.get_item_path(item) for item in items]
        encoded_data = json.dumps(paths).encode('utf-8')
        mime_data.setData("application/x-quickstfp-remote-paths", QByteArray(encoded_data))
        drag.setMimeData(mime_data)

        if len(items) == 1:
            item = items[0]
            pixmap = QPixmap(200, 30)
            pixmap.fill(Qt.GlobalColor.transparent)
            painter = QPainter(pixmap)
            icon = item.icon()
            if not icon.isNull(): icon.paint(painter, QRect(0, 5, 20, 20))
            painter.setPen(Qt.GlobalColor.black)
            painter.drawText(QRect(25, 5, 175, 20), Qt.AlignmentFlag.AlignVCenter, item.text())
            painter.end()
            drag.setPixmap(pixmap)
            drag.setHotSpot(QPoint(10, 15))
        else:
            text = f"移动 {len(items)} 个项目"
            pixmap = QPixmap(150, 30)
            pixmap.fill(Qt.GlobalColor.transparent)
            painter = QPainter(pixmap)
            painter.setBrush(Qt.GlobalColor.lightGray)
            painter.setPen(Qt.GlobalColor.NoPen)
            painter.drawRoundedRect(0, 0, 150, 30, 5, 5)
            painter.setPen(Qt.GlobalColor.black)
            painter.drawText(QRect(0, 0, 150, 30), Qt.AlignmentFlag.AlignCenter, text)
            painter.end()
            drag.setPixmap(pixmap)
            drag.setHotSpot(QPoint(75, 15))

        drag.exec(supportedActions)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls() or event.mimeData().hasFormat("application/x-quickstfp-remote-paths"):
            event.accept()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls() or event.mimeData().hasFormat("application/x-quickstfp-remote-paths"):
            event.accept()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
            urls = event.mimeData().urls()
            index = self.indexAt(event.position().toPoint())
            dst_path = self.info.getcwd()
            if index.isValid():
                item = self.model.itemFromIndex(index.siblingAtColumn(0))
                type_item = self.model.itemFromIndex(index.siblingAtColumn(2))
                if item and type_item and type_item.text() == "文件夹":
                    dst_path = self.get_item_path(item)
            for url in urls:
                local_path = url.toLocalFile()
                if local_path: self.sftp_tab_widget.transport_control_widget.put(local_path, dst_path, 20)
            self.refresh()

        elif event.mimeData().hasFormat("application/x-quickstfp-remote-paths"):
            event.accept()
            remote_paths = json.loads(
                event.mimeData().data("application/x-quickstfp-remote-paths").data().decode('utf-8'))

            index = self.indexAt(event.position().toPoint())

            # --- 【步骤 1：智能获取拖放的目标路径和 UI 节点】 ---
            dst_path = getattr(self, 'abspath', self.info.getcwd())
            target_ui_node = None  # None 代表目标是最外层（根目录）

            if index.isValid():
                item = self.model.itemFromIndex(index.siblingAtColumn(0))
                type_item = self.model.itemFromIndex(index.siblingAtColumn(2))
                if item and type_item and type_item.text() == "文件夹":
                    # 拖到了某个文件夹上
                    dst_path = self.get_item_path(item)
                    target_ui_node = item
                else:
                    # 拖到了普通文件上，和它放在同级目录
                    parent_item = item.parent() if item else None
                    if parent_item:
                        dst_path = self.get_item_path(parent_item)
                        target_ui_node = parent_item

            # --- 【步骤 2：执行移动并无缝转移 UI 节点（不刷新页面）】 ---
            for src_path in remote_paths:
                # 避免原位移动，以及避免移动到自身的子目录中
                if src_path != dst_path and not dst_path.startswith(src_path + "/"):
                    try:
                        self.info.move_file(src_path, dst_path)

                        # 找到界面中正在被拖拽的元素
                        for moved_item in self.selectedItems():
                            if self.get_item_path(moved_item) == src_path:
                                source_parent = moved_item.parent()
                                filename = src_path.split('/')[-1]

                                # 1. 从原位置“摘取”整行数据 (takeRow 会直接将其从原位置剥离)
                                if source_parent:
                                    row_items = source_parent.takeRow(moved_item.row())
                                else:
                                    row_items = self.model.takeRow(moved_item.row())

                                # 2. 更新底层绑定的路径数据为新的路径
                                new_full_path = f"{dst_path}/{filename}".replace("//", "/")
                                row_items[0].setData(new_full_path, Qt.ItemDataRole.UserRole)

                                # 3. 将摘下来的行插入到新目标位置
                                if target_ui_node:
                                    # 如果目标文件夹已经展开/加载过，则直接将节点塞进去显示
                                    first_child = target_ui_node.child(0, 0)
                                    if first_child and first_child.text() != "加载中...":
                                        target_ui_node.appendRow(row_items)
                                else:
                                    # 如果目标是最外层根目录，直接塞进根节点，并加入缓存
                                    self.model.appendRow(row_items)
                                    self.all_files_dict[filename] = row_items[0]

                                # 4. 清理旧缓存（如果文件从根目录移到了某个子目录里）
                                if not source_parent and target_ui_node:
                                    if filename in self.all_files_dict:
                                        self.all_files_dict.pop(filename)

                                break
                    except Exception as e:
                        QMessageBox.warning(self, "移动失败", f"{src_path} 移动失败:\n{e}")
        else:
            super().dropEvent(event)


class TransportTargetWidget(RemoteFileWidget):
    abspath: str = ""

    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(sftp_tab_widget)
        self.chdir(self.info.getcwd())

    def double_item(self, index: QModelIndex):
        item = self.model.itemFromIndex(index)
        path = item.text()
        try:
            # 这里的 info.is_file 可能会误判目标面板的状态，我们直接尝试 chdir 即可
            new_path = os.path.join(self.abspath, path).replace("\\", "/")
            self.chdir(new_path)
        except Exception as e:
            QMessageBox.warning(self, "访问失败", f"无法进入目标目录:\n{e}")

    def chdir(self, path: str):
        self.path_change_msg.emit(path)
        self.abspath = path
        # 只要目录变动，主动触发拉取更新 UI
        self.refresh()


class SelectRemoteFileWidget(QWidget):
    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(parent=sftp_tab_widget)
        self.transport_target_widget = TransportTargetWidget(sftp_tab_widget)
        self.vbox = QVBoxLayout()
        self.hbox = QHBoxLayout()
        self.back_button = QPushButton("<<")
        self.path_edit = QLineEdit(sftp_tab_widget.info.getcwd())
        self.select_button = QPushButton("选择")
        self.init_ui()

    def init_ui(self):
        self.hbox.addWidget(self.back_button)
        self.hbox.addWidget(self.path_edit)
        self.vbox.addLayout(self.hbox)
        self.vbox.addWidget(self.transport_target_widget)
        self.vbox.addWidget(self.select_button)
        self.setLayout(self.vbox)
        self.transport_target_widget.path_change_msg.connect(self.path_change)
        self.back_button.clicked.connect(self.back_parent_path)
        self.setWindowFlags(Qt.WindowType.Tool)

    @Slot(str)
    def path_change(self, path):
        self.path_edit.setText(path)

    def back_parent_path(self):
        path = self.get_parent_path(self.transport_target_widget.abspath)
        self.transport_target_widget.chdir(path)

    def select_target(self) -> str:
        items = self.transport_target_widget.selectedItems()
        if items:
            item = items[0]
            select_path = f"{self.transport_target_widget.abspath}/{item.text()}"
            return select_path
        path = self.transport_target_widget.abspath
        if path != '/':
            return path
        return ""

    @staticmethod
    def get_parent_path(path: str):
        new_path = os.path.dirname(path)
        return new_path.replace("\\", "/")


class UserSelectTargetWidget(QWidget):
    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(parent=sftp_tab_widget)
        self.sftp_tab_widget = sftp_tab_widget
        self.transport_control_widget = sftp_tab_widget.transport_control_widget
        self.form = QFormLayout()
        self.select_remote_file_widget = SelectRemoteFileWidget(sftp_tab_widget)
        self.src_edit = QLineEdit()
        self.dst_edit = QLineEdit()
        self.coro_num_label = QLabel("协程数量:20")
        self.coro_num_slider = QSlider(Qt.Orientation.Horizontal)
        self.speed_limit_spin = QSpinBox()
        self.speed_limit_spin.setRange(0, 999999)  # 单位 KB/s
        self.speed_limit_spin.setValue(0)
        self.speed_limit_spin.setSuffix(" KB/s (0为不限速)")
        self.src_button = QPushButton()
        self.src_dir_button = QPushButton()
        self.dst_button = QPushButton()
        self.transport_button = QPushButton("开始传输")
        self.init_ui()
        self.main()

    def init_ui(self):
        hbox = QHBoxLayout()
        hbox.addWidget(self.src_button)
        hbox.addWidget(self.src_dir_button)
        self.form.addRow(self.src_edit, hbox)
        self.form.addRow(self.dst_edit, self.dst_button)
        self.form.addRow(self.coro_num_label, self.coro_num_slider)
        self.form.addRow(QLabel("传输限速:"), self.speed_limit_spin)
        self.form.addRow(self.transport_button, QLabel())
        self.form.addRow(self.transport_button, QLabel())
        self.setLayout(self.form)
        self.src_edit.setReadOnly(True)
        self.dst_edit.setReadOnly(True)
        self.coro_num_slider.setRange(1, 1000)
        self.coro_num_slider.setValue(20)
        self.coro_num_slider.valueChanged.connect(lambda value: self.coro_num_label.setText(f"协程数量{value}"))
        self.setWindowFlags(Qt.WindowType.Tool)

    def main(self):
        pass


class UserSelectGetTargetWidget(UserSelectTargetWidget):
    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(sftp_tab_widget)

    def main(self):
        self.src_dir_button.setHidden(True)
        self.src_button.setText("选择远端文件")
        self.dst_button.setText("选择本地存储位置")
        self.src_button.clicked.connect(lambda: self.select_remote_file_widget.show())
        self.select_remote_file_widget.select_button.clicked.connect(self.select_file)
        self.transport_button.clicked.connect(self.start_get)
        self.dst_button.clicked.connect(self.get_local_file)

    def select_file(self):
        self.src_edit.setText(self.select_remote_file_widget.select_target())
        self.select_remote_file_widget.close()

    def get_local_file(self):
        file_path = QFileDialog.getExistingDirectory(self, "Open file")
        if file_path:
            self.dst_edit.setText(file_path)

    def start_get(self):
        if self.src_edit.text() and self.dst_edit.text():
            # 加上 self.speed_limit_spin.value()
            self.transport_control_widget.get(self.src_edit.text(), self.dst_edit.text(),
                                              self.coro_num_slider.value(),
                                              self.speed_limit_spin.value())
        else:
            QMessageBox.warning(self, "参数警告", "请把参数填完整")


class UserSelectPutTargetWidget(UserSelectTargetWidget):
    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(sftp_tab_widget)

    def main(self):
        self.src_button.setText("选择本地文件")
        self.src_dir_button.setText("选择本地文件夹")
        self.src_button.clicked.connect(self.get_local_file)
        self.src_dir_button.clicked.connect(self.get_local_dir)
        self.dst_button.setText("选择远端存储的位置")
        self.dst_button.clicked.connect(lambda: self.select_remote_file_widget.show())
        self.select_remote_file_widget.select_button.clicked.connect(self.select_file)
        self.transport_button.clicked.connect(self.start_put)

    def select_file(self):
        self.dst_edit.setText(self.select_remote_file_widget.select_target())
        self.select_remote_file_widget.close()

    def get_local_file(self):
        file_path = QFileDialog.getOpenFileName(self, "Open file")
        if file_path:
            self.src_edit.setText(file_path[0])

    def get_local_dir(self):
        file_path = QFileDialog.getExistingDirectory(self, "Open directory")
        if file_path:
            self.dst_edit.setText(file_path)

    def start_put(self):
        if self.src_edit.text() and self.dst_edit.text():
            # 加上 self.speed_limit_spin.value()
            self.transport_control_widget.put(self.src_edit.text(), self.dst_edit.text(),
                                              self.coro_num_slider.value(),
                                              self.speed_limit_spin.value())
            self.sftp_tab_widget.user_sftp_widget.remote_file_widget.refresh()
        else:
            QMessageBox.warning(self, "参数警告", "请把参数填完整")


class UserSFTPWidget(QWidget):
    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__()
        self.sftp_tab_widget = sftp_tab_widget
        self.info = sftp_tab_widget.info

        # --- 左侧：全新的本地文件面板 ---
        self.local_file_widget = LocalFileWidget(self.sftp_tab_widget)

        # --- 右侧：原有的远端文件面板 ---
        self.remote_file_widget = RemoteFileWidget(sftp_tab_widget)
        self.back_button = QPushButton("返回上级")

        # ---> 核心修改 1: 将 QLineEdit 改为可编辑的 QComboBox <---
        self.path_combo = QComboBox()
        self.path_combo.setEditable(True)  # 允许用户直接在框内输入路径

        # 初始化当前路径
        current_path = self.info.realpath(".")
        self.path_combo.addItem(current_path)
        self.path_combo.setCurrentText(current_path)

        self.get_button = QPushButton("下载选定")
        self.put_button = QPushButton("高级上传")

        self.show_hidden_btn = QPushButton("👁️ 显示隐藏")
        self.show_hidden_btn.setCheckable(True)

        self.init_ui()
        self.remote_file_widget.refresh()

    def init_ui(self):
        self.remote_file_widget.set_menu()
        self.remote_file_widget.path_change_msg.connect(self.display_path)

        # 组装右侧（远端）的顶栏
        remote_hbox = QHBoxLayout()
        remote_hbox.addWidget(self.back_button)
        remote_hbox.addWidget(self.path_combo)  # <--- 核心修改 2: 放到布局中

        remote_hbox.addWidget(self.show_hidden_btn)

        remote_hbox.addWidget(self.get_button)
        remote_hbox.addWidget(self.put_button)

        remote_vbox = QVBoxLayout()
        remote_vbox.setContentsMargins(0, 0, 0, 0)
        remote_vbox.addLayout(remote_hbox)
        remote_vbox.addWidget(self.remote_file_widget)

        remote_container = QWidget()
        remote_container.setLayout(remote_vbox)

        # QSplitter 组装左右布局
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.addWidget(self.local_file_widget)
        self.splitter.addWidget(remote_container)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 1)

        main_layout = QVBoxLayout()
        main_layout.addWidget(self.splitter)
        self.setLayout(main_layout)

        # 信号绑定
        self.back_button.clicked.connect(self.back_parent_path)
        self.get_button.clicked.connect(self.get)
        self.put_button.clicked.connect(self.put)

        # ---> 核心修改 3: 绑定 ComboBox 的激活信号（回车或点击下拉选项）<---
        self.path_combo.activated.connect(self.on_path_combo_activated)
        self.show_hidden_btn.toggled.connect(self.toggle_hidden_files)

    def on_path_combo_activated(self):
        """当用户在输入框按回车，或在下拉列表中选择历史路径时触发"""
        path = self.path_combo.currentText().strip()
        if not path:
            return
        try:
            # 尝试切换底层目录
            self.info.chdir(path)
            # 获取进入后的绝对路径
            real_path = self.info.realpath(".")
            # 强制清空当前视图，触发底层全量扫描以获得极速刷新体验
            self.remote_file_widget.refresh()
            self.display_path(real_path)
        except Exception as e:
            QMessageBox.warning(self, "访问失败", f"无法进入该目录:\n{e}")
            # 失败后，恢复输入框为当前的实际合法路径
            self.display_path(self.info.getcwd())

    def toggle_hidden_files(self, checked: bool):
        self.remote_file_widget.show_hidden = checked
        self.remote_file_widget.refresh()

    def get(self):
        get_target_widget = UserSelectGetTargetWidget(self.sftp_tab_widget)
        get_target_widget.show()

    def put(self):
        put_target_widget = UserSelectPutTargetWidget(self.sftp_tab_widget)
        put_target_widget.show()

    def back_parent_path(self):
        self.info.chdir("..")
        self.remote_file_widget.refresh()  # 返回上级时也强制刷新
        self.display_path(self.info.realpath("."))

    @Slot(str)
    def display_path(self, path: str):
        """当系统路径改变时，更新下拉框并沉淀历史记录"""
        self.path_combo.blockSignals(True)  # 暂时阻断信号，防止触发 activated 导致死循环

        # 如果路径不在历史记录里，则把它插入到最上面
        if self.path_combo.findText(path) == -1:
            self.path_combo.insertItem(0, path)

        self.path_combo.setCurrentText(path)
        self.path_combo.blockSignals(False)


class ControlWidget(QListWidget):
    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(parent=sftp_tab_widget)
        self.addItems(["SSH伪终端", "SFTP文件目录", "传输管理"])
        self.clicked.connect(lambda index: self.function[self.item(index.row()).text()]())
        self.function = {
            "SSH伪终端": lambda: sftp_tab_widget.stacked_widget.setCurrentIndex(0),
            "SFTP文件目录": lambda: sftp_tab_widget.stacked_widget.setCurrentIndex(1),
            "传输管理": lambda: sftp_tab_widget.stacked_widget.setCurrentIndex(2),
        }


class TransportControlWidget(QListWidget):
    """
    传输任务管理面板
    负责调度 core.transport 任务，并生成 UI 进度条组件进行显示。
    完全解耦：使用 Signal / Slot 机制与后端业务分离。
    """

    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(parent=sftp_tab_widget)
        self.FILE_ICON = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)
        self.DIR_ICON = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        self.info = sftp_tab_widget.info
        self.task_list = []

    def clear_finish_task(self):
        self.task_list = [t for t in self.task_list if not t.is_cancel]

    def _create_task_ui(self, pbar: ProgressBar, task):
        """通用方法：绑定任务的信号与 UI"""
        item = QListWidgetItem(self)
        item.setSizeHint(pbar.sizeHint())
        self.setItemWidget(item, pbar)
        self.addItem(item)

        # 绑定核心层信号 -> UI 组件
        task.progress_updated.connect(pbar.set_progress_value)
        task.range_initialized.connect(pbar.set_progress_range)
        task.transport_failed.connect(pbar.warning_transport_fail_filename)
        task.speed_updated.connect(pbar.set_speed_text)

        # 绑定 UI 操作 -> 核心层
        pbar.cancel_requested.connect(task.cancel)
        pbar.del_widget_msg.connect(lambda: self.takeItem(self.row(item)))

        # --- 新增：绑定 UI 的暂停信号到 Core 的控制阀门 ---
        pbar.pause_requested.connect(task.toggle_pause)

    def get(self, src: str, dst: str, coro_num: int, speed_limit: int = 0):
        self.clear_finish_task()
        icon = self.FILE_ICON if self.info.is_file(src) else self.DIR_ICON
        pbar = ProgressBar(src, "下载", icon)

        # 把 speed_limit 传给底层
        task = GET(src, dst, coro_num, speed_limit, self.info)
        self._create_task_ui(pbar, task)
        self.task_list.append(task)
        task()

    # 接收 speed_limit
    def put(self, src: str, dst: str, coro_num: int, speed_limit: int = 0):
        self.clear_finish_task()
        icon = self.FILE_ICON if os.path.isfile(src) else self.DIR_ICON
        pbar = ProgressBar(src, "上传", icon)

        # 把 speed_limit 传给底层
        task = PUT(src, dst, coro_num, speed_limit, self.info)
        self._create_task_ui(pbar, task)
        self.task_list.append(task)
        task()


class SFTPTabWidget(QWidget):
    """
    单个会话标签页的总控容器
    """

    def __init__(self, host: str, port: int, username: str, password: str = None, client_keys: list = None,
                 passphrase: str = None):
        super().__init__()
        self.splitter = QSplitter(Qt.Orientation.Horizontal)

        # 启动核心 Session
        self.info = SSHSFTPInfo(host, port, username, password, client_keys, passphrase)
        self.info.start()
        self.info.wait_for_connection()

        # 包含各项功能面板
        self.control_widget = ControlWidget(self)
        self.transport_control_widget = TransportControlWidget(self)
        self.user_sftp_widget = UserSFTPWidget(self)
        self.ssh_pty_widget = SSHPtyWidget(self.info)

        self.stacked_widget = QStackedWidget()
        self.hbox = QHBoxLayout(self)
        self.init_ui()

    def init_ui(self):
        # 组装面板
        self.stacked_widget.addWidget(self.ssh_pty_widget)
        self.stacked_widget.addWidget(self.user_sftp_widget)
        self.stacked_widget.addWidget(self.transport_control_widget)

        self.splitter.addWidget(self.control_widget)
        self.splitter.addWidget(self.stacked_widget)
        self.splitter.setStretchFactor(0, 0)
        self.splitter.setStretchFactor(1, 3)
        self.hbox.addWidget(self.splitter)
        self.setLayout(self.hbox)

    def closeEvent(self, event, /):
        super().closeEvent(event)

        # 使用新增加的优雅退出方法清理所有连接和挂起的 Task
        self.user_sftp_widget.remote_file_widget.external_watcher.cleanup_temp_files()
        self.info.close_session()

        # 退出 QThread
        self.info.quit()
        # 最多等待 3 秒给后台线程做清理收尾工作
        self.info.wait(3000)
