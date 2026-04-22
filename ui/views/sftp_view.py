# ui/views/sftp_view.py
import asyncio
import datetime
import os
import stat

from PySide6.QtCore import Qt, QModelIndex, Signal, Slot, QDir
from PySide6.QtGui import QCloseEvent
from PySide6.QtGui import QStandardItemModel, QStandardItem
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


class MonitorRemoteFileChange:
    def __init__(self, remote_file_widget: 'RemoteFileWidget'):
        super().__init__()
        self.remote_file_widget = remote_file_widget
        self.sftp = remote_file_widget.info.sftp
        self.loop = remote_file_widget.info.loop
        self.new_file_msg = remote_file_widget.new_file_msg
        self.sub_file_msg = remote_file_widget.sub_file_msg
        self.now_remote_path = "."

        # 新增：用于记录上一次扫描时目录的修改时间
        self.last_mtime = None

    async def check_file_changes(self):
        """合并新文件和旧文件的检查，并使用 stat 优化网络 I/O"""
        while True:
            try:
                # 1. 轻量级检查：只获取当前目录本身的元数据
                dir_attrs = await self.sftp.stat(self.now_remote_path)
                current_mtime = dir_attrs.mtime

                # 如果目录修改时间没变，说明没有文件增删，直接跳过本次完整扫描
                if self.last_mtime == current_mtime:
                    await asyncio.sleep(1)
                    continue

                self.last_mtime = current_mtime

                # 2. 只有时间变化时，才发起高成本的 scandir
                now_file_entries = []
                async for entry in self.sftp.scandir(self.now_remote_path):
                    if entry.filename not in (".", ".."):
                        if not self.remote_file_widget.show_hidden and entry.filename.startswith("."):
                            continue
                        now_file_entries.append(entry)

                now_filenames = {entry.filename for entry in now_file_entries}
                known_filenames = set(self.remote_file_widget.all_files_dict.keys())

                # 3. 集合运算：计算新增的文件
                new_files = [e for e in now_file_entries if e.filename not in known_filenames]
                if new_files:
                    self.new_file_msg.emit(new_files)

                # 4. 集合运算：计算被删除的文件
                sub_files = list(known_filenames - now_filenames)
                if sub_files:
                    self.sub_file_msg.emit(sub_files)

            except Exception:
                # 捕获异常：防止在切换目录 (chdir) 瞬间导致路径不存在而抛出异常崩溃
                self.last_mtime = None

            # 建议将此处稍微提高至 1.5 - 2 秒，肉眼感知的实时性差异不大，但能大幅降低压力
            await asyncio.sleep(1)

    def start(self):
        # 原本启动两个独立的任务，现在只需要启动合并后的单任务
        asyncio.run_coroutine_threadsafe(self.check_file_changes(), self.loop)


class Edit(QTextEdit):
    def __init__(self, remote_file_widget: 'RemoteFileWidget', path: str, text: str):
        super().__init__(parent=remote_file_widget)
        self.path = path
        self.info = remote_file_widget.info
        self.original_text = text
        self.setText(text)
        self.setWindowFlags(Qt.WindowType.Tool)

    def closeEvent(self, event: QCloseEvent):
        now_text = self.toPlainText()
        if now_text == self.original_text:
            return
        reply = QMessageBox.question(self, "文件", "文件有改动，是否保存",
                                     QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
        if reply == QMessageBox.StandardButton.Ok:
            self.info.save_file(self.path, now_text)


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
    使用 QFileSystemModel 自动加载系统文件，并支持将其拖拽出去。
    """

    def __init__(self):
        super().__init__()
        # 1. 初始化本地文件系统模型
        self.model = QFileSystemModel()
        self.model.setRootPath(QDir.rootPath())

        # 2. 初始化树形视图
        self.tree = QTreeView()
        self.tree.setModel(self.model)
        # 默认从用户的家目录开始显示 (Windows 是 C:\Users\xxx, Mac/Linux 是 /home/xxx)
        self.tree.setRootIndex(self.model.index(QDir.homePath()))

        # 开启拖拽支持：允许将本地文件直接拖拽出去
        self.tree.setDragEnabled(True)

        # 优化显示：隐藏多余的列，只保留文件名（类似于只看名字），如果你想看大小和修改日期，可以注释掉下面这行
        for i in range(1, 4): self.tree.hideColumn(i)

        # 3. 顶部路径与控制栏
        self.path_edit = QLineEdit(QDir.homePath())
        self.path_edit.setReadOnly(True)
        self.up_button = QPushButton("返回上级")

        self.init_ui()

    def init_ui(self):
        # 布局组装
        hbox = QHBoxLayout()
        hbox.addWidget(self.up_button)
        hbox.addWidget(self.path_edit)

        vbox = QVBoxLayout()
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addLayout(hbox)
        vbox.addWidget(self.tree)
        self.setLayout(vbox)

        # 信号连接
        self.tree.doubleClicked.connect(self.on_double_click)
        self.up_button.clicked.connect(self.go_up)

    def on_double_click(self, index: QModelIndex):
        """双击文件夹时，进入该文件夹"""
        path = self.model.filePath(index)
        if self.model.isDir(index):
            self.tree.setRootIndex(index)
            self.path_edit.setText(path)

    def go_up(self):
        """返回上一级目录"""
        current_path = self.path_edit.text()
        parent_dir = QDir(current_path)
        if parent_dir.cdUp():
            new_path = parent_dir.absolutePath()
            self.tree.setRootIndex(self.model.index(new_path))
            self.path_edit.setText(new_path)


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
    new_file_msg = Signal(list)
    sub_file_msg = Signal(list)
    path_change_msg = Signal(str)
    sub_folder_loaded_msg = Signal(QModelIndex, list)

    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(parent=sftp_tab_widget)
        self.sftp_tab_widget = sftp_tab_widget
        self.FILE_ICON = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)
        self.DIR_ICON = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)

        # --- 使用标准数据模型绑定 QTreeView ---
        self.model = QStandardItemModel()
        # 修改 1：添加多列表头
        self.model.setHorizontalHeaderLabels(["名称", "大小", "类型", "修改时间", "权限"])
        self.setModel(self.model)

        # 取消隐藏表头（如果原来隐藏了的话）
        self.setHeaderHidden(False)

        # 修改 2：恢复整行选中，体验更好
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

        # 修改 3：开启表头点击排序功能，默认按第一列(名称)升序排
        self.setSortingEnabled(True)
        self.header().setSortIndicator(0, Qt.SortOrder.AscendingOrder)

        # 让“名称”列的宽度稍微大一点
        self.setColumnWidth(0, 200)

        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        self.move_paths = []
        self.copy_paths = []
        self.info = sftp_tab_widget.info
        self.all_files_dict = dict()
        self.show_hidden = False
        self.monitor = MonitorRemoteFileChange(self)
        self.init_ui()

    def get_item_path(self, item: QStandardItem) -> str:
        """从 UserRole 中提取之前存入的绝对路径"""
        path = item.data(Qt.ItemDataRole.UserRole)
        return path if path else self.info.realpath(item.text())

    def selectedItems(self):
        """兼容底层原有的多选获取逻辑"""
        indexes = self.selectionModel().selectedIndexes()
        # 过滤掉其他列，只返回第一列的 Item
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
            edit_action = context_menu.addAction("打开")
            del_action = context_menu.addAction("删除")
            move_action = context_menu.addAction("移动")
            copy_action = context_menu.addAction("复制")
            download_action = context_menu.addAction("下载")
            edit_action.triggered.connect(lambda: self.double_item(index))
            del_action.triggered.connect(self.del_items)
            move_action.triggered.connect(self.move_items)
            copy_action.triggered.connect(self.copy_items)
            download_action.triggered.connect(self.download_items)

        if self.move_paths:
            context_menu.addAction("放置").triggered.connect(self.put_items)
        if self.copy_paths:
            context_menu.addAction("粘贴").triggered.connect(self.paste_items)

        if len(self.selectedItems()) == 1 and item:
            rename_action = context_menu.addAction("重命名")
            rename_action.triggered.connect(lambda: self.rename(item))

            # 高级属性修改
            chmod_action = context_menu.addAction("属性/权限")
            chmod_action.triggered.connect(lambda: self.change_permissions(item))

        context_menu.exec(self.mapToGlobal(pos))

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
        except Exception as e:
            QMessageBox.warning(self, "操作失败", f"无法获取或修改文件权限:\n{e}")

    def refresh(self):
        self.model.removeRows(0, self.model.rowCount())
        self.all_files_dict.clear()
        self.monitor.last_mtime = None

    def rename(self, item: QStandardItem) -> None:
        text, ok = QInputDialog.getText(self, "重命名", "输入新的文件名")
        if ok:
            self.info.rename(item.text(), str(text))

    def paste_items(self) -> None:
        for old_path in self.copy_paths:
            self.info.copy_file(old_path, self.info.getcwd())
        self.copy_paths.clear()

    def put_items(self) -> None:
        failed_msgs = []
        for item, old_path in self.move_paths:
            try:
                self.info.move_file(old_path, self.info.getcwd())
                self.setRowHidden(item.row(), QModelIndex(), False)  # 取消隐藏
            except Exception as e:
                failed_msgs.append(f"{old_path} -> {str(e)}")
                self.setRowHidden(item.row(), QModelIndex(), False)  # 移动失败也取消隐藏

        if failed_msgs:
            error_details = "\n".join(failed_msgs)
            QMessageBox.warning(self, "移动失败", f"以下文件移动失败，可能权限不足:\n{error_details}")

        self.move_paths.clear()

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

    def del_item(self, item: QStandardItem) -> None:
        src = self.get_item_path(item)  # 替换
        self.info.del_file(src)

    def makedir(self) -> None:
        text, ok = QInputDialog.getText(self, "新建", "输入文件夹名")
        if ok:
            self.info.makedirs(str(text))

    def new_file(self) -> None:
        text, ok = QInputDialog.getText(self, "新建", "输入文件名")
        if ok:
            self.info.save_file(str(text), "")

    def init_ui(self):
        self.new_file_msg.connect(self.add_new_file)
        self.sub_file_msg.connect(self.del_sub_file)
        self.doubleClicked.connect(self.double_item)
        self.expanded.connect(self.on_item_expanded)
        self.sub_folder_loaded_msg.connect(self.on_sub_folder_loaded)

        self.monitor.start()
        self.monitor.start()

        # 开启拖放支持
        self.setAcceptDrops(True)
        self.viewport().setAcceptDrops(True)

    def on_item_expanded(self, index: QModelIndex):
        """当用户点击树形目录的展开箭头时触发"""
        name_index = index.siblingAtColumn(0)
        item = self.model.itemFromIndex(name_index)

        if not item or not item.hasChildren():
            return

        # 检查是否是占位符
        child = item.child(0, 0)
        if child and child.text() == "加载中...":
            path = self.get_item_path(item)
            # 调度到 asyncssh 的事件循环中异步获取远端文件，防止阻塞 UI
            asyncio.run_coroutine_threadsafe(self.fetch_sub_dir(name_index, path), self.info.loop)

    async def fetch_sub_dir(self, parent_index: QModelIndex, path: str):
        """后台异步执行远端 scandir 操作"""
        try:
            entries = []
            async for entry in self.info.sftp.scandir(path):
                if entry.filename not in (".", ".."):
                    # 兼容隐藏文件过滤开关
                    if hasattr(self, 'show_hidden') and not self.show_hidden and entry.filename.startswith("."):
                        continue
                    entries.append(entry)
            self.sub_folder_loaded_msg.emit(parent_index, entries)
        except Exception as e:
            # 权限不足等错误时返回空列表
            self.sub_folder_loaded_msg.emit(parent_index, [])

    @Slot(QModelIndex, list)
    def on_sub_folder_loaded(self, parent_index: QModelIndex, entries: list):
        """拿到后台数据后，在主线程更新 UI 树节点"""
        item = self.model.itemFromIndex(parent_index)
        if not item: return

        # 清除“加载中...”占位符
        item.removeRows(0, item.rowCount())
        parent_path = self.get_item_path(item)

        # 对子文件进行排序：文件夹优先，同类按名称排序
        entries.sort(key=lambda x: (x.attrs.type != 2, x.filename))

        for entry in entries:
            is_dir = (entry.attrs.type == 2)
            name_item = QStandardItem(entry.filename)
            name_item.setIcon(self.DIR_ICON if is_dir else self.FILE_ICON)

            # --- 关键：保存该文件的绝对路径，防止多级目录路径错乱 ---
            full_path = f"{parent_path}/{entry.filename}".replace("//", "/")
            name_item.setData(full_path, Qt.ItemDataRole.UserRole)

            # [构建其他列：结合之前多列表头的方案]
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

            # 如果依然是文件夹，给它塞入下一级“加载中...”占位符，支持无限套娃展开
            if is_dir:
                dummy = QStandardItem("加载中...")
                name_item.appendRow([dummy, QStandardItem(""), QStandardItem(""), QStandardItem(""), QStandardItem("")])

            item.appendRow(row_items)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
            urls = event.mimeData().urls()
            for url in urls:
                local_path = url.toLocalFile()
                if local_path:
                    self.sftp_tab_widget.transport_control_widget.put(
                        local_path, self.info.getcwd(), 20
                    )
        else:
            super().dropEvent(event)

    @Slot(list)
    def add_new_file(self, new_files: list):
        for entry in new_files:
            filename = entry.filename
            if filename in self.all_files_dict:
                continue

            is_dir = (entry.attrs.type == 2)

            # 第1列: 名称
            name_item = QStandardItem(filename)
            name_item.setIcon(self.DIR_ICON if is_dir else self.FILE_ICON)

            full_path = self.info.realpath(filename)
            name_item.setData(full_path, Qt.ItemDataRole.UserRole)

            # 第2列: 大小 (使用自定义数字排序 Item)
            size_val = getattr(entry.attrs, 'size', 0)
            if is_dir:
                size_item = NumericSortItem("", -1)  # 文件夹大小置空，排序值设为-1置顶/沉底
            else:
                size_item = NumericSortItem(self.format_size(size_val), size_val)

            # 第3列: 类型
            type_item = QStandardItem("文件夹" if is_dir else "文件")

            # 第4列: 修改时间 (使用自定义数字排序 Item，按照时间戳排序)
            mtime_val = getattr(entry.attrs, 'mtime', 0)
            mtime_str = datetime.datetime.fromtimestamp(mtime_val).strftime('%Y-%m-%d %H:%M:%S') if mtime_val else ""
            mtime_item = NumericSortItem(mtime_str, mtime_val)

            # 第5列: 权限 (将十进制 mode 转换为标准的 rwxrwxrwx)
            perms_val = getattr(entry.attrs, 'permissions', 0)
            perm_str = stat.filemode(perms_val) if perms_val else ""
            perm_item = QStandardItem(perm_str)

            # 组装为一行
            row_items = [name_item, size_item, type_item, mtime_item, perm_item]

            if is_dir:
                # ---> 新增：添加占位符提供下拉箭头
                dummy = QStandardItem("加载中...")
                name_item.appendRow([dummy, QStandardItem(""), QStandardItem(""), QStandardItem(""), QStandardItem("")])
                self.model.insertRow(0, row_items)
            else:
                self.model.appendRow(row_items)

            self.all_files_dict[filename] = name_item

    @staticmethod
    def format_size(size: int) -> str:
        """字节转换为高可读性的单位"""
        if not size: return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024:
                return f"{size:.2f} {unit}" if unit != 'B' else f"{size} B"
            size /= 1024
        return f"{size:.2f} PB"

    @Slot(list)
    def del_sub_file(self, sub_files: list):
        for file in sub_files:
            if file not in self.all_files_dict:
                continue
            item = self.all_files_dict[file]
            self.model.removeRow(item.row())
            self.all_files_dict.pop(file)

    def double_item(self, index: QModelIndex):
        if index.column() != 0:
            index = index.siblingAtColumn(0)
        item = self.model.itemFromIndex(index)

        # ---> 替换获取路径的方式
        path = self.get_item_path(item)
        MAX_PREVIEW_SIZE = 5 * 1024 * 1024

        try:
            if self.info.is_file(path) and (not is_binary(path)):
                file_size = self.info.get_file_size(path)
                if file_size > MAX_PREVIEW_SIZE:
                    reply = QMessageBox.question(
                        self, "文件过大",
                        f"该文本文件体积较大（{file_size / 1024 / 1024:.2f} MB），直接在编辑器预览可能导致程序内存溢出或卡死。\n\n是否将其下载到本地查看？",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                    )
                    if reply == QMessageBox.StandardButton.Yes:
                        self.download_item(item)
                    return
                text = self.info.read_file(path)
                edit = Edit(self, self.info.realpath(path), text)
                edit.show()
            else:
                self.path_change_msg.emit(self.info.realpath(path))
                self.info.chdir(path)
        except Exception as e:
            QMessageBox.warning(self, "操作失败", f"无法打开文件或进入该目录。\n错误信息: {e}")

    def move_items(self) -> None:
        for item in self.selectedItems():
            self.move_item(item)

    def move_item(self, item: QStandardItem) -> None:
        self.setRowHidden(item.row(), item.parent().index() if item.parent() else QModelIndex(), True)
        self.move_paths.append((item, self.get_item_path(item)))  # 替换

    def copy_items(self) -> None:
        for item in self.selectedItems():
            self.copy_item(item)

    def copy_item(self, item: QStandardItem) -> None:
        self.copy_paths.append(self.get_item_path(item))  # 替换


class TransportTargetWidget(RemoteFileWidget):
    abspath: str = ""

    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__(sftp_tab_widget)
        self.chdir(self.info.getcwd())

    def double_item(self, index: QModelIndex):
        item = self.model.itemFromIndex(index)  # <--- 修改这一行即可
        path = item.text()
        try:
            if not self.info.is_file(path):
                new_path = os.path.join(self.abspath, path).replace("\\", "/")
                self.chdir(new_path)
        except Exception as e:
            QMessageBox.warning(self, "访问失败", f"无法进入目标目录:\n{e}")

    def chdir(self, path: str):
        self.path_change_msg.emit(path)
        self.abspath = path
        self.monitor.now_remote_path = path


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
        else:
            QMessageBox.warning(self, "参数警告", "请把参数填完整")


class UserSFTPWidget(QWidget):
    def __init__(self, sftp_tab_widget: 'SFTPTabWidget'):
        super().__init__()
        self.sftp_tab_widget = sftp_tab_widget
        self.info = sftp_tab_widget.info

        # --- 左侧：全新的本地文件面板 ---
        self.local_file_widget = LocalFileWidget()

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
        self.info.close_session()

        # 退出 QThread
        self.info.quit()
        # 最多等待 3 秒给后台线程做清理收尾工作
        self.info.wait(3000)
