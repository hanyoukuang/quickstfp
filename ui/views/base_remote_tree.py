# ui/views/base_remote_tree.py
import asyncio
import datetime
import logging
import os
import stat

from PySide6.QtCore import QFileInfo
from PySide6.QtCore import Qt, QModelIndex, Signal, Slot
from PySide6.QtGui import QStandardItemModel, QStandardItem
from PySide6.QtWidgets import QFileIconProvider
from PySide6.QtWidgets import QTreeView, QStyle, QApplication, QAbstractItemView

logger = logging.getLogger(__name__)


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


class BaseRemoteTreeWidget(QTreeView):
    """
    远端文件树的基础视图组件 (白板容器)。
    仅负责网络通信拉取数据、解析属性、渲染树状 UI 节点。
    没有任何业务操作（无右键菜单、无拖拽、无删除编辑）。
    """
    current_folder_loaded_msg = Signal(list)
    path_change_msg = Signal(str)
    sub_folder_loaded_msg = Signal(QModelIndex, list)

    def __init__(self, sftp_tab_widget):
        super().__init__(parent=sftp_tab_widget)
        self.sftp_tab_widget = sftp_tab_widget
        self.info = sftp_tab_widget.info

        # 图标相关
        self.FILE_ICON = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_FileIcon)
        self.DIR_ICON = QApplication.style().standardIcon(QStyle.StandardPixmap.SP_DirIcon)
        self.icon_provider = QFileIconProvider()
        self.icon_cache = {}

        # 数据模型初始化
        self.model = QStandardItemModel()
        self.model.setHorizontalHeaderLabels(["名称", "大小", "类型", "修改时间", "权限"])
        self.setModel(self.model)

        # 视图属性
        self.setHeaderHidden(False)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSortingEnabled(True)
        self.header().setSortIndicator(0, Qt.SortOrder.AscendingOrder)
        self.setColumnWidth(0, 200)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setExpandsOnDoubleClick(False)

        # 状态缓存
        self.all_files_dict = dict()
        self.show_hidden = False

        self.init_base_ui()

    def init_base_ui(self):
        self.current_folder_loaded_msg.connect(self.add_new_file)
        self.expanded.connect(self.on_item_expanded)
        self.sub_folder_loaded_msg.connect(self.on_sub_folder_loaded)

    def get_file_icon(self, filename: str):
        """获取系统关联的文件图标"""
        name, ext = os.path.splitext(filename)
        ext = ext.lower()
        cache_key = ext if ext else filename

        if cache_key not in self.icon_cache:
            if ext:
                icon = self.icon_provider.icon(QFileInfo(f"_.{ext[1:]}"))
            else:
                icon = self.icon_provider.icon(QFileInfo(filename))
            self.icon_cache[cache_key] = self.FILE_ICON if icon.isNull() else icon
        return self.icon_cache[cache_key]

    def get_item_path(self, item: QStandardItem) -> str:
        path = item.data(Qt.ItemDataRole.UserRole)
        return path if path else self.info.realpath(item.text())

    def selectedItems(self):
        indexes = self.selectionModel().selectedIndexes()
        return [self.model.itemFromIndex(idx) for idx in indexes if idx.column() == 0]

    # ==================== 网络拉取与渲染核心 ====================

    def refresh(self):
        """全量拉取刷新当前列表"""
        self.model.removeRows(0, self.model.rowCount())
        self.all_files_dict.clear()
        target_path = getattr(self, 'abspath', self.info.getcwd())
        asyncio.run_coroutine_threadsafe(self.fetch_current_dir(target_path), self.info.loop)

    def search(self, keyword: str):
        """搜索远端文件"""
        self.model.removeRows(0, self.model.rowCount())
        self.all_files_dict.clear()
        target_path = getattr(self, 'abspath', self.info.getcwd())
        asyncio.run_coroutine_threadsafe(self.fetch_search_results(target_path, keyword), self.info.loop)

    async def fetch_search_results(self, path: str, keyword: str):
        try:
            cmd = f'cd "{path}" && find . -iname "*{keyword}*" 2>/dev/null'
            result = await self.info.connection.run(cmd)
            stdout = result.stdout
            if not stdout:
                self.current_folder_loaded_msg.emit([])
                return
            lines = [line.strip() for line in stdout.split('\n') if line.strip() and line.strip() != '.'][:100]

            async def get_entry(line_path):
                clean_name = line_path[2:] if line_path.startswith("./") else line_path
                full_path = f"{path}/{clean_name}".replace("//", "/")
                try:
                    attrs = await self.info.sftp.stat(full_path)

                    class SearchEntry:
                        def __init__(self, name, a):
                            self.filename, self.attrs = name, a

                    return SearchEntry(clean_name, attrs)
                except Exception:
                    return None

            tasks = [get_entry(line) for line in lines]
            results = await asyncio.gather(*tasks)
            self.current_folder_loaded_msg.emit([r for r in results if r])
        except Exception as e:
            logger.warning(f"搜索远端文件失败: {e}")
            self.current_folder_loaded_msg.emit([])

    async def fetch_current_dir(self, path: str):
        try:
            entries = []
            async for entry in self.info.sftp.scandir(path):
                if entry.filename not in (".", ".."):
                    if not self.show_hidden and entry.filename.startswith("."): continue
                    entries.append(entry)
            self.current_folder_loaded_msg.emit(entries)
        except Exception as e:
            logger.warning(f"拉取目录失败: {e}")

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
                    if not self.show_hidden and entry.filename.startswith("."): continue
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
            perm_item = QStandardItem(stat.filemode(perms_val) if perms_val else "")

            row_items = [name_item, size_item, type_item, mtime_item, perm_item]
            if is_dir:
                name_item.appendRow(
                    [QStandardItem("加载中..."), QStandardItem(""), QStandardItem(""), QStandardItem(""),
                     QStandardItem("")])
            item.appendRow(row_items)

    @Slot(list)
    def add_new_file(self, new_files: list):
        for entry in new_files:
            filename = entry.filename
            if filename in self.all_files_dict: continue

            is_dir = (entry.attrs.type == 2)
            name_item = QStandardItem(filename)
            name_item.setIcon(self.DIR_ICON if is_dir else self.get_file_icon(filename))

            base_path = getattr(self, 'abspath', self.info.getcwd())
            name_item.setData(f"{base_path}/{filename}".replace("//", "/"), Qt.ItemDataRole.UserRole)

            size_val = getattr(entry.attrs, 'size', 0)
            size_item = NumericSortItem("", -1) if is_dir else NumericSortItem(self.format_size(size_val), size_val)
            type_item = QStandardItem("文件夹" if is_dir else "文件")

            mtime_val = getattr(entry.attrs, 'mtime', 0)
            mtime_str = datetime.datetime.fromtimestamp(mtime_val).strftime('%Y-%m-%d %H:%M:%S') if mtime_val else ""
            mtime_item = NumericSortItem(mtime_str, mtime_val)

            perms_val = getattr(entry.attrs, 'permissions', 0)
            perm_item = QStandardItem(stat.filemode(perms_val) if perms_val else "")

            row_items = [name_item, size_item, type_item, mtime_item, perm_item]
            if is_dir:
                name_item.appendRow(
                    [QStandardItem("加载中..."), QStandardItem(""), QStandardItem(""), QStandardItem(""),
                     QStandardItem("")])
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
