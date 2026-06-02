# ui/views/remote_file_widget.py
import os

from PySide6.QtCore import Qt, QModelIndex
from PySide6.QtGui import QStandardItem
from PySide6.QtWidgets import QMessageBox, QInputDialog, QLineEdit, QMenu, QDialog, QAbstractItemView

from core.session import SSHSFTPInfo
from core.transport import GET, PUT
from ui.components.progress_bar import ProgressBar
from ui.components.terminal_widget import SSHPtyWidget
from ui.views.editor_widgets import Edit, ExternalEditorWatcher, PermissionDialog
from ui.views.base_remote_tree import BaseRemoteTreeWidget, NumericSortItem
from ui.views.remote_drag_drop import RemoteDragDropMixin
from utils.file_utils import is_binary


class RemoteFileWidget(RemoteDragDropMixin, BaseRemoteTreeWidget):
    """
    完整的远端文件系统控件。
    附加了丰富的业务逻辑：外部编辑器、右键菜单、增删改查、以及本地到远端的拖拽等危险操作。
    """

    MAX_PREVIEW_SIZE = 5 * 1024 * 1024  # 5MB — 内置编辑器最大预览大小

    def __init__(self, sftp_tab_widget):
        super().__init__(sftp_tab_widget)

        self.move_paths = []
        self.copy_paths = []
        self.external_watcher = ExternalEditorWatcher(self.info)

        # 绑定当前类的独有操作
        self.doubleClicked.connect(self.double_item)

        # 开启拖放特性
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DragDrop)
        self.setDefaultDropAction(Qt.DropAction.MoveAction)
        self.viewport().setAcceptDrops(True)

        self.set_menu()

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

        try:
            if self.info.is_file(path) and (not is_binary(path)):
                file_size = self.info.get_file_size(path)
                if file_size > self.MAX_PREVIEW_SIZE:
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

            # 在 UI 中移除前，先保存它的文本名，防止 C++ 对象被销毁后访问报错
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

    def double_item(self, index: QModelIndex):
        if index.column() != 0: index = index.siblingAtColumn(0)
        item = self.model.itemFromIndex(index)
        path = self.get_item_path(item)

        try:
            if self.info.is_file(path) and (not is_binary(path)):
                file_size = self.info.get_file_size(path)
                if file_size > self.MAX_PREVIEW_SIZE:
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



