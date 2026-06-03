# ui/views/local_widgets.py
import json
import os
import shutil

from PySide6.QtCore import Qt, QModelIndex, QDir
from PySide6.QtWidgets import QTreeView, QWidget, QHBoxLayout, QVBoxLayout, QLineEdit, QPushButton, \
    QAbstractItemView, QFileSystemModel, QMenu, QInputDialog, QMessageBox


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


class LocalFileWidget(QWidget):
    """
    本地文件系统浏览器。
    已适配本地文件内部拖动，并接收远端文件的下载拖放，新增本地右键菜单功能。
    """

    def __init__(self, sftp_tab_widget):
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
        self.up_button = QPushButton("⬆️ 返回上级")

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

        new_folder_action = menu.addAction("📁 新建文件夹")
        new_folder_action.triggered.connect(lambda *args: self.new_folder(index))

        new_file_action = menu.addAction("📄 新建文件")
        new_file_action.triggered.connect(lambda *args: self.new_file(index))

        if index.isValid():
            menu.addSeparator()
            rename_action = menu.addAction("✏️ 重命名")
            rename_action.triggered.connect(lambda *args: self.rename(index))

            del_action = menu.addAction("🗑️ 删除")
            del_action.triggered.connect(lambda *args: self.delete_items())

            menu.addSeparator()
            copy_action = menu.addAction("📋 复制")
            copy_action.triggered.connect(lambda *args: self.copy_items())

            move_action = menu.addAction("📦 移动")
            move_action.triggered.connect(lambda *args: self.move_items())

        if self.copy_paths or self.move_paths:
            menu.addSeparator()
            paste_action = menu.addAction("📋 粘贴")
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
