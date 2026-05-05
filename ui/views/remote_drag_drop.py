# ui/views/remote_drag_drop.py
import json

from PySide6.QtCore import Qt, QMimeData, QByteArray, QRect, QPoint, QModelIndex
from PySide6.QtGui import QDrag, QPixmap, QPainter
from PySide6.QtWidgets import QMessageBox, QAbstractItemView


class RemoteDragDropMixin:
    """
    远程文件拖拽与放置功能的 Mixin。
    为 RemoteFileWidget 提供从远端到本地的拖拽下载、文件间拖拽移动等能力。
    """

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

                                # 1. 从原位置"摘取"整行数据 (takeRow 会直接将其从原位置剥离)
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


# 导入 PySide6.QtCore.Qt 用于类内部 (已在方法中局部导入)
