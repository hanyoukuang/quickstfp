from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTreeWidget, QTreeWidgetItem,
    QPushButton, QLabel, QHeaderView
)
from PySide6.QtGui import QColor


class DirectoryDiffDialog(QDialog):
    """目录比较对话框，比较本地和远端目录的文件差异"""

    def __init__(self, parent=None, local_files: dict = None, remote_files: dict = None):
        super().__init__(parent)
        self.setWindowTitle("目录比较")
        self.resize(700, 500)

        self._local = local_files or {}
        self._remote = remote_files or {}

        layout = QVBoxLayout(self)

        header = QHBoxLayout()
        header.addWidget(QLabel(f"🟢 一致:  {self._count_status('same')}  "))
        header.addWidget(QLabel(f"🔵 仅本地:  {self._count_status('local_only')}  "))
        header.addWidget(QLabel(f"🟠 仅远端:  {self._count_status('remote_only')}  "))
        header.addWidget(QLabel(f"🔴 差异:  {self._count_status('diff')}"))
        layout.addLayout(header)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["状态", "文件名", "大小 (本地)", "大小 (远端)", "时间 (远端)"])
        self._tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self._tree)

        self._populate()

    def _count_status(self, status: str) -> int:
        return sum(1 for v in self._local.values() if v.get("status") == status)

    def _populate(self):
        all_names = sorted(set(list(self._local.keys()) + list(self._remote.keys())))

        for name in all_names:
            l = self._local.get(name, {})
            r = self._remote.get(name, {})
            l_size = l.get("size", "")
            r_size = r.get("size", "")
            r_time = r.get("time", "")

            if name in self._local and name in self._remote:
                if l_size == r_size:
                    status = ("🟢 一致", QColor("#2e7d32"), QColor("#e8f5e9"))
                else:
                    status = ("🔴 差异", QColor("#c62828"), QColor("#fce4ec"))
                self._local[name]["status"] = "same" if l_size == r_size else "diff"
            elif name in self._local:
                status = ("🔵 仅本地", QColor("#1565c0"), QColor("#e3f2fd"))
                self._local[name]["status"] = "local_only"
            else:
                status = ("🟠 仅远端", QColor("#e65100"), QColor("#fff3e0"))
                self._remote[name] = {"status": "remote_only"}

            item = QTreeWidgetItem([status[0], name, str(l_size), str(r_size), r_time])
            for col in range(5):
                item.setBackground(col, status[2])
                item.setForeground(col, status[1])
            self._tree.addTopLevelItem(item)
