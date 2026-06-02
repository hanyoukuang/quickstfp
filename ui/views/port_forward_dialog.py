from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit, QPushButton,
    QComboBox, QSpinBox, QTreeWidget, QTreeWidgetItem, QLabel, QHeaderView,
    QMessageBox, QDialogButtonBox
)


class PortForwardDialog(QDialog):
    """SSH 端口转发管理对话框"""

    def __init__(self, parent=None, session=None):
        super().__init__(parent)
        self.setWindowTitle("SSH 端口转发")
        self.resize(600, 400)
        self._session = session

        layout = QVBoxLayout(self)

        self._tunnel_list = QTreeWidget()
        self._tunnel_list.setHeaderLabels(["类型", "本地端口", "远程地址", "远程端口", "状态"])
        self._tunnel_list.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self._tunnel_list)

        form = QFormLayout()
        self._type_combo = QComboBox()
        self._type_combo.addItem("本地转发 (L)", "local")
        self._type_combo.addItem("远程转发 (R)", "remote")
        form.addRow("转发类型:", self._type_combo)

        self._local_port = QSpinBox()
        self._local_port.setRange(1, 65535)
        self._local_port.setValue(8080)
        form.addRow("本地端口:", self._local_port)

        self._remote_host = QLineEdit("localhost")
        form.addRow("远程主机:", self._remote_host)

        self._remote_port = QSpinBox()
        self._remote_port.setRange(1, 65535)
        self._remote_port.setValue(80)
        form.addRow("远程端口:", self._remote_port)

        layout.addLayout(form)

        btn_layout = QHBoxLayout()
        add_btn = QPushButton("添加隧道")
        add_btn.clicked.connect(self._add_tunnel)
        del_btn = QPushButton("删除选中")
        del_btn.clicked.connect(self._del_tunnel)
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(del_btn)
        layout.addLayout(btn_layout)

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def _add_tunnel(self):
        tunnel_type = self._type_combo.currentData()
        local_port = self._local_port.value()
        remote_host = self._remote_host.text().strip()
        remote_port = self._remote_port.value()

        if not remote_host:
            return

        display = "L" if tunnel_type == "local" else "R"
        addr = f"{remote_host}:{remote_port}"

        try:
            if self._session and hasattr(self._session, 'forward_local_port'):
                if tunnel_type == "local":
                    self._session.forward_local_port('', local_port, remote_host, remote_port)
                else:
                    self._session.forward_remote_port('', remote_port, remote_host, local_port)
                status = "✅ 已建立"
            else:
                status = "❌ 无活动会话"
        except Exception as e:
            status = f"❌ {e}"

        item = QTreeWidgetItem([display, str(local_port), remote_host, str(remote_port), status])
        self._tunnel_list.addTopLevelItem(item)

    def _del_tunnel(self):
        item = self._tunnel_list.currentItem()
        if item:
            idx = self._tunnel_list.indexOfTopLevelItem(item)
            self._tunnel_list.takeTopLevelItem(idx)
