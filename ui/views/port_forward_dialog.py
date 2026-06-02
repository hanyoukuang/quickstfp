from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit, QPushButton,
    QComboBox, QSpinBox, QTreeWidget, QTreeWidgetItem, QLabel, QHeaderView
)


class PortForwardDialog(QDialog):

    def __init__(self, parent=None, session=None):
        super().__init__(parent)
        self.setWindowTitle("SSH 端口转发 (SSH Tunnel)")
        self.resize(620, 420)
        self._session = session

        layout = QVBoxLayout(self)

        self._tunnel_list = QTreeWidget()
        self._tunnel_list.setHeaderLabels(["类型", "监听端口", "目标地址", "状态"])
        self._tunnel_list.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self._tunnel_list)

        self._hint = QLabel()
        self._hint.setStyleSheet("color: #888; font-size: 11px; padding: 2px 0;")
        layout.addWidget(self._hint)

        form = QFormLayout()
        self._type_combo = QComboBox()
        self._type_combo.addItem("本地转发 (L) — 本地端口 → 远端服务", "local")
        self._type_combo.addItem("远程转发 (R) — 服务器端口 → 本机服务", "remote")
        self._type_combo.currentIndexChanged.connect(self._on_type_changed)
        form.addRow("转发类型:", self._type_combo)

        self._listen_label = QLabel("本地监听端口:")
        self._listen_port = QSpinBox()
        self._listen_port.setRange(1, 65535)
        self._listen_port.setValue(8080)
        form.addRow(self._listen_label, self._listen_port)

        self._target_label = QLabel("远端地址:")
        self._target_host = QLineEdit("localhost")
        form.addRow(self._target_label, self._target_host)

        self._target_port_label = QLabel("远端端口:")
        self._target_port = QSpinBox()
        self._target_port.setRange(1, 65535)
        self._target_port.setValue(80)
        form.addRow(self._target_port_label, self._target_port)

        layout.addLayout(form)

        btn_layout = QHBoxLayout()
        add_btn = QPushButton("添加隧道")
        add_btn.clicked.connect(self._add_tunnel)
        del_btn = QPushButton("删除选中")
        del_btn.clicked.connect(self._del_tunnel)
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(del_btn)
        layout.addLayout(btn_layout)

        self._on_type_changed(0)

    def _on_type_changed(self, idx: int):
        if idx == 0:  # Local
            self._listen_label.setText("本地监听端口:")
            self._target_label.setText("远端地址:")
            self._target_port_label.setText("远端端口:")
            self._hint.setText("效果：访问 localhost:监听端口 → SSH → 远端地址:远端端口")
        else:  # Remote
            self._listen_label.setText("服务器监听端口:")
            self._target_label.setText("本机地址:")
            self._target_port_label.setText("本机端口:")
            self._hint.setText(
                "效果：访问 服务器:监听端口 → SSH → 本机地址:本机端口\n"
                "⚠ 如果外网无法访问，检查服务器 /etc/ssh/sshd_config 中 GatewayPorts yes")

    def _add_tunnel(self):
        tunnel_type = self._type_combo.currentData()
        listen_port = self._listen_port.value()
        target_host = self._target_host.text().strip()
        target_port = self._target_port.value()

        if not target_host:
            return

        display = "L" if tunnel_type == "local" else "R"
        target_addr = f"{target_host}:{target_port}"

        try:
            if self._session and hasattr(self._session, 'forward_local_port'):
                if tunnel_type == "local":
                    self._session.forward_local_port('', listen_port, target_host, target_port)
                else:
                    self._session.forward_remote_port('', listen_port, target_host, target_port)
                status = "✅ 已建立"
            else:
                status = "❌ 无活动会话"
        except Exception as e:
            status = f"❌ {e}"

        item = QTreeWidgetItem([display, str(listen_port), target_addr, status])
        self._tunnel_list.addTopLevelItem(item)

    def _del_tunnel(self):
        item = self._tunnel_list.currentItem()
        if item:
            self._tunnel_list.takeTopLevelItem(self._tunnel_list.indexOfTopLevelItem(item))

    def closeEvent(self, event):
        self.hide()
        event.ignore()
