# ui/components/progress_bar.py
from PySide6.QtCore import Signal, Slot
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QProgressBar, QWidget, QHBoxLayout, QLabel, QMessageBox, QPushButton


class ProgressBar(QWidget):
    """
    独立的文件传输进度条组件。
    """
    update_pbar_msg = Signal(int)
    init_pbar_msg = Signal(int)
    transport_fail_msg = Signal(str)

    del_widget_msg = Signal()
    cancel_requested = Signal()
    pause_requested = Signal()
    retry_requested = Signal()

    def __init__(self, filename: str, transport_type: str, icon: QIcon):
        super().__init__()
        self.filename = filename
        self.transport_type = transport_type
        self.icon = icon

        self.layout = QHBoxLayout(self)
        self.filename_label = QLabel(f"{self.transport_type}: {self.filename}")
        self.picture_label = QLabel()
        self.progress_bar = QProgressBar()

        # --- 必须在这里完成暂停按钮和网速标签的初始化 ---
        self.speed_label = QLabel("0.00 B/s")
        self.speed_label.setFixedWidth(80)

        self.is_paused = False
        self.pause_button = QPushButton("⏸️ 暂停")
        self.retry_button = QPushButton("🔄 重试")
        self.retry_button.hide()
        self._is_failed = False

        self.cancel_button = QPushButton("⏹️ 取消")

        # 初始化UI和绑定信号必须放在所有组件实例化之后
        self.init_ui()
        self._connect_signals()

    def init_ui(self):
        self.picture_label.setPixmap(self.icon.pixmap(16, 16))
        self.layout.addWidget(self.filename_label)
        self.layout.addWidget(self.picture_label)
        self.layout.addWidget(self.progress_bar)

        # 按照顺序将新组件添加到布局中
        self.layout.addWidget(self.speed_label)
        self.layout.addWidget(self.pause_button)
        self.layout.addWidget(self.retry_button)

        self.layout.addWidget(self.cancel_button)
        self.setLayout(self.layout)

    def _connect_signals(self):
        # 绑定自身接收的信号
        self.update_pbar_msg.connect(self.set_progress_value)
        self.init_pbar_msg.connect(self.set_progress_range)
        self.transport_fail_msg.connect(self.warning_transport_fail_filename)

        # 绑定 UI 的点击事件
        self.cancel_button.clicked.connect(self.cancel_requested.emit)
        self.cancel_button.clicked.connect(self.del_widget_msg.emit)
        self.pause_button.clicked.connect(self._toggle_pause_ui)
        self.retry_button.clicked.connect(self.retry_requested.emit)

    @Slot(int)
    def set_progress_range(self, max_value: int):
        self.progress_bar.setRange(0, max_value)

    @Slot(int)
    def set_progress_value(self, current_value: int):
        self.progress_bar.setValue(current_value)

    @Slot(str)
    def warning_transport_fail_filename(self, value: str):
        if value:
            QMessageBox.warning(
                self,
                "传输警告",
                f"传输失败:\n{value}",
                QMessageBox.StandardButton.Ok
            )

    @Slot(str)
    def set_speed_text(self, speed_str: str):
        self.speed_label.setText(speed_str)

    def mark_completed(self):
        self.filename_label.setText(f"✅ {self.transport_type}: {self.filename}")
        self.pause_button.hide()
        self.cancel_button.hide()

    def mark_failed(self):
        self._is_failed = True
        self.filename_label.setText(f"❌ {self.transport_type}: {self.filename}")
        self.pause_button.hide()
        self.retry_button.show()

    def _toggle_pause_ui(self):
        """处理UI样式变化，并对外抛出信号"""
        self.is_paused = not self.is_paused
        # 切换按钮文字
        self.pause_button.setText("▶️ 继续" if self.is_paused else "⏸️ 暂停")
        self.pause_requested.emit()
