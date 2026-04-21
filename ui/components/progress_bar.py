# ui/components/progress_bar.py
from PySide6.QtCore import Signal, Slot
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QProgressBar, QWidget, QHBoxLayout, QLabel, QMessageBox, QPushButton


class ProgressBar(QWidget):
    """
    独立的文件传输进度条组件。
    纯 UI 层，只负责显示进度和抛出用户操作信号，不包含底层传输逻辑。
    """
    # 接收来自外部(核心层)的信号，用于更新 UI
    update_pbar_msg = Signal(int)
    init_pbar_msg = Signal(int)
    transport_fail_msg = Signal(str)

    # 向外部抛出的信号
    del_widget_msg = Signal()  # 移除本组件的请求
    cancel_requested = Signal()  # 用户点击了取消按钮

    def __init__(self, filename: str, transport_type: str, icon: QIcon):
        super().__init__()
        self.filename = filename
        self.transport_type = transport_type
        self.icon = icon

        self.layout = QHBoxLayout(self)
        self.filename_label = QLabel(f"{self.transport_type}: {self.filename}")
        self.picture_label = QLabel()
        self.progress_bar = QProgressBar()
        self.cancel_button = QPushButton("Cancel")

        self.init_ui()
        self._connect_signals()

    def init_ui(self):
        self.picture_label.setPixmap(self.icon.pixmap(16, 16))
        self.layout.addWidget(self.filename_label)
        self.layout.addWidget(self.picture_label)
        self.layout.addWidget(self.progress_bar)
        self.layout.addWidget(self.cancel_button)
        self.setLayout(self.layout)

    def _connect_signals(self):
        # 绑定自身接收的信号
        self.update_pbar_msg.connect(self.set_progress_value)
        self.init_pbar_msg.connect(self.set_progress_range)
        self.transport_fail_msg.connect(self.warning_transport_fail_filename)

        # 将按钮点击事件转化为对外的业务信号
        self.cancel_button.clicked.connect(self.cancel_requested.emit)
        self.cancel_button.clicked.connect(self.del_widget_msg.emit)

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
