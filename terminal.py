import asyncio
import os.path

from PySide6.QtCore import QObject, Slot, Signal, QUrl
from PySide6.QtWebChannel import QWebChannel
from PySide6.QtWebEngineWidgets import QWebEngineView

from session import SSHSFTPInfo


class TerminalBridge(QObject):
    """
    部分内容由gemini3 pro生产
    """
    output = Signal(str)

    def __init__(self, info: SSHSFTPInfo):
        super().__init__()
        self.info = info
        self.process = info.process

    @Slot()
    def start(self):
        asyncio.run_coroutine_threadsafe(self.run(), self.info.loop)

    async def run(self):
        while True:
            data = await self.process.stdout.read(1024)
            if data:
                # 发送信号（Qt 会自动处理跨线程信号槽）
                self.output.emit(data)

    @Slot(str)
    def on_input(self, data):
        """
        GUI 线程：接收前端输入
        【关键修复2】：不要直接调用 process.stdin.write，必须调度到后台 loop 执行
        """
        if self.info.loop.is_running():
            asyncio.run_coroutine_threadsafe(self._write_stdin(data), self.info.loop)

    async def _write_stdin(self, data: str):
        """在 asyncio 线程中安全写入"""
        try:
            # 【关键修复3】：编码。将前端的字符串转回 bytes 发送给 SSH
            self.process.stdin.write(data)
            await self.process.stdin.drain()
        except Exception as e:
            print(f"Write error: {e}")

    @Slot(int, int)
    def resize(self, row: int, col: int):
        self.info.loop.call_soon_threadsafe(
            self.process.change_terminal_size, row, col
        )


class SSHPtyWidget(QWebEngineView):
    def __init__(self, info: SSHSFTPInfo):
        super().__init__()
        self.channel = QWebChannel()
        self.page().setWebChannel(self.channel)
        self.setUrl(QUrl.fromLocalFile(
            os.path.abspath("terminal.html")
        ))
        self.bridge = TerminalBridge(info)
        self.channel.registerObject("bridge", self.bridge)
        self.loadFinished.connect(self.start_task)

    def start_task(self):
        self.bridge.start()
