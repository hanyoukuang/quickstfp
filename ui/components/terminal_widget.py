import asyncio
from pathlib import Path

from PySide6.QtCore import QObject, Slot, Signal, QUrl
from PySide6.QtWebChannel import QWebChannel
from PySide6.QtWebEngineWidgets import QWebEngineView

from core.session import SSHSFTPInfo


class TerminalBridge(QObject):
    output = Signal(str)

    def __init__(self, info: SSHSFTPInfo):
        super().__init__()
        self.info = info

    @Slot(int, int)
    def start(self, cols: int, rows: int):
        """由前端 JS 计算出准确的长宽后主动触发"""
        # 1. 先将终端尺寸调整到 JS 算出的精确值
        if self.info.loop.is_running() and getattr(self.info, 'process', None):
            self.info.loop.call_soon_threadsafe(
                self.info.process.change_terminal_size, cols, rows
            )
        # 2. 启动后台读取循环
        asyncio.run_coroutine_threadsafe(self.run(), self.info.loop)

    async def run(self):
        while True:
            try:
                # 此时，积攒在缓冲区里的 404 字节 Welcome 信息会被瞬间读出并发给前端！
                data = await self.info.process.stdout.read(8192)
                if data:
                    self.output.emit(data)
                else:
                    break
            except Exception as e:
                print(f"Terminal read error: {e}")
                break

    @Slot(str)
    def on_input(self, data: str):
        if self.info.loop.is_running() and getattr(self.info, 'process', None):
            asyncio.run_coroutine_threadsafe(self._write_stdin(data), self.info.loop)

    async def _write_stdin(self, data: str):
        try:
            self.info.process.stdin.write(data)
            await self.info.process.stdin.drain()
        except Exception as e:
            print(f"Terminal write error: {e}")

    @Slot(int, int)
    def resize(self, cols: int, rows: int):
        """【修复参数 Bug】：处理前端 xterm.js 窗口自适应大小的改变"""
        if self.info.loop.is_running() and getattr(self.info, 'process', None):
            self.info.loop.call_soon_threadsafe(
                # asyncssh 参数顺序严格为 (width, height)
                self.info.process.change_terminal_size, cols, rows
            )


class SSHPtyWidget(QWebEngineView):
    """
    SSH 伪终端 UI 视图容器。
    继承自 QWebEngineView，负责加载本地的 terminal.html 并注入 QWebChannel 通信对象。
    """

    def __init__(self, info: SSHSFTPInfo):
        super().__init__()
        self.info = info

        # 1. 设置 WebChannel 通信通道
        self.channel = QWebChannel()
        self.page().setWebChannel(self.channel)

        # 2. 注册 Python 端的桥接对象给 JS 前端使用
        self.bridge = TerminalBridge(self.info)
        self.channel.registerObject("bridge", self.bridge)

        # 3. 动态解析 ui/web/terminal.html 的绝对路径
        # __file__ 指向当前文件 (ui/components/terminal_widget.py)
        # .parent 是 components, .parent.parent 是 ui/
        current_dir = Path(__file__).resolve().parent
        ui_dir = current_dir.parent
        html_path = ui_dir / "web" / "terminal.html"

        # 4. 加载本地 HTML
        self.setUrl(QUrl.fromLocalFile(str(html_path)))
