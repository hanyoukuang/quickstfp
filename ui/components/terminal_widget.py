# ui/components/terminal_widget.py
import asyncio
from pathlib import Path

from PySide6.QtCore import QObject, Slot, Signal, QUrl
from PySide6.QtWebChannel import QWebChannel
from PySide6.QtWebEngineWidgets import QWebEngineView

# 引入核心业务逻辑
from core.session import SSHSFTPInfo


class TerminalBridge(QObject):
    """
    终端数据桥接类。
    负责在 Qt WebChannel (前端 xterm.js) 和 asyncssh 伪终端进程之间传递流数据。
    完全解耦了界面渲染与底层 SSH 通信。
    """
    # 当收到 SSH 输出时触发此信号，交由 Qt 自动跨线程发送给前端 Web
    output = Signal(str)

    def __init__(self, info: SSHSFTPInfo):
        super().__init__()
        self.info = info
        self.process = info.process

    @Slot()
    def start(self):
        """由 WebView 加载完成后调用，开始在后台监听 SSH 输出流"""
        asyncio.run_coroutine_threadsafe(self.run(), self.info.loop)

    async def run(self):
        """持续读取 SSH 进程的 stdout"""
        while True:
            try:
                data = await self.process.stdout.read(1024)
                if data:
                    self.output.emit(data)
                else:
                    break  # 流已结束或连接关闭
            except Exception as e:
                print(f"Terminal read error: {e}")
                break

    @Slot(str)
    def on_input(self, data: str):
        """
        GUI 线程调用：接收前端用户的按键输入
        将其调度到后台的 asyncio 事件循环中执行写入
        """
        if self.info.loop.is_running():
            asyncio.run_coroutine_threadsafe(self._write_stdin(data), self.info.loop)

    async def _write_stdin(self, data: str):
        """在 asyncio 线程中安全写入 stdin"""
        try:
            self.process.stdin.write(data)
            await self.process.stdin.drain()
        except Exception as e:
            print(f"Terminal write error: {e}")

    @Slot(int, int)
    def resize(self, row: int, col: int):
        """处理前端 xterm.js 窗口自适应大小的改变"""
        if self.info.loop.is_running():
            self.info.loop.call_soon_threadsafe(
                self.process.change_terminal_size, row, col
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

        # 5. 确保页面完全加载成功后再启动 SSH 数据监听，防止丢包
        self.loadFinished.connect(self.start_task)

    def start_task(self, ok: bool):
        """页面加载完成的回调"""
        if ok:
            self.bridge.start()
        else:
            print("警告: terminal.html 本地资源加载失败，请检查 ui/web/ 目录配置。")
