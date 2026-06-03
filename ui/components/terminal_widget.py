"""SSH pseudo-terminal widget using kai-term native PySide6 rendering.

Replaces the previous QWebEngineView + xterm.js approach with a native
QPainter-based terminal (Rust-backed VT520 parser).

Architecture:
    asyncssh stdout → TerminalBridge.run() → output Signal → kai-term feed()
    Keyboard → InputHandler.encode() → TerminalBridge.on_input() → asyncssh stdin
"""

import asyncio
import logging
import sys
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QObject, Slot, Signal, Qt, QTimer, QEvent
from PySide6.QtGui import QKeyEvent, QResizeEvent
from PySide6.QtWidgets import QApplication

from core.session import SSHSFTPInfo
from ui.terminal.widget import TerminalWidget
from ui.terminal.input_handler import InputHandler

logger = logging.getLogger(__name__)

LOG_DIR = Path.home() / ".config" / "quickstfp" / "logs"


class TerminalBridge(QObject):
    """Async bridge between asyncssh SSHClientProcess and the terminal widget.

    Runs an async loop in the background QThread that reads from SSH stdout
    and emits data via the ``output`` signal. Keyboard input is received
    via the ``on_input`` slot and forwarded to SSH stdin.

    This class is unchanged from the pre-kai-term version — the QWebChannel
    @Slot decorators are harmless in a pure-Qt context.
    """

    output = Signal(str)

    def __init__(self, info: SSHSFTPInfo):
        super().__init__()
        self.info = info
        self._log_file = None
        self._logging_enabled = False

    def enable_logging(self) -> str:
        site = f"{self.info.username}@{self.info.host}"
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        path = str(LOG_DIR / f"{site}_{ts}.log")
        self._log_file = open(path, "w", encoding="utf-8")
        self._logging_enabled = True
        logger.info(f"Terminal logging started: {path}")
        return path

    def disable_logging(self):
        self._logging_enabled = False
        if self._log_file:
            self._log_file.close()
            self._log_file = None

    def _write_to_log(self, data: str):
        if self._logging_enabled and self._log_file:
            try:
                self._log_file.write(data)
                self._log_file.flush()
            except Exception:
                self._logging_enabled = False

    @Slot(int, int)
    def start(self, cols: int, rows: int):
        """Called by the widget once it has computed accurate dimensions.

        1. Resizes the asyncssh PTY to match the widget dimensions.
        2. Starts the background read loop that pumps SSH stdout → ``output``.
        """
        if self.info.loop.is_running() and getattr(self.info, "process", None):
            self.info.loop.call_soon_threadsafe(
                self.info.process.change_terminal_size, cols, rows
            )
        asyncio.run_coroutine_threadsafe(self.run(), self.info.loop)

    async def run(self):
        while True:
            try:
                data = await self.info.process.stdout.read(8192)
                if data:
                    self.output.emit(data)
                    self._write_to_log(data)
                else:
                    break
            except Exception as e:
                logger.error(f"Terminal read error: {e}")
                break

    def close_log(self):
        self.disable_logging()

    @Slot(str)
    def on_input(self, data: str):
        """Forward keyboard input to the SSH process stdin."""
        if self.info.loop.is_running() and getattr(self.info, "process", None):
            asyncio.run_coroutine_threadsafe(self._write_stdin(data), self.info.loop)

    async def _write_stdin(self, data: str):
        try:
            self.info.process.stdin.write(data)
            await self.info.process.stdin.drain()
        except Exception as e:
            logger.error(f"Terminal write error: {e}")

    @Slot(int, int)
    def resize(self, cols: int, rows: int):
        """Propagate terminal resize to the asyncssh PTY."""
        if self.info.loop.is_running() and getattr(self.info, "process", None):
            self.info.loop.call_soon_threadsafe(
                self.info.process.change_terminal_size, cols, rows
            )


class SSHPtyWidget(TerminalWidget):
    """SSH pseudo-terminal view — extends kai-term TerminalWidget.

    Replaces the previous QWebEngineView-based SSHPtyWidget.  Uses
    ``display_only=True`` because the asyncssh PTY (not kai-term's
    PtyTerminal) manages the actual shell.  Keyboard input is captured
    via an overridden ``keyPressEvent`` and forwarded to asyncssh via
    the ``TerminalBridge``.
    """

    def __init__(self, info: SSHSFTPInfo):
        super().__init__(rows=24, cols=80, display_only=True)
        self.info = info

        # ── I/O bridge (asyncssh ↔ terminal widget) ────────────────────
        self.bridge = TerminalBridge(self.info)

        # SSH output → terminal display
        self.bridge.output.connect(self._on_ssh_output)

    # ── SSH I/O ──────────────────────────────────────────────────────────

    def _on_ssh_output(self, data: str):
        """Receive SSH stdout and feed it to the terminal renderer."""
        self.feed(data)

    def _send_input(self, data: str):
        """Send raw bytes / text to asyncssh stdin."""
        self.bridge.on_input(data)

    def _paste_to_ssh(self):
        """Override parent paste to route clipboard text to asyncssh."""
        text = QApplication.clipboard().text()
        if text:
            self._send_input(text)

    def _start_bridge(self):
        """Start the terminal bridge once the event loop is running.

        Called via a single-shot timer to ensure the widget is fully
        laid out before sending dimensions to asyncssh.
        """
        self.bridge.start(self.cols, self.rows)

    def showEvent(self, event):
        """Trigger bridge startup when the widget becomes visible."""
        super().showEvent(event)
        QTimer.singleShot(0, self._start_bridge)

    # ── Focus (prevent Tab from triggering Qt focus navigation) ─────────

    def event(self, event: QEvent):
        """Intercept Tab/Backtab before Qt's focus-navigation handler.

        Qt processes Tab at the ``event()`` level and may consume it
        (moving focus to the next widget) before ``keyPressEvent`` is
        ever called.  We check here first and route Tab to our own
        handler so it reaches the SSH session.

        On macOS Qt may deliver Shift+Tab as ``Qt.Key_Backtab`` —
        normalize it to ``Qt.Key_Tab | Qt.ShiftModifier`` for the encoder.
        """
        if event.type() == QEvent.Type.KeyPress:
            key = event.key()
            if key == Qt.Key_Tab:
                self.keyPressEvent(event)
                return True
            if key == Qt.Key_Backtab:
                synthetic = QKeyEvent(
                    QEvent.Type.KeyPress,
                    Qt.Key_Tab,
                    event.modifiers() | Qt.ShiftModifier,
                    event.text(),
                    event.isAutoRepeat(),
                    event.count(),
                )
                self.keyPressEvent(synthetic)
                return True
        return super().event(event)

    # ── Keyboard (override for SSH input routing) ────────────────────────

    def keyPressEvent(self, event: QKeyEvent) -> None:
        """Handle keyboard input — routes non-shortcut keys to asyncssh.

        Inherits zoom / copy / scrollback shortcuts from TerminalWidget,
        then sends everything else to the SSH connection.
        """
        key = event.key()
        mods = event.modifiers()

        # ── Zoom shortcuts ─────────────────────────────────────────
        zoom_mod = bool(mods & Qt.ControlModifier)
        if sys.platform != "darwin":
            zoom_mod = zoom_mod and bool(mods & Qt.ShiftModifier)
        if zoom_mod and key in (Qt.Key_Plus, Qt.Key_Equal, Qt.Key_Minus):
            delta = 1 if key != Qt.Key_Minus else -1
            self._change_font_size(delta)
            return
        if zoom_mod and key == Qt.Key_0:
            self._change_font_size(13 - self._font.pointSize())
            return

        # ── Scrollback shortcuts ───────────────────────────────────
        if key == Qt.Key_PageUp and mods & Qt.ShiftModifier:
            sb_len = self._term.scrollback_len()
            self._scroll_offset = min(
                sb_len, self._scroll_offset + self._rows // 2
            )
            self.update()
            return
        if key == Qt.Key_PageDown and mods & Qt.ShiftModifier:
            self._scroll_offset = max(
                0, self._scroll_offset - self._rows // 2
            )
            self.update()
            return

        # ── Copy ───────────────────────────────────────────────────
        copy_key = key == Qt.Key_C
        copy_mod = bool(mods & Qt.ControlModifier)
        if sys.platform == "darwin":
            is_copy = copy_key and copy_mod and not (mods & Qt.ShiftModifier)
        else:
            is_copy = copy_key and copy_mod and bool(mods & Qt.ShiftModifier)
        if is_copy:
            self._copy_selection()
            return

        # ── Paste (route to SSH) ────────────────────────────────────
        paste_key = key == Qt.Key_V
        paste_mod = bool(mods & Qt.ControlModifier)
        if sys.platform == "darwin":
            is_paste = paste_key and paste_mod and not (mods & Qt.ShiftModifier)
        else:
            is_paste = paste_key and paste_mod and bool(mods & Qt.ShiftModifier)
        if is_paste:
            self._clear_selection()
            self._paste_to_ssh()
            return

        # ── All other keys → SSH stdin ─────────────────────────────
        self._clear_selection()
        data = InputHandler.encode(event)
        if data:
            self._send_input(data.decode("utf-8", errors="replace"))

    # ── Font zoom (propagate new dimensions to asyncssh) ─────────────────

    def _change_font_size(self, delta: int) -> None:
        """Override to propagate font-zoom-induced terminal resize to SSH."""
        super()._change_font_size(delta)
        if self.info.loop.is_running() and getattr(self.info, "process", None):
            self.info.loop.call_soon_threadsafe(
                self.info.process.change_terminal_size,
                self.cols, self.rows,
            )

    # ── Resize (propagate to asyncssh) ───────────────────────────────────

    def resizeEvent(self, event: QResizeEvent) -> None:
        """Handle widget resize — update terminal geometry and notify SSH."""
        prev_cols, prev_rows = self._cols, self._rows

        super().resizeEvent(event)

        # Only propagate to SSH if dimensions actually changed
        if (self._cols != prev_cols or self._rows != prev_rows):
            if self.info.loop.is_running() and getattr(self.info, "process", None):
                self.info.loop.call_soon_threadsafe(
                    self.info.process.change_terminal_size,
                    self.cols, self.rows,
                )
