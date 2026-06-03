"""Terminal widget — vendored from kai-term (https://github.com/hanyoukuang/kai-term)

A cross-platform terminal emulator widget using native PySide6 QPainter rendering
with a Rust backend (par-term-emu-core-rust).

Supports two modes:
    - Interactive: PtyTerminal backend with local shell
    - Display-only: Terminal backend (headless) for piping external output
"""

from par_term_emu_core_rust import PtyTerminal, CursorStyle, UnderlineStyle, Terminal
from PySide6.QtWidgets import QWidget, QApplication, QMenu
from PySide6.QtCore import QTimer, Qt, QRectF
from PySide6.QtGui import (
    QPainter, QFont, QFontMetrics, QColor,
    QKeyEvent, QPaintEvent, QResizeEvent,
    QWheelEvent, QMouseEvent, QAction,
    QInputMethodEvent,
)
import sys
from .input_handler import InputHandler


_FONT_CANDIDATES = (
    "MesloLGS NF", "JetBrainsMono Nerd Font",
    "FiraCode Nerd Font", "CaskaydiaCove Nerd Font",
    "Hack Nerd Font", "DejaVuSansMono Nerd Font",
    "SF Mono", "JetBrains Mono", "Fira Code",
    "Menlo", "Courier New", "monospace",
)


def _pick_monospace_font(size: int = 13) -> QFont:
    for family in _FONT_CANDIDATES:
        font = QFont(family, size)
        font.setStyleHint(QFont.Monospace)
        font.setHintingPreference(QFont.PreferFullHinting)
        fm = QFontMetrics(font)
        if fm.horizontalAdvance("M") > 0:
            return font
    return QFont("monospace", size)


class TerminalWidget(QWidget):
    DEFAULT_FG = QColor(192, 192, 192)
    DEFAULT_BG = QColor(0, 0, 0)
    SELECTION_BG = QColor(80, 80, 80)

    def __init__(self, parent=None, rows: int = 24, cols: int = 80,
                 display_only: bool = False):
        super().__init__(parent)

        self._font = _pick_monospace_font(13)
        self._fm = QFontMetrics(self._font)
        self._cell_w = int(max(self._fm.horizontalAdvance("M"), 1))
        self._cell_h = int(max(self._fm.height(), 1))

        self._rows = rows
        self._cols = cols
        self._scroll_offset = 0
        self._wheel_accum = 0
        self._unseen_output = False
        self._cursor_visible = True
        self._blink_visible = True
        self._generation = 0
        self._display_only = display_only

        self._font_bold = QFont(self._font)
        self._font_bold.setBold(True)
        self._font_italic = QFont(self._font)
        self._font_italic.setItalic(True)
        self._font_bold_italic = QFont(self._font)
        self._font_bold_italic.setBold(True)
        self._font_bold_italic.setItalic(True)

        if display_only:
            self._term = Terminal(self._cols, self._rows)
        else:
            self._term = PtyTerminal(self._cols, self._rows)

        self._sel_start: tuple[int, int] | None = None
        self._sel_end: tuple[int, int] | None = None
        self._selecting = False
        self._preedit = ""

        self.setFocusPolicy(Qt.StrongFocus)
        self.setAttribute(Qt.WA_OpaquePaintEvent, True)
        self.setAttribute(Qt.WA_InputMethodEnabled, True)
        self.setMinimumSize(self._cell_w * 20, self._cell_h * 5)
        self.setMouseTracking(True)

        self._cursor_timer = QTimer(self)
        self._cursor_timer.timeout.connect(self._toggle_cursor)
        self._cursor_timer.start(530)

        self._poll_timer: QTimer | None = None
        if not display_only:
            self._poll_timer = QTimer(self)
            self._poll_timer.timeout.connect(self._poll_updates)
            self._poll_timer.start(16)

    # ── Public API ────────────────────────────────────────────────────────

    @property
    def cols(self) -> int:
        return self._cols

    @property
    def rows(self) -> int:
        return self._rows

    def start_shell(self) -> None:
        """Start interactive shell (PtyTerminal mode only)."""
        if self._display_only:
            raise RuntimeError("start_shell() not available in display-only mode")
        self._term.spawn_shell()

    def feed(self, data: str) -> None:
        """Feed text/escape sequences for display (display-only mode).

        Use this to pipe terminal output (e.g. from SSH) into the widget
        for rendering without a local PTY.

        Example:
            widget.feed("\\x1b[31mHello\\x1b[0m\\n")
        """
        if not self._display_only:
            raise RuntimeError("feed() only available in display-only mode")
        self._term.process_str(data)
        self.update()

    def write_to_term(self, data: bytes) -> None:
        """Write raw bytes to the terminal backend (interactive mode only)."""
        if self._display_only:
            raise RuntimeError("write_to_term() not available in display-only mode")
        self._term.write(data)

    @property
    def rows(self) -> int:
        return self._rows

    @property
    def cols(self) -> int:
        return self._cols

    # ── Polling ──────────────────────────────────────────────────────────

    def _poll_updates(self) -> None:
        if self._display_only:
            return
        if self._term.has_updates_since(self._generation):
            self._generation = self._term.update_generation()
            if self._scroll_offset == 0:
                self._unseen_output = False
                self.update()
            elif not self._unseen_output:
                self._unseen_output = True
                self.update()

        try:
            title = self._term.title()
            if title and title != self.windowTitle():
                self.setWindowTitle(title)
        except Exception:
            pass

    # ── Paint ────────────────────────────────────────────────────────────

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.TextAntialiasing, True)
        painter.setFont(self._font)
        painter.fillRect(self.rect(), self.DEFAULT_BG)

        for display_row in range(self._rows):
            self._draw_row(painter, display_row)

        if self._scroll_offset == 0:
            if self._preedit:
                self._draw_preedit(painter)
            else:
                self._draw_cursor(painter)

        if self._unseen_output and self._scroll_offset > 0:
            indicator_w = self._cell_w * 3
            indicator_h = 3
            indicator_x = self._cols * self._cell_w - indicator_w
            indicator_y = self._rows * self._cell_h - indicator_h
            painter.fillRect(indicator_x, indicator_y,
                             indicator_w, indicator_h,
                             QColor(255, 200, 0))

        painter.end()

    def _draw_row(self, painter: QPainter, display_row: int) -> None:
        y = display_row * self._cell_h
        live_row = display_row - self._scroll_offset

        if live_row < 0:
            self._draw_scrollback_row(painter, display_row, y)
        else:
            self._draw_live_row(painter, live_row, y)

    def _draw_scrollback_row(self, painter: QPainter,
                              display_row: int, y: int) -> None:
        sb_idx = self._scroll_offset - display_row - 1
        sb_len = self._term.scrollback_len()
        if sb_idx < 0 or sb_idx >= sb_len:
            return
        try:
            cells = self._term.scrollback_line(sb_idx)
        except Exception:
            return
        if not cells:
            return
        self._render_cells(painter, cells, y, display_row)

    def _draw_live_row(self, painter: QPainter,
                        live_row: int, y: int) -> None:
        if live_row >= self._rows:
            return
        try:
            cells = self._term.get_line_cells(live_row)
        except Exception:
            return
        display_row = live_row + self._scroll_offset
        self._render_cells(painter, cells, y, display_row)

    def _render_cells(self, painter: QPainter, cells: list,
                       y: int, display_row: int) -> None:
        cell_data: list[dict] = []
        for col, (char, fg, bg, attrs) in enumerate(cells):
            if col >= self._cols:
                break
            if attrs and attrs.wide_char_spacer:
                continue

            x = col * self._cell_w
            is_wide = attrs and attrs.wide_char
            cell_w = self._cell_w * 2 if is_wide else self._cell_w
            is_space = not char or char == " "

            is_reverse = attrs and attrs.reverse
            if is_reverse:
                eff_fg = bg if bg else (0, 0, 0)
                eff_bg = fg if fg else (192, 192, 192)
            else:
                eff_fg = fg
                eff_bg = bg

            bg_rgb = eff_bg if eff_bg else (0, 0, 0)
            selected = self._cell_in_selection(display_row, col)

            cell_data.append({
                'x': x, 'cell_w': cell_w, 'char': char,
                'eff_fg': eff_fg, 'bg_rgb': bg_rgb,
                'selected': selected, 'attrs': attrs,
                'is_space': is_space,
            })

        for d in cell_data:
            if d['selected']:
                painter.fillRect(d['x'], y, d['cell_w'], self._cell_h,
                                 self.SELECTION_BG)
            elif d['bg_rgb'] != (0, 0, 0):
                painter.fillRect(d['x'], y, d['cell_w'], self._cell_h,
                                 QColor(*d['bg_rgb']))

        for d in cell_data:
            attrs = d['attrs']
            char = d['char']
            x = d['x']
            cell_w = d['cell_w']

            if attrs and attrs.hidden:
                continue
            if d['is_space']:
                continue
            if attrs and attrs.blink and not self._blink_visible:
                continue

            fg_rgb = d['eff_fg'] if d['eff_fg'] else (192, 192, 192)
            if attrs and attrs.dim:
                fg_rgb = tuple(c // 2 for c in fg_rgb)

            is_bold = attrs and attrs.bold
            is_italic = attrs and attrs.italic
            is_underline = attrs and attrs.underline

            if is_bold and is_italic:
                painter.setFont(self._font_bold_italic)
            elif is_bold:
                painter.setFont(self._font_bold)
            elif is_italic:
                painter.setFont(self._font_italic)
            else:
                painter.setFont(self._font)

            painter.save()

            is_block = len(char) == 1 and 0x2580 <= ord(char) <= 0x259F
            if is_block:
                painter.setClipRect(x, y, cell_w, self._cell_h)
            else:
                painter.setClipRect(x - 2, y - 2, cell_w + 4, self._cell_h + 4)

            painter.setPen(QColor(*fg_rgb))
            painter.drawText(x, int(y + self._fm.ascent()), char)

            if attrs and attrs.strikethrough:
                mid_y = y + self._cell_h // 2
                painter.drawLine(x, mid_y, x + cell_w, mid_y)

            if is_underline:
                base_y = y + self._fm.ascent() + 2
                ul_style = attrs.underline_style
                self._draw_underline(painter, x, base_y, cell_w, ul_style)

            painter.restore()

        painter.setFont(self._font)

    @staticmethod
    def _draw_underline(painter: QPainter, x: int, base_y: int,
                         cell_w: int, style) -> None:
        """Draw underline with style: Straight, Double, Curly, Dotted, Dashed."""
        if style == UnderlineStyle.Double:
            painter.drawLine(x, base_y - 1, x + cell_w, base_y - 1)
            painter.drawLine(x, base_y + 1, x + cell_w, base_y + 1)
        elif style == UnderlineStyle.Curly:
            # Approximate with short dashes
            pen = painter.pen()
            pen.setStyle(Qt.DashLine)
            painter.setPen(pen)
            painter.drawLine(x, base_y, x + cell_w, base_y)
            pen.setStyle(Qt.SolidLine)
            painter.setPen(pen)
        elif style == UnderlineStyle.Dotted:
            pen = painter.pen()
            pen.setStyle(Qt.DotLine)
            painter.setPen(pen)
            painter.drawLine(x, base_y, x + cell_w, base_y)
            pen.setStyle(Qt.SolidLine)
            painter.setPen(pen)
        elif style == UnderlineStyle.Dashed:
            pen = painter.pen()
            pen.setStyle(Qt.DashLine)
            painter.setPen(pen)
            painter.drawLine(x, base_y, x + cell_w, base_y)
            pen.setStyle(Qt.SolidLine)
            painter.setPen(pen)
        else:
            # Straight (default) or None
            painter.drawLine(x, base_y, x + cell_w, base_y)

    def _draw_cursor(self, painter: QPainter) -> None:
        if not self._cursor_visible:
            return
        try:
            cx, cy = self._term.cursor_position()
            style = self._term.cursor_style()
        except Exception:
            return
        if not (0 <= cy < self._rows and 0 <= cx < self._cols):
            return

        x = cx * self._cell_w
        y = cy * self._cell_h

        _UNDERLINE = {CursorStyle.BlinkingUnderline, CursorStyle.SteadyUnderline}
        _BAR = {CursorStyle.BlinkingBar, CursorStyle.SteadyBar}

        if style in _UNDERLINE:
            painter.fillRect(x, y + self._cell_h - 2, self._cell_w, 2,
                             self.DEFAULT_FG)
        elif style in _BAR:
            painter.fillRect(x, y, 2, self._cell_h, self.DEFAULT_FG)
        else:
            painter.fillRect(x, y, self._cell_w, self._cell_h, self.DEFAULT_FG)

    def _draw_preedit(self, painter: QPainter) -> None:
        try:
            cx, cy = self._term.cursor_position()
        except Exception:
            return
        if not (0 <= cy < self._rows and 0 <= cx < self._cols):
            return

        x = cx * self._cell_w
        y = cy * self._cell_h
        painter.setFont(self._font)
        painter.setPen(self.DEFAULT_FG)
        painter.drawText(x, int(y + self._fm.ascent()), self._preedit)

        preedit_w = len(self._preedit) * self._cell_w
        ul_y = y + self._cell_h - 2
        painter.drawLine(x, int(ul_y), x + preedit_w, int(ul_y))

        if self._cursor_visible:
            cx_end = x + preedit_w
            painter.fillRect(cx_end, y, self._cell_w, self._cell_h,
                             self.DEFAULT_FG)

    # ── Selection ────────────────────────────────────────────────────────

    @staticmethod
    def _in_range(val: int, a: int, b: int) -> bool:
        lo, hi = (a, b) if a <= b else (b, a)
        return lo <= val <= hi

    def _cell_in_selection(self, row: int, col: int) -> bool:
        if not self._sel_start or not self._sel_end:
            return False
        r1, c1 = self._sel_start
        r2, c2 = self._sel_end
        if r1 == r2:
            return row == r1 and self._in_range(col, c1, c2)
        if row < min(r1, r2) or row > max(r1, r2):
            return False
        if row == r1:
            return col >= c1 if r1 <= r2 else col <= c1
        if row == r2:
            return col <= c2 if r1 <= r2 else col >= c2
        return True

    def _selected_text(self) -> str:
        if not self._sel_start or not self._sel_end:
            return ""
        r1, c1 = self._sel_start
        r2, c2 = self._sel_end
        if r1 > r2 or (r1 == r2 and c1 > c2):
            r1, c1, r2, c2 = r2, c2, r1, c1

        lines = []
        for r in range(r1, r2 + 1):
            live_row = r - self._scroll_offset
            if live_row < 0:
                sb_idx = self._scroll_offset - r - 1
                try:
                    cells = self._term.scrollback_line(sb_idx)
                    text = "".join(c[0] for c in cells)
                except Exception:
                    text = ""
            else:
                if live_row >= self._rows:
                    continue
                try:
                    text = self._term.get_line(live_row)
                except Exception:
                    text = ""
            if not text:
                continue

            sc = c1 if r == r1 else 0
            ec = c2 + 1 if r == r2 else len(text)
            if sc < len(text):
                lines.append(text[sc:ec])
        return "\n".join(lines)

    def _copy_selection(self) -> None:
        text = self._selected_text()
        if text:
            QApplication.clipboard().setText(text)

    def _clear_selection(self) -> None:
        self._sel_start = None
        self._sel_end = None
        self.update()

    def _paste_to_ssh(self) -> None:
        """Send clipboard text to the SSH connection.

        Override in subclass to route paste to a custom backend.
        """
        if not self._display_only:
            text = QApplication.clipboard().text()
            if text:
                self._term.write_str(text)

    # ── Mouse events ─────────────────────────────────────────────────────

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton:
            col = int(event.position().x() // self._cell_w)
            row = int(event.position().y() // self._cell_h)
            self._clear_selection()
            self._sel_start = (row, col)
            self._sel_end = (row, col)
            self._selecting = True
            self.setCursor(Qt.IBeamCursor)
        elif event.button() == Qt.MiddleButton:
            self._paste_to_ssh()
        else:
            super().mousePressEvent(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if self._selecting:
            col = max(0, min(self._cols - 1,
                       int(event.position().x() // self._cell_w)))
            row = max(0, min(self._rows - 1,
                       int(event.position().y() // self._cell_h)))
            self._sel_end = (row, col)
            self.update()
        else:
            super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.LeftButton and self._selecting:
            self._selecting = False
            self.setCursor(Qt.ArrowCursor)
            if self._sel_start == self._sel_end:
                self._clear_selection()
            else:
                self._copy_selection()
        else:
            super().mouseReleaseEvent(event)

    def contextMenuEvent(self, event) -> None:
        menu = QMenu(self)

        copy_action = QAction("📋 复制", menu)
        copy_action.setShortcut("Ctrl+Shift+C")
        copy_action.triggered.connect(self._copy_selection)
        copy_action.setEnabled(bool(self._sel_start))
        menu.addAction(copy_action)

        paste_action = QAction("📋 粘贴", menu)
        paste_action.setShortcut("Ctrl+Shift+V")
        paste_action.triggered.connect(self._paste_to_ssh)
        menu.addAction(paste_action)

        menu.addSeparator()

        zoom_in = QAction("🔍 放大", menu)
        zoom_in.setShortcut("Ctrl++")
        zoom_in.triggered.connect(lambda: self._change_font_size(1))
        menu.addAction(zoom_in)

        zoom_out = QAction("🔎 缩小", menu)
        zoom_out.setShortcut("Ctrl+-")
        zoom_out.triggered.connect(lambda: self._change_font_size(-1))
        menu.addAction(zoom_out)

        zoom_reset = QAction("↩️ 重置缩放", menu)
        zoom_reset.setShortcut("Ctrl+0")
        zoom_reset.triggered.connect(lambda: self._change_font_size(
            13 - self._font.pointSize()))
        menu.addAction(zoom_reset)

        menu.exec(event.globalPos())

    def wheelEvent(self, event: QWheelEvent) -> None:
        delta = event.angleDelta().y()
        sb_len = self._term.scrollback_len()
        if sb_len == 0:
            return

        self._wheel_accum += delta
        threshold = self._cell_h
        lines = self._wheel_accum // threshold
        if lines == 0:
            return
        self._wheel_accum %= threshold

        self._scroll_offset = max(0, min(sb_len,
                                  self._scroll_offset - lines))
        self.update()

    # ── Keyboard ─────────────────────────────────────────────────────────

    def keyPressEvent(self, event: QKeyEvent) -> None:
        key = event.key()
        mods = event.modifiers()

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
        if key == Qt.Key_PageUp and mods & Qt.ShiftModifier:
            sb_len = self._term.scrollback_len()
            self._scroll_offset = min(sb_len,
                                      self._scroll_offset + self._rows // 2)
            self.update()
            return
        if key == Qt.Key_PageDown and mods & Qt.ShiftModifier:
            self._scroll_offset = max(0,
                                      self._scroll_offset - self._rows // 2)
            self.update()
            return

        # Copy: Cmd+C (macOS) or Ctrl+Shift+C
        copy_key = key == Qt.Key_C
        copy_mod = bool(mods & Qt.ControlModifier)
        if sys.platform == "darwin":
            is_copy = copy_key and copy_mod and not (mods & Qt.ShiftModifier)
        else:
            is_copy = copy_key and copy_mod and bool(mods & Qt.ShiftModifier)
        if is_copy:
            self._copy_selection()
            return

        # Paste: Cmd+V (macOS) or Ctrl+Shift+V
        paste_key = key == Qt.Key_V
        paste_mod = bool(mods & Qt.ControlModifier)
        if sys.platform == "darwin":
            is_paste = paste_key and paste_mod and not (mods & Qt.ShiftModifier)
        else:
            is_paste = paste_key and paste_mod and bool(mods & Qt.ShiftModifier)
        if is_paste:
            self._clear_selection()
            if not self._display_only:
                clipboard = QApplication.clipboard()
                text = clipboard.text()
                if text:
                    self._term.write_str(text)
            return

        if not self._display_only:
            data = InputHandler.encode(event)
            if data:
                self._term.write(data)

    def inputMethodEvent(self, event: QInputMethodEvent) -> None:
        commit = event.commitString()
        if commit:
            self._term.write_str(commit)
        self._preedit = event.preeditString()
        self.update()

    def inputMethodQuery(self, query: Qt.InputMethodQuery):
        if query == Qt.ImCursorRectangle:
            try:
                cx, cy = self._term.cursor_position()
            except Exception:
                return QRectF()
            x = cx * self._cell_w
            y = cy * self._cell_h
            return QRectF(x, y, self._cell_w, self._cell_h)
        return None

    # ── Resize ────────────────────────────────────────────────────────────

    def resizeEvent(self, event: QResizeEvent) -> None:
        new_cols = max(1, self.width() // self._cell_w)
        new_rows = max(1, self.height() // self._cell_h)

        if new_cols != self._cols or new_rows != self._rows:
            self._cols = new_cols
            self._rows = new_rows
            self._term.resize(self._cols, self._rows)

        self.update()

    # ── Helpers ───────────────────────────────────────────────────────────

    def _toggle_cursor(self) -> None:
        self._cursor_visible = not self._cursor_visible
        self._blink_visible = not self._blink_visible
        self.update()

    def _change_font_size(self, delta: int) -> None:
        size = max(6, min(32, self._font.pointSize() + delta))
        self._font = _pick_monospace_font(size)
        self._fm = QFontMetrics(self._font)
        self._cell_w = int(max(self._fm.horizontalAdvance("M"), 1))
        self._cell_h = int(max(self._fm.height(), 1))

        self._font_bold = QFont(self._font)
        self._font_bold.setBold(True)
        self._font_italic = QFont(self._font)
        self._font_italic.setItalic(True)
        self._font_bold_italic = QFont(self._font)
        self._font_bold_italic.setBold(True)
        self._font_bold_italic.setItalic(True)

        new_cols = max(1, self.width() // self._cell_w)
        new_rows = max(1, self.height() // self._cell_h)
        self._cols = new_cols
        self._rows = new_rows
        self._term.resize(self._cols, self._rows)
        self.update()
