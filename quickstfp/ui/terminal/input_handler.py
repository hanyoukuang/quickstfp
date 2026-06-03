"""Encode QKeyEvent into terminal input bytes."""

import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeyEvent


class InputHandler:
    """Convert Qt keyboard events to terminal escape sequences.

    Handles:
      - Plain text (including Unicode)
      - Ctrl+key combinations (C0 control codes)
      - Alt+key (ESC-prefixed)
      - Special keys (arrows, home/end, F1-F12, etc.)
      - Shift+Tab
    """

    # Mapping of Qt key codes to terminal escape sequences
    _KEY_SEQUENCES: dict[int, bytes] = {
        Qt.Key_Up: b"\x1b[A",
        Qt.Key_Down: b"\x1b[B",
        Qt.Key_Right: b"\x1b[C",
        Qt.Key_Left: b"\x1b[D",
        Qt.Key_Home: b"\x1b[H",
        Qt.Key_End: b"\x1b[F",
        Qt.Key_PageUp: b"\x1b[5~",
        Qt.Key_PageDown: b"\x1b[6~",
        Qt.Key_Backspace: b"\x7f",
        Qt.Key_Delete: b"\x1b[3~",
        Qt.Key_Insert: b"\x1b[2~",
        Qt.Key_Return: b"\r",
        Qt.Key_Enter: b"\r",
        Qt.Key_Tab: b"\t",
        Qt.Key_Escape: b"\x1b",
        Qt.Key_F1: b"\x1bOP",
        Qt.Key_F2: b"\x1bOQ",
        Qt.Key_F3: b"\x1bOR",
        Qt.Key_F4: b"\x1bOS",
        Qt.Key_F5: b"\x1b[15~",
        Qt.Key_F6: b"\x1b[17~",
        Qt.Key_F7: b"\x1b[18~",
        Qt.Key_F8: b"\x1b[19~",
        Qt.Key_F9: b"\x1b[20~",
        Qt.Key_F10: b"\x1b[21~",
        Qt.Key_F11: b"\x1b[23~",
        Qt.Key_F12: b"\x1b[24~",
    }

    _MODIFIER_ONLY_KEYS = {
        Qt.Key_Control, Qt.Key_Shift,
        Qt.Key_Alt, Qt.Key_Meta,
        Qt.Key_Super_L, Qt.Key_Super_R,
        Qt.Key_CapsLock, Qt.Key_NumLock,
    }

    @classmethod
    def encode(cls, event: QKeyEvent) -> bytes | None:
        """Encode a QKeyEvent into terminal input bytes.

        Returns None if the key should not be sent to the PTY.
        """
        key = event.key()
        modifiers = event.modifiers()
        text = event.text()

        # Ignore modifier-only keys
        if key in cls._MODIFIER_ONLY_KEYS:
            return None

        # --- Ctrl+key → C0 control codes (0x00-0x1F) ---
        if sys.platform == "darwin":
            ctrl_pressed = bool(modifiers & Qt.MetaModifier)
        else:
            ctrl_pressed = bool(modifiers & Qt.ControlModifier)

        if ctrl_pressed:
            if text:
                return text.encode("utf-8")
            if Qt.Key_A <= key <= Qt.Key_Z:
                return bytes([key - Qt.Key_A + 1])
            seq = cls._KEY_SEQUENCES.get(key)
            if seq:
                return seq
            return None

        # --- Alt+key → ESC prefix ---
        if modifiers & Qt.AltModifier:
            if key in cls._KEY_SEQUENCES:
                return b"\x1b" + cls._KEY_SEQUENCES[key]
            if text:
                return b"\x1b" + text.encode("utf-8")
            return None

        # --- Shift+Tab → back-tab ---
        if key == Qt.Key_Tab and modifiers & Qt.ShiftModifier:
            return b"\x1b[Z"

        # --- Special keys ---
        seq = cls._KEY_SEQUENCES.get(key)
        if seq is not None:
            return seq

        # --- Plain text (including with Shift for uppercase) ---
        if text:
            return text.encode("utf-8")

        return None
