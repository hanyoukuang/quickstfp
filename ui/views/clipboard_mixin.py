from typing import List, Tuple, Any


class ClipboardMixin:
    """
    文件操作剪贴板混入类。
    管理复制/移动操作的路径暂存，供 LocalFileWidget 和 RemoteFileWidget 复用。
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._copy_paths: List[str] = []
        self._move_paths: List[Tuple[Any, str]] = []

    @property
    def has_clipboard(self) -> bool:
        return bool(self._copy_paths or self._move_paths)

    def _clipboard_copy(self, paths: List[str]) -> None:
        self._copy_paths = list(paths)
        self._move_paths.clear()

    def _clipboard_move(self, items_and_paths: List[Tuple[Any, str]]) -> None:
        self._move_paths = list(items_and_paths)
        self._copy_paths.clear()

    def _clipboard_clear(self) -> None:
        self._copy_paths.clear()
        self._move_paths.clear()
