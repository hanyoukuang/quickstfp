import asyncio
import os
from typing import List, Tuple, Coroutine, Optional, Set

import asyncssh
from PySide6.QtCore import Signal, Slot
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QProgressBar, QWidget, QHBoxLayout, QLabel, QMessageBox, QPushButton

from session import SSHSFTPInfo


class ImmediateSchedulerPool:
    """
    由gemini3 pro生成
    """

    def __init__(self, coro_num: int):
        self.max_workers = coro_num

        # 任务队列：(size, coro, id)
        # 保持有序：index 0 是最小，index -1 是最大
        self.pending_tasks: List[Tuple[int, Coroutine, int]] = []

        # 正在运行的任务集合
        self.running_tasks: Set[asyncio.Task] = set()

        # 记录当前谁占据了“最大任务”的王位 (存储 Task 对象)
        self._big_task_ref: Optional[asyncio.Task] = None

        # 用于 join 等待的事件
        self._all_done_event = asyncio.Event()
        self._all_done_event.set()  # 初始状态是空闲的

        self._counter = 0
        self._stopped = False

    def _dispatch(self):
        """
        调度员：每次被调用时，只要有空位就填满。
        这个方法是非阻塞的，会立即安排任务。
        """
        if self._stopped:
            return

        # 只要 正在运行数 < 最大并发 且 还有库存
        while len(self.running_tasks) < self.max_workers and self.pending_tasks:

            # 清除全完成标记
            self._all_done_event.clear()

            # --- 决策逻辑 ---
            # 1. 检查王位是否空缺（或者占据王位的任务其实已经运行完了）
            is_big_slot_open = (self._big_task_ref is None) or (self._big_task_ref.done())

            task_data = None
            is_assigned_big = False

            if is_big_slot_open:
                # 👑 王位空缺 -> 必须取最大的 (List 尾部)
                task_data = self.pending_tasks.pop()
                is_assigned_big = True
                # print(f"调度: 取出最大 size={task_data[0]}")
            else:
                # ⚡ 王位有人 -> 只能取最小的插空 (List 头部)
                task_data = self.pending_tasks.pop(0)
                is_assigned_big = False
                # print(f"调度: 取出最小 size={task_data[0]}")

            # --- 启动任务 ---
            size, coro, _ = task_data

            # 包装协程以处理回调
            task = asyncio.create_task(self._worker_wrapper(coro, size, is_assigned_big))

            self.running_tasks.add(task)

            if is_assigned_big:
                self._big_task_ref = task

    async def _worker_wrapper(self, coro: Coroutine, size: int, is_big: bool):
        """包装器：负责执行并在结束后再次触发调度"""
        try:
            await coro
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Task error: {e}")
        finally:
            # 1. 从运行集合移除
            current_task = asyncio.current_task()
            self.running_tasks.discard(current_task)

            # 2. 如果我是大王，我退位了 (Dispatch 中会通过 _big_task_ref.done() 判断，这里设为 None 更保险)
            if self._big_task_ref == current_task:
                self._big_task_ref = None

            # 3. 核心：我结束了，可能有坑位了，立刻触发调度！
            self._dispatch()

            # 4. 检查是否全部完成以解除 join
            if not self.running_tasks and not self.pending_tasks:
                self._all_done_event.set()

    async def submit(self, task_coro_list: List[Tuple[int, Coroutine]]):
        if self._stopped:
            raise RuntimeError("Pool is stopped")

        for size, coro in task_coro_list:
            self._counter += 1
            self.pending_tasks.append((size, coro, self._counter))

        # 排序：小 -> 大
        self.pending_tasks.sort(key=lambda x: x[0])

        # 有新任务了，触发调度
        self._dispatch()

    async def join(self):
        """等待所有任务完成"""
        if not self.pending_tasks and not self.running_tasks:
            return
        await self._all_done_event.wait()

    async def cancel(self):
        self._stopped = True
        # 1. 倒掉所有没下锅的菜
        self.pending_tasks.clear()

        # 2. 掀翻所有正在煮的锅
        # 复制一份列表进行取消，避免遍历时集合变动
        tasks_to_cancel = list(self.running_tasks)
        for t in tasks_to_cancel:
            t.cancel()

        # 3. 等待清理现场
        if tasks_to_cancel:
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)

        self.running_tasks.clear()
        self._big_task_ref = None
        self._all_done_event.set()
        print(">> Pool Cancelled")


def path_stand(src: str, loc: str) -> tuple[str, str]:
    src = src.replace('\\', '/').rstrip('/')
    loc = loc.replace('\\', '/').rstrip('/')
    loc = '/'.join((loc, src.split('/')[-1]))
    return src, loc


class ProgressBar(QWidget):
    now_progressbar_size: int = 0
    update_pbar_msg = Signal(int)
    init_pbar_msg = Signal(int)
    transport_fail_msg = Signal(str)
    del_widget_msg = Signal()

    def __init__(self, filename: str, transport_type: str, icon: QIcon):
        super().__init__()
        self.icon = icon
        self.layout = QHBoxLayout(self)
        self.filename_label = QLabel(f"{transport_type}: {filename}")
        self.picture_label = QLabel()
        self.progress_bar = QProgressBar()
        self.cancel_button = QPushButton("Cancel")
        self.init_ui()

    def init_ui(self):
        self.picture_label.setPixmap(self.icon.pixmap(16, 16))
        self.layout.addWidget(self.filename_label)
        self.layout.addWidget(self.picture_label)
        self.layout.addWidget(self.progress_bar)
        self.layout.addWidget(self.cancel_button)
        self.setLayout(self.layout)
        self.update_pbar_msg.connect(lambda value: self.progress_bar.setValue(value))
        self.init_pbar_msg.connect(lambda value: self.progress_bar.setRange(0, value))
        self.transport_fail_msg.connect(self.warning_transport_fail_filename)

    @Slot(str)
    def warning_transport_fail_filename(self, value: str):
        if value:
            QMessageBox.warning(self, "传输警告", f"传输失败" + value, QMessageBox.StandardButton.Ok)


class Transport:
    transport_future: asyncio.Future
    pool: ImmediateSchedulerPool

    def __init__(self, src: str, loc: str, co_num: int, info: 'SSHSFTPInfo', pbar: ProgressBar) -> None:
        super().__init__()
        self.src = src
        self.loc = loc
        self.co_num = co_num
        self.sftp = info.sftp
        self.loop = info.loop
        self.transport_coro_list = []
        self.pbar = pbar
        self.update_pbar_msg = pbar.update_pbar_msg
        self.init_pbar_msg = pbar.init_pbar_msg
        self.transport_fail_msg = pbar.transport_fail_msg
        self.transport_fail_filename = ""
        self.pbar.cancel_button.clicked.connect(self.cancel)

    async def transport(self):
        pass

    def warning_transport_fail_filename(self, fn):
        try:
            fn.result()
        except:
            pass
        self.transport_fail_msg.emit(self.transport_fail_filename)

    def start(self):
        future = asyncio.run_coroutine_threadsafe(self.transport(), self.loop)
        future.add_done_callback(self.warning_transport_fail_filename)

    def cancel(self):
        try:
            future = asyncio.run_coroutine_threadsafe(self.pool.cancel(), self.loop)
            future.result()
        except:
            pass
        finally:
            self.pbar.del_widget_msg.emit()

    def __call__(self, *args, **kwargs):
        self.start()


class GET(Transport):
    def __init__(self, src: str, loc: str, co_num: int, info: 'SSHSFTPInfo', pbar: ProgressBar) -> None:
        super().__init__(src, loc, co_num, info, pbar)

    async def _transport_file(self, src: str, loc: str) -> None:
        last_size = 0

        def update(_src: bytes, _loc: bytes, now_size: int, _all_size: int) -> None:
            nonlocal last_size
            self.update_pbar_msg.emit(self.pbar.now_progressbar_size + now_size - last_size)
            self.pbar.now_progressbar_size += now_size - last_size
            last_size = now_size

        # async with self.semaphore:
        try:
            await self.sftp.get(src, loc, progress_handler=update)
        except (OSError, asyncssh.SFTPError):
            all_size = await self.sftp.getsize(src)
            self.update_pbar_msg.emit(self.pbar.now_progressbar_size + all_size - last_size)
            self.pbar.now_progressbar_size += all_size - last_size
            self.transport_fail_filename += f"{src}\n"

    async def search_transport_file(self, src: str, loc: str) -> int:
        if not os.path.exists(loc):
            os.mkdir(loc)
        task_list = []
        total = 0
        async for entry in self.sftp.scandir(src):
            if entry.filename in ('.', '..'):
                continue
            next_src = "/".join((src, entry.filename))
            next_loc = "/".join((loc, entry.filename))
            if entry.attrs.type == 2:  # Directory
                task_list.append(asyncio.create_task(self.search_transport_file(next_src, next_loc)))
            else:  # File
                total += entry.attrs.size
                self.transport_coro_list.append((entry.attrs.size, self._transport_file(next_src, next_loc)))
        for future in asyncio.as_completed(task_list):
            total += await future
        return total

    async def transport(self) -> None:
        self.pool = ImmediateSchedulerPool(self.co_num)
        src, loc = path_stand(self.src, self.loc)
        if await self.sftp.isdir(src):
            all_size = await self.search_transport_file(src, loc)
            self.init_pbar_msg.emit(all_size)
            await self.pool.submit(self.transport_coro_list)
        else:
            all_size = await self.sftp.getsize(src)
            self.init_pbar_msg.emit(all_size)
            await self.pool.submit([(all_size, self._transport_file(src, loc))])
        await self.pool.join()


class PUT(Transport):
    def __init__(self, src: str, loc: str, co_num: int, session: 'SSHSFTPInfo', pbar: ProgressBar) -> None:
        super().__init__(src, loc, co_num, session, pbar)
        self.task_list_mkdir = []

    async def _transport_file(self, src: str, loc: str) -> None:
        last_size = 0

        def update(_src: bytes, _loc: bytes, now_size: int, _all_size: int) -> None:
            nonlocal last_size
            self.update_pbar_msg.emit(self.pbar.now_progressbar_size + now_size - last_size)
            self.pbar.now_progressbar_size += now_size - last_size
            last_size = now_size

        try:
            await self.sftp.put(src, loc, progress_handler=update)
        except (OSError, asyncssh.SFTPError, asyncio.CancelledError):
            all_size = os.path.getsize(src)
            self.update_pbar_msg.emit(self.pbar.now_progressbar_size + all_size - last_size)
            self.pbar.now_progressbar_size += all_size - last_size
            self.transport_fail_filename += f"{src}\n"

    def search_transport_file(self, src: str, loc: str) -> int:
        total_size = 0
        self.task_list_mkdir.append(self.sftp.makedirs(loc, exist_ok=True))
        for entry in os.scandir(src):
            next_src = "/".join((src, entry.name))
            next_loc = "/".join((loc, entry.name))
            if entry.is_dir():
                total_size += self.search_transport_file(next_src, next_loc)
            else:
                self.transport_coro_list.append((entry.stat().st_size, self._transport_file(next_src, next_loc)))
                total_size += entry.stat().st_size
        return total_size

    async def transport(self) -> None:
        self.pool = ImmediateSchedulerPool(self.co_num)
        src, loc = path_stand(self.src, self.loc)
        if os.path.isdir(src):
            all_size = self.search_transport_file(src, loc)
            self.init_pbar_msg.emit(all_size)
            for future in asyncio.as_completed(self.task_list_mkdir):
                await future
            await self.pool.submit(self.transport_coro_list)
        else:
            all_size = os.path.getsize(src)
            self.init_pbar_msg.emit(all_size)
            await self.pool.submit([(all_size, self._transport_file(src, loc))])
        await self.pool.join()
