# core/transport.py
import asyncio
import os
from typing import List, Tuple, Coroutine, Optional, Set

import asyncssh
from PySide6.QtCore import Signal, Slot, QObject

from core.session import SSHSFTPInfo
from utils.file_utils import path_stand


class ImmediateSchedulerPool:
    """
    异步任务并发控制池。
    限制最大协程并发数，并保证任务按特定优先级（大小）被调度。
    """

    def __init__(self, coro_num: int):
        self.max_workers = coro_num
        self.pending_tasks: List[Tuple[int, Coroutine, int]] = []
        self.running_tasks: Set[asyncio.Task] = set()
        self._big_task_ref: Optional[asyncio.Task] = None
        self._all_done_event = asyncio.Event()
        self._all_done_event.set()
        self._counter = 0
        self._stopped = False

    def _dispatch(self):
        if self._stopped:
            return

        while len(self.running_tasks) < self.max_workers and self.pending_tasks:
            self._all_done_event.clear()
            is_big_slot_open = (self._big_task_ref is None) or (self._big_task_ref.done())

            if is_big_slot_open:
                task_data = self.pending_tasks.pop()
                is_assigned_big = True
            else:
                task_data = self.pending_tasks.pop(0)
                is_assigned_big = False

            size, coro, _ = task_data
            task = asyncio.create_task(self._worker_wrapper(coro, size, is_assigned_big))
            self.running_tasks.add(task)

            if is_assigned_big:
                self._big_task_ref = task

    async def _worker_wrapper(self, coro: Coroutine, size: int, is_big: bool):
        try:
            await coro
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Task error: {e}")
        finally:
            current_task = asyncio.current_task()
            self.running_tasks.discard(current_task)

            if self._big_task_ref == current_task:
                self._big_task_ref = None

            self._dispatch()

            if not self.running_tasks and not self.pending_tasks:
                self._all_done_event.set()

    async def submit(self, task_coro_list: List[Tuple[int, Coroutine]]):
        if self._stopped:
            raise RuntimeError("Pool is stopped")

        for size, coro in task_coro_list:
            self._counter += 1
            self.pending_tasks.append((size, coro, self._counter))

        self.pending_tasks.sort(key=lambda x: x[0])
        self._dispatch()

    async def join(self):
        if not self.pending_tasks and not self.running_tasks:
            return
        await self._all_done_event.wait()

    async def cancel(self):
        self._stopped = True
        self.pending_tasks.clear()

        tasks_to_cancel = list(self.running_tasks)
        for t in tasks_to_cancel:
            t.cancel()

        if tasks_to_cancel:
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)

        self.running_tasks.clear()
        self._big_task_ref = None
        self._all_done_event.set()


class ProgressTracker:
    """独立的进度追踪器，用于替代原来臃肿的嵌套闭包"""

    def __init__(self, transport_instance: 'Transport'):
        self.transport = transport_instance
        self.last_size = 0

    def __call__(self, _src: bytes, _loc: bytes, now_size: int, _all_size: int) -> None:
        """被 asyncssh 调用，更新传输进度"""
        delta = now_size - self.last_size
        self.transport._total_progress_size += delta
        self.transport.progress_updated.emit(self.transport._total_progress_size)
        self.last_size = now_size

    def handle_fail(self, all_size: int, src: str) -> None:
        """发生异常时调用，补齐因失败丢失的进度条长度，并记录失败文件"""
        delta = all_size - self.last_size
        self.transport._total_progress_size += delta
        self.transport.progress_updated.emit(self.transport._total_progress_size)
        self.transport.transport_fail_filename += f"{src}\n"


class Transport(QObject):
    """
    基础传输核心类。完全脱离 UI 控件依赖，仅通过信号(Signal)进行状态广播。
    """
    # 解耦专用信号：UI 层只需监听这些信号即可更新进度条
    progress_updated = Signal(int)  # 更新当前进度
    range_initialized = Signal(int)  # 初始化总任务大小
    transport_failed = Signal(str)  # 传输失败的异常文件信息
    transport_cancelled = Signal()  # 任务被取消

    def __init__(self, src: str, loc: str, co_num: int, info: 'SSHSFTPInfo') -> None:
        super().__init__()
        self.is_cancel = False
        self.src = src
        self.loc = loc
        self.co_num = co_num
        self.sftp = info.sftp
        self.loop = info.loop
        self.transport_coro_list = []
        self.pool: Optional[ImmediateSchedulerPool] = None

        self.transport_fail_filename = ""
        # 用于记录当前传输的总量（取代原先 UI 控件中维护的进度值）
        self._total_progress_size = 0

    async def transport(self):
        raise NotImplementedError("Subclasses should implement this method.")

    def _on_transport_done(self, future):
        """传输协程结束后的回调，负责发出失败异常通知"""
        try:
            future.result()
        except asyncio.CancelledError:
            # 任务被用户主动取消，属于正常行为，忽略即可
            pass
        except Exception as e:
            # 捕获整个传输过程中的致命异常（如断网），通过信号发给UI层
            self.transport_failed.emit(f"传输任务异常中止: {str(e)}")

        # 这里保留原来的逻辑：通知具体哪些文件失败了
        if self.transport_fail_filename:
            self.transport_failed.emit(f"部分文件读写失败:\n{self.transport_fail_filename}")

    def start(self):
        """启动传输任务（调度到后台事件循环）"""
        future = asyncio.run_coroutine_threadsafe(self.transport(), self.loop)
        future.add_done_callback(self._on_transport_done)

    @Slot()
    def cancel(self):
        """取消传输任务"""
        try:
            if self.pool:
                future = asyncio.run_coroutine_threadsafe(self.pool.cancel(), self.loop)
                future.result()
        except Exception:
            pass
        self.transport_cancelled.emit()
        self.is_cancel = True

    def __call__(self, *args, **kwargs):
        self.start()


class GET(Transport):
    """下载任务核心类"""

    def __init__(self, src: str, loc: str, co_num: int, info: 'SSHSFTPInfo') -> None:
        super().__init__(src, loc, co_num, info)

    async def _transport_file(self, src: str, loc: str) -> None:
        tracker = ProgressTracker(self)
        try:
            await self.sftp.get(src, loc, progress_handler=tracker)
        except (OSError, asyncssh.SFTPError):
            all_size = await self.sftp.getsize(src)
            tracker.handle_fail(all_size, src)

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
            self.range_initialized.emit(all_size)
            await self.pool.submit(self.transport_coro_list)
        else:
            all_size = await self.sftp.getsize(src)
            self.range_initialized.emit(all_size)
            await self.pool.submit([(all_size, self._transport_file(src, loc))])
        await self.pool.join()


class PUT(Transport):
    """上传任务核心类"""

    def __init__(self, src: str, loc: str, co_num: int, session: 'SSHSFTPInfo') -> None:
        super().__init__(src, loc, co_num, session)
        self.task_list_mkdir = []

    async def _transport_file(self, src: str, loc: str) -> None:
        tracker = ProgressTracker(self)
        try:
            await self.sftp.put(src, loc, progress_handler=tracker)
        except (OSError, asyncssh.SFTPError, asyncio.CancelledError):
            all_size = os.path.getsize(src)
            tracker.handle_fail(all_size, src)

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
            self.range_initialized.emit(all_size)
            for future in asyncio.as_completed(self.task_list_mkdir):
                await future
            await self.pool.submit(self.transport_coro_list)
        else:
            all_size = os.path.getsize(src)
            self.range_initialized.emit(all_size)
            await self.pool.submit([(all_size, self._transport_file(src, loc))])
        await self.pool.join()
