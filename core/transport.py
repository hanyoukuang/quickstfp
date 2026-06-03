# core/transport.py
import asyncio
import logging
import os
import time
from fnmatch import fnmatch
from typing import List, Tuple, Coroutine, Optional, Set

import asyncssh
from PySide6.QtCore import Signal, Slot, QObject

from core.session import SSHSFTPInfo
from utils.file_utils import path_stand

logger = logging.getLogger(__name__)


class SpeedLimiter:
    """基于令牌桶算法的全局限速器（支持多协程共享）"""

    def __init__(self, limit_kbps: int):
        # 内部换算为 Byte/s
        self.limit_bps = limit_kbps * 1024
        self.tokens = self.limit_bps
        self.last_time = time.monotonic()
        self.lock = asyncio.Lock()

    async def consume(self, amount: int):
        if self.limit_bps <= 0:
            return

        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_time

            # 补充这段时间内产生的令牌，上限不超过一秒的量
            self.tokens = min(self.limit_bps, self.tokens + elapsed * self.limit_bps)

            if self.tokens < amount:
                # 令牌不够，计算需要等待的时间
                wait_time = (amount - self.tokens) / self.limit_bps
                await asyncio.sleep(wait_time)
                # 睡醒后，更新时间和清空令牌（相当于刚好消耗完这些时间的产出）
                self.last_time = time.monotonic()
                self.tokens = 0
            else:
                # 令牌充足，直接扣除
                self.tokens -= amount
                self.last_time = now


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
            logger.error(f"Task error: {e}")
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
    """独立的进度追踪器，支持断点续传的初始进度偏移和网速计算"""

    def __init__(self, transport_instance: 'Transport', initial_size: int = 0):
        self.transport = transport_instance
        self.last_size = initial_size  # 记录初始偏移量

        # 如果是断点续传，初始化时就把已存在的文件大小加到总进度中
        if initial_size > 0:
            self.transport._total_progress_size += initial_size
            self.transport.progress_updated.emit(self.transport._total_progress_size)

    async def __call__(self, _src: bytes, _loc: bytes, now_size: int, _all_size: int) -> None:
        delta = now_size - self.last_size
        async with self.transport._state_lock:
            self.transport._total_progress_size += delta
            self.transport.progress_updated.emit(self.transport._total_progress_size)
        self.last_size = now_size

        now_time = time.monotonic()
        time_delta = now_time - self.transport._last_time
        if time_delta >= 0.5:
            async with self.transport._state_lock:
                size_delta = self.transport._total_progress_size - self.transport._last_speed_size
                speed = size_delta / time_delta
                self.transport._last_time = now_time
                self.transport._last_speed_size = self.transport._total_progress_size
            self.transport.speed_updated.emit(self._format_speed(speed))

    async def handle_fail(self, all_size: int, src: str) -> None:
        delta = all_size - self.last_size
        async with self.transport._state_lock:
            self.transport._total_progress_size += delta
            self.transport.transport_fail_filename += f"{src}\n"
        self.transport.progress_updated.emit(self.transport._total_progress_size)

    def _format_speed(self, speed_bytes: float) -> str:
        """网速格式化"""
        if speed_bytes >= 1024 * 1024 * 1024:
            return f"{speed_bytes / (1024 * 1024 * 1024):.2f} GB/s"
        elif speed_bytes >= 1024 * 1024:
            return f"{speed_bytes / (1024 * 1024):.2f} MB/s"
        elif speed_bytes >= 1024:
            return f"{speed_bytes / 1024:.2f} KB/s"
        else:
            return f"{speed_bytes:.2f} B/s"


class Transport(QObject):
    """
    基础传输核心类。完全脱离 UI 控件依赖，仅通过信号(Signal)进行状态广播。
    """
    # 解耦专用信号：UI 层只需监听这些信号即可更新进度条
    progress_updated = Signal(int)  # 更新当前进度
    range_initialized = Signal(int)  # 初始化总任务大小
    transport_failed = Signal(str)  # 传输失败的异常文件信息
    transport_cancelled = Signal()  # 任务被取消
    speed_updated = Signal(str)  # 网速
    transport_completed = Signal()  # 所有传输任务完成

    def __init__(self, src: str, loc: str, co_num: int, speed_limit: int, info: 'SSHSFTPInfo') -> None:
        super().__init__()
        self.is_cancel = False
        self.src = src
        self.loc = loc
        self.co_num = co_num
        self.speed_limit = speed_limit
        self.limiter = SpeedLimiter(speed_limit)
        self.sftp = info.sftp
        self.loop = info.loop
        self.transport_coro_list = []
        self.pool: Optional[ImmediateSchedulerPool] = None
        self.filter_patterns = ""

        self.transport_fail_filename = ""
        self._total_progress_size = 0
        self._last_time = time.monotonic()
        self._last_speed_size = 0
        self.pause_event = None
        self._state_lock = asyncio.Lock()

    @Slot()
    def toggle_pause(self):
        """切换暂停状态槽函数"""

        # --- 修改 3：UI 线程触发时，必须将状态的修改抛回给后台事件循环去执行 ---
        def _toggle():
            if self.pause_event:
                if self.pause_event.is_set():
                    self.pause_event.clear()
                else:
                    self.pause_event.set()

        self.loop.call_soon_threadsafe(_toggle)

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

        self.transport_completed.emit()

    def start(self):
        """启动传输任务（调度到后台事件循环）"""

        # --- 修改 2：利用包装函数，在后台的 asyncio 循环内部创建并启动事件锁 ---
        async def _wrapper():
            self.pause_event = asyncio.Event()
            self.pause_event.set()  # 默认状态为放行
            await self.transport()

        future = asyncio.run_coroutine_threadsafe(_wrapper(), self.loop)
        future.add_done_callback(self._on_transport_done)

    @Slot()
    def cancel(self):
        """取消传输任务"""
        try:
            if self.pool:
                # 仅通知后台事件循环取消任务，绝不能使用 future.result() 阻塞 UI 线程
                asyncio.run_coroutine_threadsafe(self.pool.cancel(), self.loop)
        except Exception as e:
            logger.debug(f"Cancel pool error (non-critical): {e}")
        self.transport_cancelled.emit()
        self.is_cancel = True

        # --- 新增：如果在暂停状态下取消，需要强制打开锁，否则任务会死等，无法响应取消信号 ---
        if self.pause_event and not self.pause_event.is_set():
            self.loop.call_soon_threadsafe(self.pause_event.set)

    def __call__(self, *args, **kwargs):
        self.start()

    def _calc_chunk_size(self) -> int:
        if self.speed_limit <= 0:
            return 1024 * 1024
        return min(1024 * 1024, max(1024 * 32, self.speed_limit * 1024))

    @staticmethod
    def _resume_state(target_size: int, source_size: int) -> tuple:
        if target_size == source_size and source_size != 0:
            return 'wb', target_size, True
        if 0 < target_size < source_size:
            return 'ab', target_size, False
        return 'wb', 0, False

    def _should_skip_file(self, filename: str) -> bool:
        patterns = self.filter_patterns.strip()
        if not patterns:
            return False
        for p in patterns.split(";"):
            p = p.strip()
            if p and (fnmatch(filename, p) or p in filename):
                return True
        return False


class GET(Transport):
    """下载任务核心类"""

    def __init__(self, src: str, loc: str, co_num: int, speed_limit: int, info: 'SSHSFTPInfo') -> None:
        super().__init__(src, loc, co_num, speed_limit, info)

    async def _transport_file(self, src: str, loc: str) -> None:
        try:
            remote_size = await self.sftp.getsize(src)
            local_size = os.path.getsize(loc) if os.path.exists(loc) else 0

            mode, start_pos, is_done = self._resume_state(local_size, remote_size)
            if is_done:
                ProgressTracker(self, initial_size=local_size)
                return

            tracker = ProgressTracker(self, initial_size=start_pos)
            chunk_size = self._calc_chunk_size()

            async with self.sftp.open(src, 'rb') as remote_file:
                if start_pos > 0:
                    await remote_file.seek(start_pos)
                with open(loc, mode) as local_file:
                    now_size = start_pos
                    while True:
                        await self.pause_event.wait()
                        await self.limiter.consume(chunk_size)
                        chunk = await remote_file.read(chunk_size)
                        if not chunk:
                            break
                        local_file.write(chunk)
                        now_size += len(chunk)
                        await tracker(b'', b'', now_size, remote_size)

        except asyncio.CancelledError:
            # 捕获用户主动取消的信号，直接退出，绝不能调用 handle_fail 抛出任何进度条信号
            raise
        except (OSError, asyncssh.SFTPError):
            # 真正的网络传输故障，才发送失败日志和补偿进度
            all_size = await self.sftp.getsize(src)
            tracker = ProgressTracker(self)
            await tracker.handle_fail(all_size, src)

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
                if self._should_skip_file(entry.filename):
                    continue
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

    def __init__(self, src: str, loc: str, co_num: int, speed_limit: int, session: 'SSHSFTPInfo') -> None:
        super().__init__(src, loc, co_num, speed_limit, session)
        self.task_list_mkdir = []

    async def _transport_file(self, src: str, loc: str) -> None:
        try:
            local_size = os.path.getsize(src)
            try:
                remote_size = (await self.sftp.stat(loc)).size
            except asyncssh.SFTPNoSuchFile:
                remote_size = 0

            mode, start_pos, is_done = self._resume_state(remote_size, local_size)
            if is_done:
                ProgressTracker(self, initial_size=remote_size)
                return

            tracker = ProgressTracker(self, initial_size=start_pos)
            chunk_size = self._calc_chunk_size()

            async with self.sftp.open(loc, mode) as remote_file:
                if start_pos > 0:
                    await remote_file.seek(start_pos)
                with open(src, 'rb') as local_file:
                    local_file.seek(start_pos)
                    now_size = start_pos
                    while True:
                        await self.pause_event.wait()
                        await self.limiter.consume(chunk_size)
                        chunk = local_file.read(chunk_size)
                        if not chunk:
                            break
                        await remote_file.write(chunk)
                        now_size += len(chunk)
                        await tracker(b'', b'', now_size, local_size)

        except asyncio.CancelledError:
            # 用户主动取消，静默退出
            raise
        except (OSError, asyncssh.SFTPError):
            all_size = os.path.getsize(src)
            tracker = ProgressTracker(self)
            await tracker.handle_fail(all_size, src)

    async def search_transport_file(self, src: str, loc: str) -> int:
        total_size = 0
        self.task_list_mkdir.append(self.sftp.makedirs(loc, exist_ok=True))
        loop = asyncio.get_event_loop()
        entries = await loop.run_in_executor(None, lambda: list(os.scandir(src)))
        for entry in entries:
            next_src = "/".join((src, entry.name))
            next_loc = "/".join((loc, entry.name))
            if entry.is_dir():
                total_size += await self.search_transport_file(next_src, next_loc)
            else:
                if self._should_skip_file(entry.name):
                    continue
                self.transport_coro_list.append((entry.stat().st_size, self._transport_file(next_src, next_loc)))
                total_size += entry.stat().st_size
        return total_size

    async def transport(self) -> None:
        self.pool = ImmediateSchedulerPool(self.co_num)
        src, loc = path_stand(self.src, self.loc)
        if os.path.isdir(src):
            all_size = await self.search_transport_file(src, loc)
            self.range_initialized.emit(all_size)
            for future in asyncio.as_completed(self.task_list_mkdir):
                await future
            await self.pool.submit(self.transport_coro_list)
        else:
            all_size = os.path.getsize(src)
            self.range_initialized.emit(all_size)
            await self.pool.submit([(all_size, self._transport_file(src, loc))])
        await self.pool.join()
