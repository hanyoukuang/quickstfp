import asyncio
import os
import time
from dataclasses import dataclass
from typing import List, Tuple, Coroutine, Optional, Set, Callable, Any

import asyncssh

from app.core.speed_limiter import SpeedLimiter
from utils.file_utils import path_stand


@dataclass
class TransportEvent:
    """标准化传输事件"""
    type: str
    data: Any = None


ProgressCallback = Callable[[TransportEvent], None]


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
            is_big_slot_open = (self._big_task_ref is None) or (
                self._big_task_ref.done()
            )

            if is_big_slot_open:
                task_data = self.pending_tasks.pop()
                is_assigned_big = True
            else:
                task_data = self.pending_tasks.pop(0)
                is_assigned_big = False

            size, coro, _ = task_data
            task = asyncio.create_task(
                self._worker_wrapper(coro, size, is_assigned_big)
            )
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
    """独立的进度追踪器，支持断点续传的初始进度偏移和网速计算"""

    def __init__(
        self,
        on_event: ProgressCallback,
        transport_instance: "Transport",
        initial_size: int = 0,
    ):
        self.on_event = on_event
        self.transport = transport_instance
        self.last_size = initial_size

        if initial_size > 0:
            self.transport._total_progress_size += initial_size
            self.on_event(TransportEvent(
                type="progress",
                data=self.transport._total_progress_size,
            ))

    def __call__(self, _src: bytes, _loc: bytes, now_size: int, _all_size: int) -> None:
        delta = now_size - self.last_size
        self.transport._total_progress_size += delta
        self.on_event(TransportEvent(
            type="progress",
            data=self.transport._total_progress_size,
        ))
        self.last_size = now_size

        now_time = time.time()
        time_delta = now_time - self.transport._last_time
        if time_delta >= 0.5:
            size_delta = (
                self.transport._total_progress_size
                - self.transport._last_speed_size
            )
            speed = size_delta / time_delta
            self.on_event(TransportEvent(
                type="speed",
                data=self._format_speed(speed),
            ))

            self.transport._last_time = now_time
            self.transport._last_speed_size = (
                self.transport._total_progress_size
            )

    def handle_fail(self, all_size: int, src: str) -> None:
        delta = all_size - self.last_size
        self.transport._total_progress_size += delta
        self.on_event(TransportEvent(
            type="progress",
            data=self.transport._total_progress_size,
        ))
        self.transport.transport_fail_filename += f"{src}\n"

    def _format_speed(self, speed_bytes: float) -> str:
        if speed_bytes >= 1024 * 1024 * 1024:
            return f"{speed_bytes / (1024 * 1024 * 1024):.2f} GB/s"
        elif speed_bytes >= 1024 * 1024:
            return f"{speed_bytes / (1024 * 1024):.2f} MB/s"
        elif speed_bytes >= 1024:
            return f"{speed_bytes / 1024:.2f} KB/s"
        else:
            return f"{speed_bytes:.2f} B/s"


class Transport:
    """
    基础传输核心类。完全脱离 UI 控件依赖，通过回调 (on_event) 进行状态广播。
    """

    def __init__(
        self,
        src: str,
        loc: str,
        co_num: int,
        speed_limit: int,
        sftp: "asyncssh.SFTPClient",
        on_event: ProgressCallback,
    ) -> None:
        self.is_cancel = False
        self.src = src
        self.loc = loc
        self.co_num = co_num
        self.speed_limit = speed_limit
        self.limiter = SpeedLimiter(speed_limit)
        self.sftp = sftp
        self.on_event = on_event
        self.transport_coro_list: List[Tuple[int, Coroutine]] = []
        self.pool: Optional[ImmediateSchedulerPool] = None

        self.transport_fail_filename = ""
        self._total_progress_size = 0
        self._last_time = time.time()
        self._last_speed_size = 0
        self.pause_event: Optional[asyncio.Event] = None

    def toggle_pause(self):
        """切换暂停状态"""
        if self.pause_event is None:
            return
        if self.pause_event.is_set():
            self.pause_event.clear()
        else:
            self.pause_event.set()

    async def transport(self):
        raise NotImplementedError("Subclasses should implement this method.")

    async def start(self):
        """启动传输任务"""
        self.pause_event = asyncio.Event()
        self.pause_event.set()
        await self.transport()

    async def cancel(self):
        """取消传输任务"""
        try:
            if self.pool:
                await self.pool.cancel()
        except Exception:
            pass
        self.is_cancel = True
        self.on_event(TransportEvent(type="cancelled"))

        if self.pause_event and not self.pause_event.is_set():
            self.pause_event.set()

    def __call__(self, *args, **kwargs):
        raise RuntimeError("Use await transport.start() instead of calling directly")


class GET(Transport):
    """下载任务核心类"""

    async def _transport_file(self, src: str, loc: str) -> None:
        try:
            remote_size = await self.sftp.getsize(src)
            local_size = os.path.getsize(loc) if os.path.exists(loc) else 0

            mode = "ab" if 0 < local_size < remote_size else "wb"
            start_pos = local_size if 0 < local_size < remote_size else 0

            if local_size == remote_size and remote_size != 0:
                ProgressTracker(self.on_event, self, initial_size=local_size)
                return

            tracker = ProgressTracker(self.on_event, self, initial_size=start_pos)

            chunk_size = 1024 * 1024
            if self.speed_limit > 0:
                chunk_size = min(
                    1024 * 1024, max(1024 * 32, self.speed_limit * 1024)
                )

            async with self.sftp.open(src, "rb") as remote_file:
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
                        tracker(b"", b"", now_size, remote_size)

        except asyncio.CancelledError:
            raise
        except (OSError, asyncssh.SFTPError):
            all_size = await self.sftp.getsize(src)
            tracker = ProgressTracker(self.on_event, self)
            tracker.handle_fail(all_size, src)

    async def search_transport_file(self, src: str, loc: str) -> int:
        if not os.path.exists(loc):
            os.mkdir(loc)
        task_list = []
        total = 0
        async for entry in self.sftp.scandir(src):
            if entry.filename in (".", ".."):
                continue
            next_src = "/".join((src, entry.filename))
            next_loc = "/".join((loc, entry.filename))
            if entry.attrs.type == 2:
                task_list.append(
                    asyncio.create_task(
                        self.search_transport_file(next_src, next_loc)
                    )
                )
            else:
                total += entry.attrs.size
                self.transport_coro_list.append(
                    (entry.attrs.size, self._transport_file(next_src, next_loc))
                )

        for future in asyncio.as_completed(task_list):
            total += await future
        return total

    async def transport(self) -> None:
        self.pool = ImmediateSchedulerPool(self.co_num)
        src, loc = path_stand(self.src, self.loc)
        if await self.sftp.isdir(src):
            all_size = await self.search_transport_file(src, loc)
            self.on_event(TransportEvent(type="range", data=all_size))
            await self.pool.submit(self.transport_coro_list)
        else:
            all_size = await self.sftp.getsize(src)
            self.on_event(TransportEvent(type="range", data=all_size))
            await self.pool.submit(
                [(all_size, self._transport_file(src, loc))]
            )
        await self.pool.join()
        self.on_event(TransportEvent(type="done"))


class PUT(Transport):
    """上传任务核心类"""

    def __init__(
        self,
        src: str,
        loc: str,
        co_num: int,
        speed_limit: int,
        sftp: "asyncssh.SFTPClient",
        on_event: ProgressCallback,
    ) -> None:
        super().__init__(src, loc, co_num, speed_limit, sftp, on_event)
        self.task_list_mkdir: List[Coroutine] = []

    async def _transport_file(self, src: str, loc: str) -> None:
        try:
            local_size = os.path.getsize(src)
            try:
                remote_size = (await self.sftp.stat(loc)).size
            except asyncssh.SFTPNoSuchFile:
                remote_size = 0

            mode = "ab" if 0 < remote_size < local_size else "wb"
            start_pos = remote_size if 0 < remote_size < local_size else 0

            if remote_size == local_size and local_size != 0:
                ProgressTracker(self.on_event, self, initial_size=remote_size)
                return

            tracker = ProgressTracker(self.on_event, self, initial_size=start_pos)

            chunk_size = 1024 * 1024
            if self.speed_limit > 0:
                chunk_size = min(
                    1024 * 1024, max(1024 * 32, self.speed_limit * 1024)
                )

            async with self.sftp.open(loc, mode) as remote_file:
                if start_pos > 0:
                    await remote_file.seek(start_pos)
                with open(src, "rb") as local_file:
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
                        tracker(b"", b"", now_size, local_size)

        except asyncio.CancelledError:
            raise
        except (OSError, asyncssh.SFTPError):
            all_size = os.path.getsize(src)
            tracker = ProgressTracker(self.on_event, self)
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
                self.transport_coro_list.append(
                    (entry.stat().st_size, self._transport_file(next_src, next_loc))
                )
                total_size += entry.stat().st_size
        return total_size

    async def transport(self) -> None:
        self.pool = ImmediateSchedulerPool(self.co_num)
        src, loc = path_stand(self.src, self.loc)
        if os.path.isdir(src):
            all_size = self.search_transport_file(src, loc)
            self.on_event(TransportEvent(type="range", data=all_size))
            for future in asyncio.as_completed(self.task_list_mkdir):
                await future
            await self.pool.submit(self.transport_coro_list)
        else:
            all_size = os.path.getsize(src)
            self.on_event(TransportEvent(type="range", data=all_size))
            await self.pool.submit(
                [(all_size, self._transport_file(src, loc))]
            )
        await self.pool.join()
        self.on_event(TransportEvent(type="done"))
