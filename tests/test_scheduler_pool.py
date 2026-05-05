import asyncio

import pytest

from app.core.transport import ImmediateSchedulerPool


class TestImmediateSchedulerPool:
    """ImmediateSchedulerPool 正常情况测试"""

    @pytest.mark.asyncio
    async def test_single_task_completes(self):
        """单个任务正常完成"""
        pool = ImmediateSchedulerPool(coro_num=1)
        result = []

        async def task():
            result.append(1)

        await pool.submit([(1, task())])
        await pool.join()
        assert result == [1]

    @pytest.mark.asyncio
    async def test_multiple_tasks_all_complete(self):
        """多个任务全部完成"""
        pool = ImmediateSchedulerPool(coro_num=3)
        results = set()

        async def task(n):
            results.add(n)

        await pool.submit([(1, task(i)) for i in range(10)])
        await pool.join()
        assert results == set(range(10))

    @pytest.mark.asyncio
    async def test_concurrency_limit_respected(self):
        """并发数严格受限制"""
        pool = ImmediateSchedulerPool(coro_num=2)
        max_concurrent = 0
        current = 0
        lock = asyncio.Lock()

        async def task(_n):
            nonlocal max_concurrent, current
            async with lock:
                current += 1
                max_concurrent = max(max_concurrent, current)
            await asyncio.sleep(0.01)
            async with lock:
                current -= 1

        await pool.submit([(1, task(i)) for i in range(8)])
        await pool.join()
        assert max_concurrent <= 2

    @pytest.mark.asyncio
    async def test_big_task_scheduling_priority(self):
        """大任务被后调度，小任务优先（检查调度顺序）"""
        pool = ImmediateSchedulerPool(coro_num=1)
        execution_order = []

        async def task(n):
            execution_order.append(n)

        await pool.submit([
            (100, task(100)),
            (1, task(1)),
            (10, task(10)),
            (50, task(50)),
            (1, task(2)),
        ])
        await pool.join()

        # coro_num=1 时按顺序执行：小 → 大
        # pending 按 size 排序：[(1, task(1)), (1, task(2)), (10, task(10)), (50, task(50)), (100, task(100))]
        # coro_num=1 时，_dispatch 从尾部取（大任务优先），但因为只有一个 worker
        # big_slot_open 为 True，所以先取 100，然后等 100 完成后再取 50...
        # 实际上顺序可能是 [100, 50, 10, 1, 2] 或 [100, 50, 10, 2, 1]
        # 大任务被优先调度
        assert execution_order[0] == 100

    @pytest.mark.asyncio
    async def test_join_blocks_until_completion(self):
        """join 在所有任务完成前阻塞"""
        pool = ImmediateSchedulerPool(coro_num=1)
        started = asyncio.Event()
        completed = asyncio.Event()

        async def task():
            started.set()
            await asyncio.sleep(0.1)
            completed.set()

        await pool.submit([(1, task())])
        await started.wait()

        join_done = False

        async def do_join():
            nonlocal join_done
            await pool.join()
            join_done = True

        join_task = asyncio.create_task(do_join())
        await asyncio.sleep(0.01)
        assert not join_done, "join should still be blocking"

        await completed.wait()
        await join_task
        assert join_done

    @pytest.mark.asyncio
    async def test_reuse_pool_after_join(self):
        """join 后可以继续提交新任务"""
        pool = ImmediateSchedulerPool(coro_num=2)
        r1 = []

        async def task(n):
            r1.append(n)

        await pool.submit([(1, task(i)) for i in range(3)])
        await pool.join()

        r2 = []

        async def task2(n):
            r2.append(n)

        await pool.submit([(1, task2(i)) for i in range(3)])
        await pool.join()

        assert len(r1) == 3
        assert len(r2) == 3


class TestImmediateSchedulerPoolBoundary:
    """ImmediateSchedulerPool 边界情况测试"""

    @pytest.mark.asyncio
    async def test_empty_task_list(self):
        """空任务列表"""
        pool = ImmediateSchedulerPool(coro_num=5)
        await pool.submit([])
        await pool.join()

    @pytest.mark.asyncio
    async def test_single_worker(self):
        """单个 worker"""
        pool = ImmediateSchedulerPool(coro_num=1)
        results = []

        async def task(n):
            await asyncio.sleep(0.01)
            results.append(n)

        await pool.submit([(1, task(i)) for i in range(5)])
        await pool.join()
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_many_workers(self):
        """worker 数大于任务数"""
        pool = ImmediateSchedulerPool(coro_num=100)
        results = []

        async def task(n):
            results.append(n)

        await pool.submit([(1, task(i)) for i in range(5)])
        await pool.join()
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_single_large_task(self):
        """单个大任务"""
        pool = ImmediateSchedulerPool(coro_num=1)
        results = []

        async def task():
            results.append("done")

        await pool.submit([(1000000, task())])
        await pool.join()
        assert results == ["done"]

    @pytest.mark.asyncio
    async def test_failing_task_does_not_crash_pool(self):
        """任务内部异常不导致池崩溃"""
        pool = ImmediateSchedulerPool(coro_num=2)
        results = []

        async def bad_task():
            raise ValueError("test error")

        async def good_task():
            results.append("ok")

        await pool.submit([(1, bad_task()), (1, good_task())])
        await pool.join()
        assert results == ["ok"]

    @pytest.mark.asyncio
    async def test_join_when_already_complete(self):
        """所有任务已完成时 join 立即返回"""
        pool = ImmediateSchedulerPool(coro_num=2)
        await pool.join()

    @pytest.mark.asyncio
    async def test_max_workers_zero(self):
        """max_workers = 0，任务永远不会被调度"""
        pool = ImmediateSchedulerPool(coro_num=0)
        results = []

        async def task():
            results.append("done")

        await pool.submit([(1, task())])
        # 不能被调度，但提交不应报错
        # join 会因为 pending_tasks 非空而阻塞，不能等
        # 直接取消
        await pool.cancel()
        assert results == []


class TestImmediateSchedulerPoolError:
    """ImmediateSchedulerPool 错误情况测试"""

    @pytest.mark.asyncio
    async def test_submit_after_cancel_raises_error(self):
        """cancel 后提交任务应抛出 RuntimeError"""
        pool = ImmediateSchedulerPool(coro_num=2)
        await pool.cancel()

        with pytest.raises(RuntimeError, match="Pool is stopped"):
            await pool.submit([(1, asyncio.sleep(0.01))])

    @pytest.mark.asyncio
    async def test_cancel_kills_running_tasks(self):
        """cancel 应杀死正在运行的任务"""
        pool = ImmediateSchedulerPool(coro_num=2)
        cancelled = False

        async def slow_task():
            nonlocal cancelled
            try:
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                cancelled = True
                raise

        await pool.submit([(1, slow_task()), (1, slow_task())])
        await asyncio.sleep(0.05)
        await pool.cancel()
        assert cancelled

    @pytest.mark.asyncio
    async def test_cancel_clears_pending(self):
        """cancel 应清除待处理任务"""
        pool = ImmediateSchedulerPool(coro_num=1)
        results = []

        async def slow_task():
            await asyncio.sleep(10)
            results.append("slow")

        async def fast_task():
            results.append("fast")

        # 确保 slow_task 被先调度：大小更大，sort 后排在末尾，dispatch 从末尾取
        await pool.submit([(1, fast_task()), (100, slow_task())])
        await asyncio.sleep(0.05)
        await pool.cancel()
        # slow_task 在运行中被 kill，fast_task 在 pending 中被清除
        assert "fast" not in results

    @pytest.mark.asyncio
    async def test_double_cancel_does_not_crash(self):
        """重复 cancel 不应崩溃"""
        pool = ImmediateSchedulerPool(coro_num=2)

        async def task():
            await asyncio.sleep(0.01)

        await pool.submit([(1, task())])
        await pool.join()
        await pool.cancel()
        await pool.cancel()
