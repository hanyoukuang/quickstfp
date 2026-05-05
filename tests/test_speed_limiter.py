import asyncio
import time

import pytest

from app.core.speed_limiter import SpeedLimiter


class TestSpeedLimiter:
    """SpeedLimiter 正常情况测试"""

    @pytest.mark.asyncio
    async def test_no_limit_returns_immediately(self):
        """限速为 0 时，consume 应立即返回"""
        limiter = SpeedLimiter(0)
        start = time.monotonic()
        await limiter.consume(1024 * 1024)
        elapsed = time.monotonic() - start
        assert elapsed < 0.01, f"Expected nearly instant, got {elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_consume_within_tokens(self):
        """令牌充足时，consume 应立即返回"""
        limiter = SpeedLimiter(10 * 1024 * 1024)  # 很大的限速
        start = time.monotonic()
        await limiter.consume(1024)
        elapsed = time.monotonic() - start
        assert elapsed < 0.01, f"Expected nearly instant, got {elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_consume_exceeding_tokens_causes_delay(self):
        """超出令牌桶容量时需要等待"""
        limiter = SpeedLimiter(100)  # 100 KB/s
        # 消耗 200KB 的令牌，应该产生大约 2 秒的延迟
        start = time.monotonic()
        await limiter.consume(200 * 1024)
        elapsed = time.monotonic() - start
        assert elapsed > 0.5, f"Expected delay, got only {elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_multiple_consume_burst(self):
        """多次快速消耗，超过初始令牌桶容量时产生延迟"""
        limiter = SpeedLimiter(5)  # 5 KB/s，初始令牌 5KB

        start = time.monotonic()
        # 每次 1KB，共 10 次 = 10KB > 初始 5KB 容量，需要等待
        for _ in range(10):
            await limiter.consume(1024)
        elapsed = time.monotonic() - start

        assert elapsed > 0.1, f"Expected some delay with 10KB at 5KB/s, got {elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_concurrent_consumers(self):
        """多协程并发消费，不应死锁"""
        limiter = SpeedLimiter(1024)  # 1 MB/s

        async def consumer():
            await limiter.consume(1024 * 10)

        tasks = [asyncio.create_task(consumer()) for _ in range(5)]
        await asyncio.gather(*tasks)

    @pytest.mark.asyncio
    async def test_consume_after_long_wait_accumulates_tokens(self):
        """等待一段时间后令牌桶恢复，消费应几乎立即返回"""
        limiter = SpeedLimiter(1024)  # 1 MB/s

        await asyncio.sleep(0.5)  # 等待 0.5 秒，累积 512KB 的令牌
        start = time.monotonic()
        await limiter.consume(256 * 1024)  # 256KB < 512KB
        elapsed = time.monotonic() - start
        assert elapsed < 0.05, f"Expected nearly instant after token recovery, got {elapsed:.3f}s"


class TestSpeedLimiterBoundary:
    """SpeedLimiter 边界情况测试"""

    @pytest.mark.asyncio
    async def test_zero_amount_consumption(self):
        """消耗 0 字节应立即返回"""
        limiter = SpeedLimiter(1024)
        start = time.monotonic()
        await limiter.consume(0)
        elapsed = time.monotonic() - start
        assert elapsed < 0.01

    @pytest.mark.asyncio
    async def test_negative_amount_consumption(self):
        """消耗负数应立即返回"""
        limiter = SpeedLimiter(1024)
        start = time.monotonic()
        await limiter.consume(-100)
        elapsed = time.monotonic() - start
        assert elapsed < 0.01

    @pytest.mark.asyncio
    async def test_tiny_limit(self):
        """极小限速值"""
        limiter = SpeedLimiter(1)  # 1 KB/s
        start = time.monotonic()
        await limiter.consume(10 * 1024)  # 10KB
        elapsed = time.monotonic() - start
        assert elapsed > 1.0, f"Expected > 1s delay with 10KB at 1KB/s, got {elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_very_large_limit(self):
        """极大限速值"""
        limiter = SpeedLimiter(100 * 1024 * 1024)  # 100GB/s
        start = time.monotonic()
        await limiter.consume(1024 * 1024)
        elapsed = time.monotonic() - start
        assert elapsed < 0.01

    @pytest.mark.asyncio
    async def test_consume_exact_token_amount(self):
        """消耗恰好 1 秒令牌量的数据"""
        limiter = SpeedLimiter(10)  # 10 KB/s = 10240 bytes/s
        await asyncio.sleep(1.0)  # 等一秒让令牌充满
        start = time.monotonic()
        await limiter.consume(10 * 1024)
        elapsed = time.monotonic() - start
        # 令牌刚好用完，应该几乎不需要等待
        assert elapsed < 0.05, f"Expected nearly instant, got {elapsed:.3f}s"

    @pytest.mark.asyncio
    async def test_limit_kbps_calculation(self):
        """验证 limit_kbps 正确转换为 bps"""
        limiter = SpeedLimiter(10)
        assert limiter.limit_bps == 10 * 1024

        limiter2 = SpeedLimiter(0)
        assert limiter2.limit_bps == 0

        limiter3 = SpeedLimiter(500)
        assert limiter3.limit_bps == 500 * 1024


class TestSpeedLimiterError:
    """SpeedLimiter 错误情况测试"""

    @pytest.mark.asyncio
    async def test_consume_negative_amount_drops_through(self):
        """负数消费量直接通过，不抛异常"""
        limiter = SpeedLimiter(1024)
        try:
            await limiter.consume(-1)
        except Exception as e:
            pytest.fail(f"Should not raise on negative amount: {e}")

    @pytest.mark.asyncio
    async def test_pause_state_not_affected_by_limit(self):
        """限速器在 limit=0 时不应影响后续使用"""
        limiter = SpeedLimiter(0)
        await limiter.consume(1024)

        limiter = SpeedLimiter(1024)
        await limiter.consume(1024)  # 不应崩溃
