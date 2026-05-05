import asyncio
import time


class SpeedLimiter:
    """基于令牌桶算法的全局限速器（支持多协程共享）"""

    def __init__(self, limit_kbps: int):
        self.limit_bps = limit_kbps * 1024
        self.tokens = float(self.limit_bps)
        self.last_time = time.monotonic()
        self.lock = asyncio.Lock()

    async def consume(self, amount: int):
        if self.limit_bps <= 0:
            return

        if amount <= 0:
            return

        async with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_time

            self.tokens = min(self.limit_bps, self.tokens + elapsed * self.limit_bps)

            if self.tokens < amount:
                wait_time = (amount - self.tokens) / self.limit_bps
                await asyncio.sleep(wait_time)
                self.last_time = time.monotonic()
                self.tokens = 0
            else:
                self.tokens -= amount
                self.last_time = now
