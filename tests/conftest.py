import pytest
import asyncio


@pytest.fixture(scope="session")
def event_loop():
    """为整个测试会话提供事件循环"""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()
