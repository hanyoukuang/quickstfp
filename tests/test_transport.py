import asyncio
import time
from unittest.mock import MagicMock

import pytest

from app.core.transport import (
    Transport,
    TransportEvent,
    ProgressTracker,
)


class TestTransportEvent:
    """TransportEvent 数据类测试"""

    def test_create_event(self):
        event = TransportEvent(type="progress", data=100)
        assert event.type == "progress"
        assert event.data == 100

    def test_event_repr(self):
        event = TransportEvent(type="done", data=None)
        assert "done" in repr(event) or "done" in str(event)

    def test_event_equality(self):
        e1 = TransportEvent(type="progress", data=100)
        e2 = TransportEvent(type="progress", data=100)
        e3 = TransportEvent(type="progress", data=200)
        assert e1 == e2
        assert e1 != e3


class TestProgressTracker:
    """ProgressTracker 测试"""

    def test_progress_callback_invoked(self):
        events = []

        def callback(event: TransportEvent):
            events.append(event)

        transport = MagicMock(spec=Transport)
        transport._total_progress_size = 0
        transport._last_time = time.time()  # 初始化为当前时间，避免立即触发速度事件
        transport._last_speed_size = 0
        transport.transport_fail_filename = ""

        tracker = ProgressTracker(callback, transport)

        tracker(b"", b"", 1024, 4096)
        assert len(events) == 1
        assert events[0].type == "progress"
        assert events[0].data == 1024

        tracker(b"", b"", 2048, 4096)
        assert len(events) == 2
        assert events[1].data == 2048

    def test_progress_total_accumulates(self):
        events = []

        def callback(event: TransportEvent):
            events.append(event)

        transport = MagicMock(spec=Transport)
        transport._total_progress_size = 0
        transport._last_time = 0
        transport._last_speed_size = 0
        transport.transport_fail_filename = ""

        tracker = ProgressTracker(callback, transport)

        tracker(b"", b"", 100, 1000)
        assert transport._total_progress_size == 100

        tracker(b"", b"", 300, 1000)
        assert transport._total_progress_size == 300

    def test_initial_size_offset(self):
        events = []

        def callback(event: TransportEvent):
            events.append(event)

        transport = MagicMock(spec=Transport)
        transport._total_progress_size = 0
        transport._last_time = 0
        transport._last_speed_size = 0
        transport.transport_fail_filename = ""

        ProgressTracker(callback, transport, initial_size=500)

        assert transport._total_progress_size == 500
        assert len(events) == 1
        assert events[0].data == 500

    def test_speed_callback(self):
        events = []

        def callback(event: TransportEvent):
            events.append(event)

        transport = MagicMock(spec=Transport)
        transport._total_progress_size = 0
        transport._last_time = 0
        transport._last_speed_size = 0
        transport.transport_fail_filename = ""

        tracker = ProgressTracker(callback, transport)

        import time
        transport._last_time = time.time() - 1.0

        tracker(b"", b"", 1024 * 1024, 4096 * 1024)

        speed_events = [e for e in events if e.type == "speed"]
        assert len(speed_events) > 0

    def test_handle_fail(self):
        events = []

        def callback(event: TransportEvent):
            events.append(event)

        transport = MagicMock(spec=Transport)
        transport._total_progress_size = 0
        transport._last_time = 0
        transport._last_speed_size = 0
        transport.transport_fail_filename = ""

        tracker = ProgressTracker(callback, transport)
        tracker(b"", b"", 500, 1000)

        tracker.handle_fail(1000, "/remote/test.txt")
        assert transport._total_progress_size == 1000
        assert "/remote/test.txt" in transport.transport_fail_filename

    def test_format_speed(self):
        tracker = ProgressTracker(lambda e: None, MagicMock())

        assert "B/s" in tracker._format_speed(500)
        assert "KB/s" in tracker._format_speed(2 * 1024)
        assert "MB/s" in tracker._format_speed(2 * 1024 * 1024)
        assert "GB/s" in tracker._format_speed(2 * 1024 * 1024 * 1024)


class TestTransportCallback:
    """Transport 回调机制测试"""

    def test_transport_has_on_event(self):
        events = []

        def callback(event: TransportEvent):
            events.append(event)

        sftp = MagicMock()
        transport = Transport(
            src="/src",
            loc="/loc",
            co_num=1,
            speed_limit=0,
            sftp=sftp,
            on_event=callback,
        )
        assert transport.on_event is callback

    def test_transport_direct_call_raises(self):
        """直接调用 Transport 实例应抛出 RuntimeError"""
        sftp = MagicMock()
        transport = Transport(
            src="/src",
            loc="/loc",
            co_num=1,
            speed_limit=0,
            sftp=sftp,
            on_event=lambda e: None,
        )
        with pytest.raises(RuntimeError):
            transport()

    @pytest.mark.asyncio
    async def test_toggle_pause(self):
        sftp = MagicMock()
        transport = Transport(
            src="/src",
            loc="/loc",
            co_num=1,
            speed_limit=0,
            sftp=sftp,
            on_event=lambda e: None,
        )
        transport.pause_event = asyncio.Event()
        transport.pause_event.set()

        transport.toggle_pause()
        assert not transport.pause_event.is_set()

        transport.toggle_pause()
        assert transport.pause_event.is_set()

    @pytest.mark.asyncio
    async def test_toggle_pause_when_none(self):
        """pause_event 为 None 时 toggle_pause 不崩溃"""
        sftp = MagicMock()
        transport = Transport(
            src="/src",
            loc="/loc",
            co_num=1,
            speed_limit=0,
            sftp=sftp,
            on_event=lambda e: None,
        )
        transport.pause_event = None
        transport.toggle_pause()

    @pytest.mark.asyncio
    async def test_cancel_emits_event(self):
        events = []

        def callback(event: TransportEvent):
            events.append(event)

        sftp = MagicMock()
        transport = Transport(
            src="/src",
            loc="/loc",
            co_num=1,
            speed_limit=0,
            sftp=sftp,
            on_event=callback,
        )
        transport.pause_event = asyncio.Event()
        transport.pause_event.set()

        await transport.cancel()

        cancelled_events = [e for e in events if e.type == "cancelled"]
        assert len(cancelled_events) == 1
        assert transport.is_cancel
