"""Transport 模块单元测试"""
import pytest
from quickstfp.core.transport import SpeedLimiter, ImmediateSchedulerPool, ProgressTracker, Transport, GET, PUT
from quickstfp.utils.file_utils import path_stand, is_binary


class TestPathStand:

    def test_joins_source_basename(self):
        src = "/home/user/file.txt"
        loc = "/tmp"
        result_src, result_loc = path_stand(src, loc)
        assert result_src == "/home/user/file.txt"
        assert result_loc == "/tmp/file.txt"

    def test_converts_backslash(self):
        src = r"C:\Users\file.txt"
        loc = r"D:\backup"
        result_src, result_loc = path_stand(src, loc)
        assert result_src == "C:/Users/file.txt"
        assert result_loc == "D:/backup/file.txt"

    def test_strips_trailing_slash(self):
        src, loc = path_stand("/home/user/", "/tmp/")
        assert src == "/home/user"
        assert loc == "/tmp/user"


class TestIsBinary:

    def test_pdf_is_binary(self):
        assert is_binary("document.pdf") is True

    def test_txt_is_not_binary(self):
        assert is_binary("readme.txt") is False

    def test_python_is_not_binary(self):
        assert is_binary("main.py") is False


class TestSpeedLimiter:

    @pytest.mark.asyncio
    async def test_unlimited_passthrough(self):
        limiter = SpeedLimiter(0)
        await limiter.consume(1024 * 1024)  # should not block


class TestResumeState:

    def test_new_transfer(self):
        mode, start_pos, is_done = Transport._resume_state(0, 1000)
        assert mode == 'wb'
        assert start_pos == 0
        assert is_done is False

    def test_resume_transfer(self):
        mode, start_pos, is_done = Transport._resume_state(500, 1000)
        assert mode == 'ab'
        assert start_pos == 500
        assert is_done is False

    def test_already_complete(self):
        mode, start_pos, is_done = Transport._resume_state(1000, 1000)
        assert is_done is True
