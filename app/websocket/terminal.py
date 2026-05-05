import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.deps import get_ssh_manager
from app.service.ssh_manager import SSHManager, SessionNotFoundError

router = APIRouter(tags=["ws-terminal"])
logger = logging.getLogger("terminal")


@router.websocket("/terminal/{session_id}")
async def terminal_ws(websocket: WebSocket, session_id: str):
    manager = get_ssh_manager()
    try:
        session = manager.get(session_id)
    except SessionNotFoundError:
        await websocket.close(code=4004, reason="Session not found")
        return

    await websocket.accept()

    process = None
    read_task = None

    try:
        process = await session.connection.create_process(
            command="bash",
            request_pty=True,
            term_type="xterm-256color",
            term_size=(80, 24),
        )

        stop_event = asyncio.Event()
        resize_queue = asyncio.Queue()

        async def read_ssh_output():
            try:
                while not stop_event.is_set():
                    data = await process.stdout.read(8192)
                    if not data:
                        break
                    await websocket.send_text(data)
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"Terminal read error: {e}")

        async def handle_resize():
            try:
                while not stop_event.is_set():
                    try:
                        cols, rows = await asyncio.wait_for(resize_queue.get(), timeout=1)
                        process.change_terminal_size(cols, rows)
                    except asyncio.TimeoutError:
                        continue
            except asyncio.CancelledError:
                pass

        async def read_ws_input():
            try:
                while True:
                    data = await websocket.receive_text()

                    if data.startswith("{") and '"type"' in data:
                        try:
                            msg = json.loads(data)
                            if msg.get("type") == "resize":
                                cols = int(msg.get("cols", 80))
                                rows = int(msg.get("rows", 24))
                                await resize_queue.put((cols, rows))
                                continue
                        except (json.JSONDecodeError, ValueError):
                            pass

                    process.stdin.write(data)
                    await process.stdin.drain()
            except WebSocketDisconnect:
                stop_event.set()
            except Exception as e:
                logger.error(f"Terminal write error: {e}")
                stop_event.set()

        read_task = asyncio.create_task(read_ssh_output())
        resize_task = asyncio.create_task(handle_resize())
        try:
            await read_ws_input()
        finally:
            stop_event.set()
            for task in (read_task, resize_task):
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"Terminal WS error: {e}")
        try:
            await websocket.send_text(f"\r\n\x1b[31mTerminal error: {e}\x1b[0m\r\n")
        except Exception:
            pass
    finally:
        if process:
            process.close()
