import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.deps import get_ssh_manager
from app.service.ssh_manager import SessionNotFoundError

router = APIRouter(tags=["ws-terminal"])


@router.websocket("/terminal/{session_id}")
async def terminal_ws(websocket: WebSocket, session_id: str):
    manager = get_ssh_manager()
    try:
        session = manager.get(session_id)
    except SessionNotFoundError:
        await websocket.close(code=4004, reason="Session not found")
        return

    await websocket.accept()

    stop_event = asyncio.Event()

    async def read_ssh_output():
        try:
            while not stop_event.is_set():
                data = await session.process.stdout.read(8192)
                if not data:
                    break
                await websocket.send_text(data)
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def read_ws_input():
        try:
            while True:
                data = await websocket.receive_text()
                session.process.stdin.write(data)
                await session.process.stdin.drain()
        except WebSocketDisconnect:
            stop_event.set()
        except Exception:
            stop_event.set()

    read_task = asyncio.create_task(read_ssh_output())
    try:
        await read_ws_input()
    finally:
        stop_event.set()
        read_task.cancel()
        try:
            await read_task
        except asyncio.CancelledError:
            pass
