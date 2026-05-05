import asyncio
import json
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.deps import get_ssh_manager
from app.service.ssh_manager import SessionNotFoundError
from app.core.transport import TransportEvent, GET, PUT, ProgressCallback, Transport

router = APIRouter(tags=["ws-progress"])


@router.websocket("/transport/{session_id}")
async def transport_progress_ws(websocket: WebSocket, session_id: str):
    manager = get_ssh_manager()
    try:
        session = manager.get(session_id)
    except SessionNotFoundError:
        await websocket.close(code=4004, reason="Session not found")
        return

    await websocket.accept()

    transport_obj: Optional[Transport] = None
    transport_task: Optional[asyncio.Task] = None
    listen_task: Optional[asyncio.Task] = None

    def make_callback() -> ProgressCallback:
        async def on_event(event: TransportEvent):
            try:
                payload = json.dumps({"type": event.type, "data": event.data})
                await websocket.send_text(payload)
            except Exception:
                pass

        def sync_callback(event: TransportEvent):
            asyncio.ensure_future(on_event(event))

        return sync_callback

    async def listen_controls():
        nonlocal transport_obj
        while True:
            try:
                data = await websocket.receive_text()
                msg = json.loads(data)
                action = msg.get("action")
                if action == "pause":
                    transport_obj.toggle_pause()
                    is_paused = transport_obj.pause_event is not None and not transport_obj.pause_event.is_set()
                    await websocket.send_text(json.dumps({"type": "paused" if is_paused else "resumed"}))
                elif action == "cancel":
                    await transport_obj.cancel()
                    break
            except (WebSocketDisconnect, Exception):
                if transport_obj:
                    await transport_obj.cancel()
                break

    try:
        data = await websocket.receive_text()
        msg = json.loads(data)

        if msg.get("action") != "start":
            await websocket.send_text(json.dumps({"type": "error", "data": "Expected 'start' action"}))
            return

        transport_type = msg.get("type", "GET")
        src = msg.get("src", "")
        dst = msg.get("dst", "")
        co_num = msg.get("co_num", 4)
        speed_limit = msg.get("speed_limit", 0)

        callback = make_callback()

        if transport_type == "GET":
            t = GET(
                src=src, loc=dst, co_num=co_num,
                speed_limit=speed_limit, sftp=session.sftp, on_event=callback,
            )
        else:
            t = PUT(
                src=src, loc=dst, co_num=co_num,
                speed_limit=speed_limit, sftp=session.sftp, on_event=callback,
            )

        transport_obj = t
        transport_task = asyncio.create_task(t.start())
        listen_task = asyncio.create_task(listen_controls())

        done, pending = await asyncio.wait(
            [transport_task, listen_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        if transport_task.done():
            exc = transport_task.exception()
            if exc and not isinstance(exc, asyncio.CancelledError):
                try:
                    await websocket.send_text(json.dumps({"type": "error", "data": str(exc)}))
                except Exception:
                    pass

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(json.dumps({"type": "error", "data": str(e)}))
        except Exception:
            pass
    finally:
        if transport_obj and not transport_obj.is_cancel:
            try:
                await transport_obj.cancel()
            except Exception:
                pass
        for task in (transport_task, listen_task):
            if task and not task.done():
                task.cancel()
