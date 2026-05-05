import asyncio
import json
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.deps import get_ssh_manager
from app.service.ssh_manager import SessionNotFoundError
from app.core.transport import TransportEvent, GET, PUT, ProgressCallback

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

    transport_task: Optional[asyncio.Task] = None

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

    try:
        data = await websocket.receive_text()
        msg = json.loads(data)
        action = msg.get("action")

        if action == "start":
            transport_type = msg.get("type", "GET")
            src = msg.get("src", "")
            dst = msg.get("dst", "")
            co_num = msg.get("co_num", 4)
            speed_limit = msg.get("speed_limit", 0)

            callback = make_callback()

            if transport_type == "GET":
                t = GET(
                    src=src,
                    loc=dst,
                    co_num=co_num,
                    speed_limit=speed_limit,
                    sftp=session.sftp,
                    on_event=callback,
                )
            else:
                t = PUT(
                    src=src,
                    loc=dst,
                    co_num=co_num,
                    speed_limit=speed_limit,
                    sftp=session.sftp,
                    on_event=callback,
                )

            transport_task = asyncio.create_task(t.start())

    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(json.dumps({"type": "error", "data": str(e)}))
        except Exception:
            pass
    finally:
        if transport_task and not transport_task.done():
            transport_task.cancel()
            try:
                await transport_task
            except asyncio.CancelledError:
                pass
