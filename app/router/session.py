import asyncssh
from fastapi import APIRouter, Depends, HTTPException

from app.deps import get_ssh_manager
from app.schemas import SessionCreate, SessionInfo, MessageResponse
from app.service.ssh_manager import SSHManager, SessionNotFoundError

router = APIRouter(tags=["sessions"])


@router.post("/sessions", response_model=SessionInfo)
async def create_session(payload: SessionCreate, manager: SSHManager = Depends(get_ssh_manager)):
    try:
        session_id = await manager.connect(
            host=payload.host,
            port=payload.port,
            username=payload.username,
            password=payload.password,
            client_keys=payload.client_keys,
            passphrase=payload.passphrase,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})
    except asyncssh.PermissionDenied as e:
        raise HTTPException(status_code=401, detail={"ok": False, "message": f"Permission denied: {e}"})
    except (OSError, asyncssh.ConnectionLost, asyncssh.Error) as e:
        raise HTTPException(status_code=502, detail={"ok": False, "message": f"Connection failed: {e}"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"ok": False, "message": str(e)})

    session = manager.get(session_id)
    return {
        "session_id": session_id,
        "host": session.host,
        "port": session.port,
        "username": session.username,
        "banner_msg": session.banner_msg,
    }


@router.delete("/sessions/{session_id}", response_model=MessageResponse)
async def close_session(session_id: str, manager: SSHManager = Depends(get_ssh_manager)):
    try:
        await manager.disconnect(session_id)
    except SessionNotFoundError:
        raise HTTPException(status_code=404, detail={"ok": False, "message": "Session not found"})
    return {"ok": True, "message": "Session closed"}


@router.get("/sessions/{session_id}/status", response_model=SessionInfo)
def get_session_status(session_id: str, manager: SSHManager = Depends(get_ssh_manager)):
    try:
        session = manager.get(session_id)
    except SessionNotFoundError:
        raise HTTPException(status_code=404, detail={"ok": False, "message": "Session not found"})
    return {
        "session_id": session_id,
        "host": session.host,
        "port": session.port,
        "username": session.username,
        "banner_msg": session.banner_msg,
    }
