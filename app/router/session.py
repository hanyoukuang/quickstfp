import asyncssh
from fastapi import APIRouter, Depends, HTTPException, Query

from app.deps import get_ssh_manager, get_db
from app.schemas import SessionCreate, SessionInfo, MessageResponse
from app.service.ssh_manager import SSHManager, SessionNotFoundError
from database.user_model import UserInfoDB

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


@router.post("/sessions/connect-site")
async def connect_by_site(
    site_id: int = Query(...),
    auth_type: str = Query(default="password"),
    db: UserInfoDB = Depends(get_db),
    manager: SSHManager = Depends(get_ssh_manager),
):
    row = None
    if auth_type == "password":
        row = db.query_idx_password(site_id)
        if row:
            _, host, port, username, password = row
            client_keys = None
            passphrase = None
    else:
        row = db.query_idx_key(site_id)
        if row:
            _, host, port, username, key_path, passphrase = row
            password = None
            client_keys = [key_path] if key_path else None

    if not row:
        raise HTTPException(status_code=404, detail={"ok": False, "message": "Site not found"})

    try:
        session_id = await manager.connect(
            host=host,
            port=port,
            username=username,
            password=password,
            client_keys=client_keys,
            passphrase=passphrase,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})
    except asyncssh.PermissionDenied as e:
        raise HTTPException(status_code=401, detail={"ok": False, "message": f"Permission denied: {e}"})
    except (OSError, asyncssh.ConnectionLost, asyncssh.Error) as e:
        raise HTTPException(status_code=502, detail={"ok": False, "message": f"Connection failed: {e}"})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"ok": False, "message": str(e)})

    return {
        "session_id": session_id,
        "host": host,
        "port": port,
        "username": username,
        "banner_msg": "",
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
