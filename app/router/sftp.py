import time
import asyncssh
from fastapi import APIRouter, Depends, HTTPException, Query

from app.deps import get_ssh_manager
from app.schemas import (
    MessageResponse,
    RenameRequest,
    PathPairRequest,
)
from app.service.ssh_manager import SSHManager, SessionNotFoundError

router = APIRouter(tags=["sftp"])


def _make_file_entry(name: str, path: str, attrs) -> dict:
    mtime = attrs.mtime
    mtime_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(mtime)) if mtime else ""
    entry_type = "dir" if attrs.type == 2 else "file"
    size = attrs.size if attrs.size is not None else 0
    perms = oct(attrs.permissions) if attrs.permissions is not None else "0"
    return {
        "name": name,
        "path": path,
        "size": size,
        "size_display": _format_size(size),
        "type": entry_type,
        "mtime": mtime,
        "mtime_display": mtime_str,
        "permissions": perms,
    }


def _format_size(size: int) -> str:
    if not size:
        return "0 B"
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.2f} {unit}" if unit != "B" else f"{size} B"
        size /= 1024
    return f"{size:.2f} PB"


def _get_session(session_id: str, manager: SSHManager):
    try:
        return manager.get(session_id)
    except SessionNotFoundError:
        raise HTTPException(status_code=404, detail={"ok": False, "message": "Session not found"})


@router.get("/sftp/{session_id}/list")
async def list_dir(
    session_id: str,
    path: str = Query(default="/"),
    manager: SSHManager = Depends(get_ssh_manager),
):
    session = _get_session(session_id, manager)
    try:
        entries = []
        async for entry in session.sftp.scandir(path):
            if entry.filename in (".", ".."):
                continue
            full_path = "/".join((path.rstrip("/"), entry.filename))
            entries.append(_make_file_entry(entry.filename, full_path, entry.attrs))
        return {"current_path": path, "entries": entries}
    except asyncssh.SFTPError as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})


@router.get("/sftp/{session_id}/stat")
async def stat_file(
    session_id: str,
    path: str = Query(...),
    manager: SSHManager = Depends(get_ssh_manager),
):
    session = _get_session(session_id, manager)
    try:
        attrs = await session.sftp.stat(path)
        name = path.rstrip("/").split("/")[-1] or "/"
        return _make_file_entry(name, path, attrs)
    except asyncssh.SFTPNoSuchFile:
        raise HTTPException(status_code=404, detail={"ok": False, "message": "File not found"})
    except asyncssh.SFTPError as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})


@router.get("/sftp/{session_id}/read")
async def read_file(
    session_id: str,
    path: str = Query(...),
    manager: SSHManager = Depends(get_ssh_manager),
):
    session = _get_session(session_id, manager)
    try:
        content = await session.read_file(path)
        return {"content": content}
    except ValueError as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})
    except asyncssh.SFTPError as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})
    except UnicodeDecodeError as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": f"Cannot read file: {e}"})


@router.put("/sftp/{session_id}/write", response_model=MessageResponse)
async def write_file(
    session_id: str,
    path: str = Query(...),
    body: dict = {},
    manager: SSHManager = Depends(get_ssh_manager),
):
    session = _get_session(session_id, manager)
    content = body.get("content", "")
    try:
        await session.save_file(path, content)
        return {"ok": True, "message": "File written"}
    except asyncssh.SFTPError as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})


@router.post("/sftp/{session_id}/mkdir", response_model=MessageResponse)
async def make_directory(
    session_id: str,
    path: str = Query(...),
    manager: SSHManager = Depends(get_ssh_manager),
):
    session = _get_session(session_id, manager)
    try:
        await session.makedirs(path)
        return {"ok": True, "message": "Directory created"}
    except asyncssh.SFTPError as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})


@router.delete("/sftp/{session_id}/delete", response_model=MessageResponse)
async def delete_path(
    session_id: str,
    path: str = Query(...),
    manager: SSHManager = Depends(get_ssh_manager),
):
    session = _get_session(session_id, manager)
    try:
        await session.del_file(path)
        return {"ok": True, "message": "Deleted"}
    except Exception as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})


@router.post("/sftp/{session_id}/rename", response_model=MessageResponse)
async def rename_item(
    session_id: str,
    payload: RenameRequest,
    manager: SSHManager = Depends(get_ssh_manager),
):
    session = _get_session(session_id, manager)
    try:
        await session.rename(payload.old_path, payload.new_name)
        return {"ok": True, "message": "Renamed"}
    except asyncssh.SFTPError as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})


@router.post("/sftp/{session_id}/copy", response_model=MessageResponse)
async def copy_item(
    session_id: str,
    payload: PathPairRequest,
    manager: SSHManager = Depends(get_ssh_manager),
):
    session = _get_session(session_id, manager)
    try:
        await session.copy_file(payload.src, payload.dst)
        return {"ok": True, "message": "Copied"}
    except Exception as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})


@router.post("/sftp/{session_id}/move", response_model=MessageResponse)
async def move_item(
    session_id: str,
    payload: PathPairRequest,
    manager: SSHManager = Depends(get_ssh_manager),
):
    session = _get_session(session_id, manager)
    try:
        await session.move_file(payload.src, payload.dst)
        return {"ok": True, "message": "Moved"}
    except Exception as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})


@router.put("/sftp/{session_id}/chmod", response_model=MessageResponse)
async def change_permissions(
    session_id: str,
    path: str = Query(...),
    body: dict = {},
    manager: SSHManager = Depends(get_ssh_manager),
):
    session = _get_session(session_id, manager)
    permissions = body.get("permissions", 0)
    try:
        await session.chmod(path, int(permissions))
        return {"ok": True, "message": "Permissions changed"}
    except asyncssh.SFTPError as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})
