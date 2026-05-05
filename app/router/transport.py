import io
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File
from fastapi.responses import StreamingResponse

from app.deps import get_ssh_manager
from app.service.ssh_manager import SSHManager, SessionNotFoundError

router = APIRouter(tags=["transport"])


def _get_session(session_id: str, manager: SSHManager):
    try:
        return manager.get(session_id)
    except SessionNotFoundError:
        raise HTTPException(status_code=404, detail={"ok": False, "message": "Session not found"})


@router.post("/transport/{session_id}/upload")
async def upload_file(
    session_id: str,
    path: str = Query(...),
    file: UploadFile = File(...),
    manager: SSHManager = Depends(get_ssh_manager),
):
    session = _get_session(session_id, manager)
    content = await file.read()
    try:
        remote_path = path.rstrip("/") + "/" + (file.filename or "uploaded_file")
        await session.sftp.makedirs(path, exist_ok=True)
        async with session.sftp.open(remote_path, "wb") as remote_file:
            await remote_file.write(content)
        return {"ok": True, "message": f"Uploaded to {remote_path}", "size": len(content)}
    except Exception as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})


@router.get("/transport/{session_id}/download")
async def download_file(
    session_id: str,
    path: str = Query(...),
    manager: SSHManager = Depends(get_ssh_manager),
):
    session = _get_session(session_id, manager)
    try:
        async with session.sftp.open(path, "rb") as remote_file:
            content = await remote_file.read()
        filename = path.rstrip("/").split("/")[-1] or "download"

        return StreamingResponse(
            io.BytesIO(content),
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})
