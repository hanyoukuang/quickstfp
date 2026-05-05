import re
from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, File
from fastapi.responses import StreamingResponse

from app.deps import get_ssh_manager
from app.service.ssh_manager import SSHManager, SessionNotFoundError

router = APIRouter(tags=["transport"])


def _get_session(session_id: str, manager: SSHManager):
    try:
        return manager.get(session_id)
    except SessionNotFoundError:
        raise HTTPException(status_code=404, detail={"ok": False, "message": "Session not found"})


def _parse_range(range_header: str, file_size: int):
    m = re.match(r"^bytes=(\d+)-(\d*)$", range_header.strip())
    if not m:
        return None
    start = int(m.group(1))
    end_str = m.group(2)
    end = int(end_str) if end_str else file_size - 1
    if start > end or start >= file_size:
        return None
    return start, end


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
    request: Request,
    path: str = Query(...),
    manager: SSHManager = Depends(get_ssh_manager),
):
    session = _get_session(session_id, manager)
    filename = path.rstrip("/").split("/")[-1] or "download"
    try:
        file_size = await session.sftp.getsize(path)

        range_header = request.headers.get("Range")
        range_parsed = _parse_range(range_header, file_size) if range_header else None

        if range_parsed:
            range_start, range_end = range_parsed
            content_length = range_end - range_start + 1

            async def file_stream():
                async with session.sftp.open(path, "rb") as remote_file:
                    await remote_file.seek(range_start)
                    remaining = content_length
                    while remaining > 0:
                        chunk = await remote_file.read(min(65536, remaining))
                        if not chunk:
                            break
                        remaining -= len(chunk)
                        yield chunk

            headers = {
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Range": f"bytes {range_start}-{range_end}/{file_size}",
                "Content-Length": str(content_length),
                "Accept-Ranges": "bytes",
            }
            return StreamingResponse(file_stream(), status_code=206, media_type="application/octet-stream", headers=headers)

        async def file_stream():
            async with session.sftp.open(path, "rb") as remote_file:
                while True:
                    chunk = await remote_file.read(65536)
                    if not chunk:
                        break
                    yield chunk

        headers = {
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(file_size),
            "Accept-Ranges": "bytes",
        }
        return StreamingResponse(file_stream(), media_type="application/octet-stream", headers=headers)
    except Exception as e:
        raise HTTPException(status_code=400, detail={"ok": False, "message": str(e)})
