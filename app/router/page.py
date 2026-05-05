from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from app.deps import get_ssh_manager
from app.service.ssh_manager import SSHManager, SessionNotFoundError

router = APIRouter(tags=["pages"])

templates = Jinja2Templates(directory="app/template")


@router.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse(request, "site_manager.html", {
        "request": request,
        "error": None,
    })


@router.get("/sites", response_class=HTMLResponse)
async def sites_page(request: Request):
    return templates.TemplateResponse(request, "site_manager.html", {
        "request": request,
        "error": None,
    })


@router.get("/sessions/{session_id}", response_class=HTMLResponse)
async def session_page(request: Request, session_id: str, manager: SSHManager = Depends(get_ssh_manager)):
    if not session_id.strip():
        return templates.TemplateResponse(request, "error.html", {
            "request": request,
            "code": 400,
            "message": "Session ID cannot be empty",
        })

    try:
        session = manager.get(session_id)
        context = {
            "request": request,
            "session_id": session_id,
            "host": session.host,
            "username": session.username,
            "port": session.port,
            "banner": session.banner_msg or "",
            "error": None,
        }
    except SessionNotFoundError:
        context = {
            "request": request,
            "session_id": session_id,
            "host": "unknown",
            "username": "unknown",
            "port": 0,
            "banner": "",
            "error": "Session not found or expired",
        }
    except Exception as e:
        context = {
            "request": request,
            "session_id": session_id,
            "host": "unknown",
            "username": "unknown",
            "port": 0,
            "banner": "",
            "error": str(e),
        }
    return templates.TemplateResponse(request, "session.html", context)
