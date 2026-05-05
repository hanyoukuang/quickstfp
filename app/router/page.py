from fastapi import APIRouter, Depends, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse

from app.deps import get_ssh_manager
from app.service.ssh_manager import SSHManager

router = APIRouter(tags=["pages"])

templates = Jinja2Templates(directory="app/template")


@router.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse(request, "site_manager.html", {"request": request})


@router.get("/sites", response_class=HTMLResponse)
async def sites_page(request: Request):
    return templates.TemplateResponse(request, "site_manager.html", {"request": request})


@router.get("/sessions/{session_id}", response_class=HTMLResponse)
async def session_page(request: Request, session_id: str, manager: SSHManager = Depends(get_ssh_manager)):
    try:
        session = manager.get(session_id)
        context = {
            "request": request,
            "session_id": session_id,
            "host": session.host,
            "username": session.username,
            "port": session.port,
        }
    except Exception:
        context = {"request": request, "session_id": session_id, "host": "unknown", "username": "unknown", "port": 0}
    return templates.TemplateResponse(request, "session.html", context)
