from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.deps import ssh_manager, get_db, get_snippet_service
from app.router import site, session, sftp, transport, snippet, page
from app.websocket import terminal, progress


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_db()
    get_snippet_service()
    yield
    await ssh_manager.disconnect_all()


app = FastAPI(
    title="QuickSFTP Web",
    version="0.1.0",
    lifespan=lifespan,
)


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(
        status_code=400,
        content={"ok": False, "message": str(exc)},
    )


app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(site.router, prefix="/api")
app.include_router(session.router, prefix="/api")
app.include_router(sftp.router, prefix="/api")
app.include_router(transport.router, prefix="/api")
app.include_router(snippet.router, prefix="/api")
app.include_router(terminal.router, prefix="/ws")
app.include_router(progress.router, prefix="/ws")
app.include_router(page.router)
