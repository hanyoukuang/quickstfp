from fastapi import APIRouter, Depends, HTTPException, Query

from app.deps import get_snippet_service
from app.schemas import SnippetCreate, SnippetUpdate, MessageResponse
from app.service.snippet_service import SnippetService

router = APIRouter(tags=["snippets"])


@router.get("/snippets")
def list_snippets(
    site_id: str = Query(default=""),
    service: SnippetService = Depends(get_snippet_service),
):
    return service.get_snippets(site_id)


@router.post("/snippets", response_model=MessageResponse)
def add_snippet(
    payload: SnippetCreate,
    site_id: str = Query(default=""),
    service: SnippetService = Depends(get_snippet_service),
):
    result = service.add_snippet(
        name=payload.name,
        cmd=payload.cmd,
        scope=payload.scope,
        site_id=site_id,
    )
    return {"ok": True, "message": f"Snippet added at index {result['index']}"}


@router.put("/snippets/{index}", response_model=MessageResponse)
def update_snippet(
    index: int,
    payload: SnippetUpdate,
    site_id: str = Query(default=""),
    service: SnippetService = Depends(get_snippet_service),
):
    result = service.update_snippet(
        index=index,
        name=payload.name,
        cmd=payload.cmd,
        scope=payload.scope,
        site_id=site_id,
    )
    if result is None:
        raise HTTPException(status_code=404, detail={"ok": False, "message": "Snippet not found"})
    return {"ok": True, "message": "Snippet updated"}


@router.delete("/snippets/{index}", response_model=MessageResponse)
def delete_snippet(
    index: int,
    scope: str = Query(default="global"),
    site_id: str = Query(default=""),
    service: SnippetService = Depends(get_snippet_service),
):
    ok = service.delete_snippet(index=index, scope=scope, site_id=site_id)
    if not ok:
        raise HTTPException(status_code=404, detail={"ok": False, "message": "Snippet not found"})
    return {"ok": True, "message": "Snippet deleted"}
