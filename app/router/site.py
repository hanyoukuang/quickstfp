import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException

from app.deps import get_db
from app.schemas import SiteCreate, SiteUpdate, SiteResponse, MessageResponse
from database.user_model import UserInfoDB

router = APIRouter(tags=["sites"])


def _build_response(db_row: tuple, auth_type: str) -> dict:
    if auth_type == "password":
        idx, host, port, username, _password = db_row
        return {"id": idx, "auth_type": "password", "host": host, "port": port, "username": username, "key_path": None}
    else:
        idx, host, port, username, key_path, _passphrase = db_row
        return {"id": idx, "auth_type": "key", "host": host, "port": port, "username": username, "key_path": key_path}


@router.get("/sites", response_model=list[SiteResponse])
def list_sites(db: UserInfoDB = Depends(get_db)):
    sites = []
    for row in db.query_all_password():
        sites.append(_build_response(row, "password"))
    for row in db.query_all_key():
        sites.append(_build_response(row, "key"))
    return sites


@router.post("/sites", response_model=SiteResponse)
def create_site(payload: SiteCreate, db: UserInfoDB = Depends(get_db)):
    if payload.auth_type == "password":
        db.insert_password(
            host=payload.host,
            port=payload.port,
            username=payload.username,
            password=payload.password or "",
        )
        rows = db.query_password(payload.host, payload.port, payload.username, payload.password or "")
        if not rows:
            raise HTTPException(status_code=500, detail={"ok": False, "message": "Failed to create site"})
        return _build_response(rows[0], "password")
    else:
        db.insert_key(
            host=payload.host,
            port=payload.port,
            username=payload.username,
            key_path=payload.key_path or "",
            passphrase=payload.passphrase or "",
        )
        rows = db.query_key(payload.host, payload.port, payload.username, payload.key_path or "", payload.passphrase or "")
        if not rows:
            raise HTTPException(status_code=500, detail={"ok": False, "message": "Failed to create site"})
        return _build_response(rows[0], "key")


@router.put("/sites/{site_id}", response_model=SiteResponse)
def update_site(site_id: int, payload: SiteUpdate, db: UserInfoDB = Depends(get_db)):
    if payload.auth_type == "password":
        db.update_password(
            idx=site_id,
            host=payload.host,
            port=payload.port,
            username=payload.username,
            password=payload.password or "",
        )
        row = db.query_idx_password(site_id)
        if not row:
            raise HTTPException(status_code=404, detail={"ok": False, "message": "Site not found"})
        return _build_response(row, "password")
    else:
        db.update_key(
            idx=site_id,
            host=payload.host,
            port=payload.port,
            username=payload.username,
            key_path=payload.key_path or "",
            passphrase=payload.passphrase or "",
        )
        row = db.query_idx_key(site_id)
        if not row:
            raise HTTPException(status_code=404, detail={"ok": False, "message": "Site not found"})
        return _build_response(row, "key")


@router.delete("/sites/{site_id}", response_model=MessageResponse)
def delete_site(site_id: int, auth_type: str = "password", db: UserInfoDB = Depends(get_db)):
    if auth_type == "password":
        row = db.query_idx_password(site_id)
        if not row:
            raise HTTPException(status_code=404, detail={"ok": False, "message": "Site not found"})
        db.del_idx_password(site_id)
    else:
        row = db.query_idx_key(site_id)
        if not row:
            raise HTTPException(status_code=404, detail={"ok": False, "message": "Site not found"})
        db.del_idx_key(site_id)
    return {"ok": True, "message": "Site deleted"}


@router.get("/sites/export", response_model=MessageResponse)
def export_sites(db: UserInfoDB = Depends(get_db)):
    data: list[dict[str, Any]] = []
    for row in db.query_all_password():
        idx, host, port, username, password = row
        data.append({"auth_type": "password", "host": host, "port": port, "username": username, "password": password})
    for row in db.query_all_key():
        idx, host, port, username, key_path, passphrase = row
        data.append({"auth_type": "key", "host": host, "port": port, "username": username, "key_path": key_path, "passphrase": passphrase})
    return {"ok": True, "message": json.dumps(data, ensure_ascii=False)}


@router.post("/sites/import", response_model=MessageResponse)
def import_sites(payload: dict, db: UserInfoDB = Depends(get_db)):
    items = payload.get("data", [])
    if not isinstance(items, list):
        raise HTTPException(status_code=400, detail={"ok": False, "message": "data must be a list"})
    count = 0
    for item in items:
        auth_type = item.get("auth_type", "password")
        if auth_type == "password":
            db.insert_password(
                host=item.get("host", ""),
                port=item.get("port", 22),
                username=item.get("username", ""),
                password=item.get("password", ""),
            )
        else:
            db.insert_key(
                host=item.get("host", ""),
                port=item.get("port", 22),
                username=item.get("username", ""),
                key_path=item.get("key_path", ""),
                passphrase=item.get("passphrase", ""),
            )
        count += 1
    return {"ok": True, "message": f"Imported {count} sites"}
