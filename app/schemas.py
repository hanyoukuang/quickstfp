from typing import Optional, Literal
from pydantic import BaseModel, Field


class SiteCreate(BaseModel):
    auth_type: Literal["password", "key"] = "password"
    host: str = Field(..., min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(..., min_length=1)
    password: Optional[str] = None
    key_path: Optional[str] = None
    passphrase: Optional[str] = None


class SiteUpdate(BaseModel):
    auth_type: Literal["password", "key"] = "password"
    host: str = Field(..., min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(..., min_length=1)
    password: Optional[str] = None
    key_path: Optional[str] = None
    passphrase: Optional[str] = None


class SiteResponse(BaseModel):
    id: int
    auth_type: str
    host: str
    port: int
    username: str
    key_path: Optional[str] = None


class FileEntry(BaseModel):
    name: str
    path: str
    size: int
    size_display: str
    type: str
    mtime: float
    mtime_display: str
    permissions: str


class FileListResponse(BaseModel):
    current_path: str
    entries: list[FileEntry]


class MessageResponse(BaseModel):
    ok: bool
    message: str


class RenameRequest(BaseModel):
    old_path: str
    new_name: str


class PathPairRequest(BaseModel):
    src: str
    dst: str


class SessionCreate(BaseModel):
    host: str = Field(..., min_length=1)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(..., min_length=1)
    password: Optional[str] = None
    client_keys: Optional[list[str]] = None
    passphrase: Optional[str] = None


class SessionInfo(BaseModel):
    session_id: str
    host: str
    port: int
    username: str
    banner_msg: str


class SnippetCreate(BaseModel):
    name: str = Field(..., min_length=1)
    cmd: str = Field(..., min_length=1)
    scope: Literal["global", "site"] = "global"


class SnippetUpdate(BaseModel):
    name: str = Field(..., min_length=1)
    cmd: str = Field(..., min_length=1)
    scope: Literal["global", "site"] = "global"
