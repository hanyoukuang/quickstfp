from typing import Optional

from app.config import settings
from app.service.ssh_manager import SSHManager
from database.user_model import UserInfoDB
from app.service.snippet_service import SnippetService


ssh_manager: SSHManager = SSHManager()
db: Optional[UserInfoDB] = None
snippet_service: Optional[SnippetService] = None


def get_ssh_manager() -> SSHManager:
    return ssh_manager


def get_db() -> UserInfoDB:
    global db
    if db is None:
        db = UserInfoDB(db_path=settings.db_path)
    return db


def get_snippet_service() -> SnippetService:
    global snippet_service
    if snippet_service is None:
        snippet_service = SnippetService(snippets_file=settings.snippets_file)
    return snippet_service
