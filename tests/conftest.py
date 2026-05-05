import os
import tempfile

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.deps import get_db, get_snippet_service
from database.user_model import UserInfoDB
from app.service.snippet_service import SnippetService


@pytest.fixture(autouse=True)
def reset_overrides():
    app.dependency_overrides.clear()
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def test_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db_instance = UserInfoDB(db_path=path)
    yield db_instance
    db_instance.close()
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def test_snippet_service():
    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    service = SnippetService(snippets_file=path)
    yield service
    if os.path.exists(path):
        os.unlink(path)


@pytest.fixture
def client_with_db(client, test_db):
    app.dependency_overrides[get_db] = lambda: test_db
    yield client
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def client_with_snippets(client, test_snippet_service):
    app.dependency_overrides[get_snippet_service] = lambda: test_snippet_service
    yield client
    app.dependency_overrides.pop(get_snippet_service, None)
