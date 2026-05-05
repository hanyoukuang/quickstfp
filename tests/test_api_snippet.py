import os
import tempfile

import pytest

from app.service.snippet_service import SnippetService


class TestSnippetService:
    """SnippetService 纯单元测试"""

    @pytest.fixture
    def service(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        svc = SnippetService(snippets_file=path)
        yield svc
        if os.path.exists(path):
            os.unlink(path)

    def test_empty_get(self, service):
        result = service.get_snippets()
        assert result["global"] == []
        assert result["site"] == []

    def test_add_global(self, service):
        service.add_snippet("docker logs", "docker logs -f", scope="global")
        result = service.get_snippets()
        assert len(result["global"]) == 1
        assert result["global"][0]["name"] == "docker logs"
        assert result["global"][0]["cmd"] == "docker logs -f"

    def test_add_site_specific(self, service):
        service.add_snippet("site cmd", "echo site", scope="site", site_id="server1")
        result = service.get_snippets(site_id="server1")
        assert len(result["site"]) == 1
        assert result["site"][0]["name"] == "site cmd"

    def test_update_snippet(self, service):
        service.add_snippet("old", "echo old", scope="global")
        service.update_snippet(0, "new", "echo new", scope="global")
        result = service.get_snippets()
        assert result["global"][0]["name"] == "new"
        assert result["global"][0]["cmd"] == "echo new"

    def test_delete_snippet(self, service):
        service.add_snippet("cmd1", "echo 1", scope="global")
        service.add_snippet("cmd2", "echo 2", scope="global")
        assert service.delete_snippet(0, scope="global")
        result = service.get_snippets()
        assert len(result["global"]) == 1
        assert result["global"][0]["cmd"] == "echo 2"

    def test_update_nonexistent(self, service):
        result = service.update_snippet(99, "x", "y", scope="global")
        assert result is None

    def test_delete_nonexistent(self, service):
        assert not service.delete_snippet(99, scope="global")

    def test_delete_out_of_bounds(self, service):
        service.add_snippet("only", "echo only", scope="global")
        assert not service.delete_snippet(1, scope="global")
        assert not service.delete_snippet(-1, scope="global")

    def test_site_isolation(self, service):
        service.add_snippet("same name", "cmd a", scope="site", site_id="A")
        service.add_snippet("same name", "cmd b", scope="site", site_id="B")
        result_a = service.get_snippets(site_id="A")
        result_b = service.get_snippets(site_id="B")
        assert len(result_a["site"]) == 1
        assert len(result_b["site"]) == 1
        assert result_a["site"][0]["cmd"] == "cmd a"
        assert result_b["site"][0]["cmd"] == "cmd b"

    def test_persistence(self, service):
        service.add_snippet("persist", "echo saved", scope="global")
        # Create a new service instance pointing to the same file
        svc2 = SnippetService(snippets_file=service.snippets_file)
        result = svc2.get_snippets()
        assert len(result["global"]) == 1
        assert result["global"][0]["name"] == "persist"


class TestSnippetAPI:
    """Snippet API 集成测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client_with_snippets):
        self.client = client_with_snippets

    def test_list_empty(self):
        resp = self.client.get("/api/snippets")
        assert resp.status_code == 200
        data = resp.json()
        assert data["global"] == []
        assert data["site"] == []

    def test_add_snippet(self):
        resp = self.client.post("/api/snippets", json={
            "name": "test cmd",
            "cmd": "echo hello",
            "scope": "global",
        })
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        resp2 = self.client.get("/api/snippets")
        assert len(resp2.json()["global"]) == 1

    def test_add_site_snippet(self):
        resp = self.client.post("/api/snippets?site_id=server1", json={
            "name": "site cmd",
            "cmd": "echo site",
            "scope": "site",
        })
        assert resp.status_code == 200

        resp2 = self.client.get("/api/snippets?site_id=server1")
        assert len(resp2.json()["site"]) == 1

    def test_update_snippet(self):
        self.client.post("/api/snippets", json={"name": "old", "cmd": "echo old", "scope": "global"})
        resp = self.client.put("/api/snippets/0", json={
            "name": "new", "cmd": "echo new", "scope": "global",
        })
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        resp2 = self.client.get("/api/snippets")
        assert resp2.json()["global"][0]["name"] == "new"

    def test_delete_snippet(self):
        self.client.post("/api/snippets", json={"name": "tmp", "cmd": "echo tmp", "scope": "global"})
        resp = self.client.delete("/api/snippets/0?scope=global")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        resp2 = self.client.get("/api/snippets")
        assert len(resp2.json()["global"]) == 0

    def test_add_snippet_missing_name(self):
        resp = self.client.post("/api/snippets", json={"cmd": "echo x"})
        assert resp.status_code == 422

    def test_add_snippet_empty_name(self):
        resp = self.client.post("/api/snippets", json={
            "name": "", "cmd": "echo x",
        })
        assert resp.status_code == 422

    def test_add_snippet_empty_cmd(self):
        resp = self.client.post("/api/snippets", json={
            "name": "test", "cmd": "",
        })
        assert resp.status_code == 422

    def test_update_nonexistent(self):
        resp = self.client.put("/api/snippets/99", json={
            "name": "x", "cmd": "y", "scope": "global",
        })
        assert resp.status_code == 404

    def test_delete_nonexistent(self):
        resp = self.client.delete("/api/snippets/99?scope=global")
        assert resp.status_code == 404
