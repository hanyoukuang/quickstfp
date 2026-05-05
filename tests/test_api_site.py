import json
import pytest


class TestSiteAPI:
    """站点 API 正常情况测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client_with_db):
        self.client = client_with_db

    def _create_password_site(self, host="test.example.com", port=22, username="admin", password="secret"):
        resp = self.client.post("/api/sites", json={
            "auth_type": "password",
            "host": host,
            "port": port,
            "username": username,
            "password": password,
        })
        return resp

    def _create_key_site(self, host="key.example.com", port=22, username="admin", key_path="/keys/test"):
        resp = self.client.post("/api/sites", json={
            "auth_type": "key",
            "host": host,
            "port": port,
            "username": username,
            "key_path": key_path,
            "passphrase": "keypass",
        })
        return resp

    def test_create_password_site(self):
        resp = self._create_password_site()
        assert resp.status_code == 200
        data = resp.json()
        assert data["host"] == "test.example.com"
        assert data["auth_type"] == "password"
        assert data["username"] == "admin"
        assert "password" not in data

    def test_create_key_site(self):
        resp = self._create_key_site()
        assert resp.status_code == 200
        data = resp.json()
        assert data["host"] == "key.example.com"
        assert data["auth_type"] == "key"

    def test_list_sites_empty(self):
        resp = self.client.get("/api/sites")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_sites(self):
        self._create_password_site(host="a.com")
        self._create_key_site(host="b.com")
        resp = self.client.get("/api/sites")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_update_password_site(self):
        resp = self._create_password_site()
        site_id = resp.json()["id"]

        resp2 = self.client.put(f"/api/sites/{site_id}", json={
            "auth_type": "password",
            "host": "updated.example.com",
            "port": 2222,
            "username": "newadmin",
            "password": "newpass",
        })
        assert resp2.status_code == 200
        data = resp2.json()
        assert data["host"] == "updated.example.com"
        assert data["port"] == 2222
        assert data["username"] == "newadmin"

    def test_update_key_site(self):
        resp = self._create_key_site()
        site_id = resp.json()["id"]

        resp2 = self.client.put(f"/api/sites/{site_id}", json={
            "auth_type": "key",
            "host": "updated-key.example.com",
            "port": 22,
            "username": "newadmin",
            "key_path": "/keys/updated",
            "passphrase": "newpass",
        })
        assert resp2.status_code == 200
        data = resp2.json()
        assert data["host"] == "updated-key.example.com"
        assert data["key_path"] == "/keys/updated"

    def test_delete_password_site(self):
        resp = self._create_password_site()
        site_id = resp.json()["id"]

        resp2 = self.client.delete(f"/api/sites/{site_id}?auth_type=password")
        assert resp2.status_code == 200
        assert resp2.json()["ok"] is True

        resp3 = self.client.get("/api/sites")
        assert len(resp3.json()) == 0

    def test_delete_key_site(self):
        resp = self._create_key_site()
        site_id = resp.json()["id"]

        resp2 = self.client.delete(f"/api/sites/{site_id}?auth_type=key")
        assert resp2.status_code == 200
        assert resp2.json()["ok"] is True

    def test_export_sites(self):
        self._create_password_site(host="a.com")
        self._create_key_site(host="b.com")
        resp = self.client.get("/api/sites/export")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        exported = json.loads(data["message"])
        assert len(exported) == 2
        assert exported[0]["host"] == "a.com"

    def test_import_sites(self):
        import_data = [
            {"auth_type": "password", "host": "imported.com", "port": 22, "username": "u1", "password": "p1"},
            {"auth_type": "key", "host": "imported2.com", "port": 2222, "username": "u2", "key_path": "/k", "passphrase": "pp"},
        ]
        resp = self.client.post("/api/sites/import", json={"data": import_data})
        assert resp.status_code == 200
        assert "Imported 2" in resp.json()["message"]

        resp2 = self.client.get("/api/sites")
        assert len(resp2.json()) == 2


class TestSiteAPIBoundary:
    """站点 API 边界情况测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client_with_db):
        self.client = client_with_db

    def test_create_site_with_default_port(self):
        resp = self.client.post("/api/sites", json={
            "auth_type": "password",
            "host": "test.example.com",
            "username": "admin",
            "password": "secret",
        })
        assert resp.status_code == 200
        assert resp.json()["port"] == 22

    def test_create_site_with_max_port(self):
        resp = self.client.post("/api/sites", json={
            "auth_type": "password",
            "host": "test.example.com",
            "port": 65535,
            "username": "admin",
            "password": "secret",
        })
        assert resp.status_code == 200
        assert resp.json()["port"] == 65535

    def test_create_site_with_long_hostname(self):
        long_host = "a" * 200 + ".example.com"
        resp = self.client.post("/api/sites", json={
            "auth_type": "password",
            "host": long_host,
            "username": "admin",
            "password": "secret",
        })
        assert resp.status_code == 200

    def test_delete_nonexistent_site(self):
        resp = self.client.delete("/api/sites/9999?auth_type=password")
        assert resp.status_code == 404

    def test_update_nonexistent_site(self):
        resp = self.client.put("/api/sites/9999", json={
            "auth_type": "password",
            "host": "x.com",
            "username": "x",
            "password": "x",
        })
        assert resp.status_code == 404

    def test_import_empty_list(self):
        resp = self.client.post("/api/sites/import", json={"data": []})
        assert resp.status_code == 200
        assert "Imported 0" in resp.json()["message"]

    def test_export_empty(self):
        resp = self.client.get("/api/sites/export")
        assert resp.status_code == 200
        exported = json.loads(resp.json()["message"])
        assert exported == []


class TestSiteAPIError:
    """站点 API 错误情况测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client_with_db):
        self.client = client_with_db

    def test_create_site_missing_host(self):
        resp = self.client.post("/api/sites", json={
            "auth_type": "password",
            "username": "admin",
            "password": "secret",
        })
        assert resp.status_code == 422

    def test_create_site_missing_username(self):
        resp = self.client.post("/api/sites", json={
            "auth_type": "password",
            "host": "test.example.com",
            "password": "secret",
        })
        assert resp.status_code == 422

    def test_create_site_empty_host(self):
        resp = self.client.post("/api/sites", json={
            "auth_type": "password",
            "host": "",
            "username": "admin",
            "password": "secret",
        })
        assert resp.status_code == 422

    def test_create_site_empty_username(self):
        resp = self.client.post("/api/sites", json={
            "auth_type": "password",
            "host": "test.example.com",
            "username": "",
            "password": "secret",
        })
        assert resp.status_code == 422

    def test_create_site_invalid_auth_type(self):
        resp = self.client.post("/api/sites", json={
            "auth_type": "invalid",
            "host": "test.example.com",
            "username": "admin",
            "password": "secret",
        })
        assert resp.status_code == 422

    def test_create_site_port_out_of_range_low(self):
        resp = self.client.post("/api/sites", json={
            "auth_type": "password",
            "host": "test.example.com",
            "port": 0,
            "username": "admin",
            "password": "secret",
        })
        assert resp.status_code == 422

    def test_create_site_port_out_of_range_high(self):
        resp = self.client.post("/api/sites", json={
            "auth_type": "password",
            "host": "test.example.com",
            "port": 65536,
            "username": "admin",
            "password": "secret",
        })
        assert resp.status_code == 422

    def test_create_site_missing_password_for_password_auth(self):
        resp = self.client.post("/api/sites", json={
            "auth_type": "password",
            "host": "test.example.com",
            "username": "admin",
        })
        assert resp.status_code == 200  # password is optional in schema

    def test_import_invalid_format(self):
        resp = self.client.post("/api/sites/import", json={"data": "not_a_list"})
        assert resp.status_code == 400
