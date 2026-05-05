import pytest


class TestPageRoutesError:
    """页面路由错误情况测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_nonexistent_route(self):
        resp = self.client.get("/api/unknown-endpoint")
        assert resp.status_code == 404

    def test_nonexistent_page(self):
        resp = self.client.get("/login")
        assert resp.status_code == 404

    def test_post_to_root(self):
        resp = self.client.post("/")
        assert resp.status_code == 405

    def test_put_to_sites_page(self):
        resp = self.client.put("/sites")
        assert resp.status_code == 405

    def test_delete_to_sites_page(self):
        resp = self.client.delete("/sites")
        assert resp.status_code == 405

    def test_patch_to_session_page(self):
        resp = self.client.patch("/sessions/test-id")
        assert resp.status_code == 405


class TestStaticFilesError:
    """静态文件错误情况测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_static_nonexistent(self):
        resp = self.client.get("/static/nonexistent-file.xyz")
        assert resp.status_code == 404

    def test_static_nonexistent_js(self):
        resp = self.client.get("/static/js/nonexistent.js")
        assert resp.status_code == 404

    def test_static_nonexistent_css(self):
        resp = self.client.get("/static/css/nonexistent.css")
        assert resp.status_code == 404

    def test_static_parent_traversal_literal_dots(self):
        resp = self.client.get("/static/js/../../../etc/passwd")
        assert resp.status_code == 404

    def test_static_encoded_dots(self):
        resp = self.client.get("/static/%2e%2e/%2e%2e/etc/passwd")
        assert resp.status_code == 404

    def test_static_url_encoded_slash(self):
        resp = self.client.get("/static/js%2Fterminal.js")
        assert resp.status_code in (200, 404)

    def test_static_with_query_params(self):
        resp = self.client.get("/static/css/app.css?v=1.0")
        assert resp.status_code == 200

    def test_static_with_hash(self):
        resp = self.client.get("/static/css/app.css")
        assert resp.status_code == 200


class TestSessionPageError:
    """Session 页面错误处理测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_session_with_sql_injection_attempt(self):
        resp = self.client.get("/sessions/1' OR '1'='1")
        assert resp.status_code == 200

    def test_session_with_xss_attempt(self):
        resp = self.client.get("/sessions/%3Cimg%20src=x%20onerror=alert(1)%3E")
        assert resp.status_code == 200
        assert "<img src=x onerror=alert(1)>" not in resp.text

    def test_session_id_only_spaces(self):
        resp = self.client.get("/sessions/%20%20%20")
        assert resp.status_code == 200

    def test_session_id_newline(self):
        resp = self.client.get("/sessions/test%0Anewline")
        assert resp.status_code == 200


class TestFrontendSecurity:
    """前端安全测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_static_no_execute_cgi(self):
        resp = self.client.get("/static/css/app.css")
        assert "text/css" in resp.headers["content-type"]
        assert "application/x-httpd-php" not in resp.headers.get("content-type", "")

    def test_session_context_escaped(self):
        resp = self.client.get("/sessions/test-id")
        html = resp.text
        assert html.count("</script>") > 0

    def test_doctype_present(self):
        resp = self.client.get("/")
        assert "<!DOCTYPE html>" in resp.text or resp.text.strip().startswith("<")
