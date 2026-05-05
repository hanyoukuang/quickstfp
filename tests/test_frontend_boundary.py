import pytest


class TestPageRoutesBoundary:
    """页面路由边界情况测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_session_id_empty_string(self):
        resp = self.client.get("/sessions/")
        assert resp.status_code in (200, 307, 404)

    def test_session_id_single_char(self):
        resp = self.client.get("/sessions/a")
        assert resp.status_code == 200

    def test_session_id_very_long(self):
        long_id = "x" * 500
        resp = self.client.get("/sessions/" + long_id)
        assert resp.status_code == 200

    def test_session_id_with_slashes(self):
        resp = self.client.get("/sessions/a/b/c")
        assert resp.status_code == 404

    def test_session_id_with_spaces(self):
        resp = self.client.get("/sessions/hello%20world")
        assert resp.status_code == 200

    def test_session_id_numeric(self):
        resp = self.client.get("/sessions/12345")
        assert resp.status_code == 200

    def test_session_id_special_chars_hyphen(self):
        resp = self.client.get("/sessions/test-id-123")
        assert resp.status_code == 200

    def test_session_id_unicode(self):
        resp = self.client.get("/sessions/%E4%B8%AD%E6%96%87")
        assert resp.status_code == 200


class TestStaticFilesBoundary:
    """静态文件边界情况测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_static_empty_path(self):
        resp = self.client.get("/static/")
        assert resp.status_code in (200, 404, 307)

    def test_static_directory_listing(self):
        resp = self.client.get("/static/css/")
        assert resp.status_code in (404, 403)

    def test_static_very_long_path(self):
        long_name = "a/" * 50 + "test.css"
        resp = self.client.get("/static/" + long_name)
        assert resp.status_code == 404

    def test_static_dotfile(self):
        resp = self.client.get("/static/.hidden")
        assert resp.status_code == 404

    def test_static_null_byte(self):
        resp = self.client.get("/static/css/app.css%00extra")
        assert resp.status_code in (400, 404, 422)

    def test_head_request_root(self):
        resp = self.client.head("/")
        assert resp.status_code in (200, 405)

    def test_head_request_static(self):
        resp = self.client.head("/static/css/app.css")
        assert resp.status_code == 200

    def test_head_request_session(self):
        resp = self.client.head("/sessions/test-id")
        assert resp.status_code in (200, 405)

    def test_content_type_static_js(self):
        resp = self.client.get("/static/js/terminal.js")
        ct = resp.headers.get("content-type", "")
        assert "javascript" in ct.lower() or "text/" in ct.lower()

    def test_unknown_page_route(self):
        resp = self.client.get("/nonexistent-route")
        assert resp.status_code == 404


class TestTemplateBoundary:
    """模板边界测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_site_manager_no_jinja_leak(self):
        resp = self.client.get("/sites")
        assert "{{" not in resp.text and "{%" not in resp.text

    def test_session_page_no_jinja_leak(self):
        resp = self.client.get("/sessions/test-id")
        assert "{{" not in resp.text and "{%" not in resp.text

    def test_error_page_no_jinja_leak(self):
        resp = self.client.get("/sessions/%00invalid")
        if resp.status_code == 200:
            assert "{{" not in resp.text and "{%" not in resp.text

    def test_session_id_plus_sign(self):
        resp = self.client.get("/sessions/hello+world")
        assert resp.status_code == 200
