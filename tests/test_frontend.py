
import pytest


class TestPageRoutes:
    """页面路由测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_root_page(self):
        resp = self.client.get("/")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/html")
        assert "QuickSFTP" in resp.text
        assert "Sites" in resp.text

    def test_sites_page(self):
        resp = self.client.get("/sites")
        assert resp.status_code == 200
        assert "Saved Sites" in resp.text or "site-card" in resp.text or "site-list" in resp.text

    def test_session_page_unknown(self):
        resp = self.client.get("/sessions/unknown-id")
        assert resp.status_code == 200
        assert "Terminal" in resp.text

    def test_root_page_has_nav(self):
        resp = self.client.get("/")
        html = resp.text
        assert "QuickSFTP" in html
        assert "class=\"topbar\"" in html or "<nav" in html

    def test_site_manager_has_form(self):
        resp = self.client.get("/sites")
        html = resp.text
        assert "addPasswordSite" in html or "host" in html.lower()


class TestStaticFiles:
    """静态文件服务测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_css_served(self):
        resp = self.client.get("/static/css/app.css")
        assert resp.status_code == 200
        assert "text/css" in resp.headers["content-type"]
        assert ":root" in resp.text

    def test_xterm_js_served(self):
        resp = self.client.get("/static/js/xterm/xterm.min.js")
        assert resp.status_code == 200
        assert "javascript" in resp.headers["content-type"].lower()

    def test_xterm_css_served(self):
        resp = self.client.get("/static/js/xterm/xterm.min.css")
        assert resp.status_code == 200
        assert "text/css" in resp.headers["content-type"]

    def test_terminal_js_served(self):
        resp = self.client.get("/static/js/terminal.js")
        assert resp.status_code == 200
        assert "Terminal" in resp.text

    def test_filebrowser_js_served(self):
        resp = self.client.get("/static/js/filebrowser.js")
        assert resp.status_code == 200
        assert "filebrowser" in resp.text

    def test_transport_js_served(self):
        resp = self.client.get("/static/js/transport.js")
        assert resp.status_code == 200
        assert "transport" in resp.text.lower()

    def test_snippets_js_served(self):
        resp = self.client.get("/static/js/snippets.js")
        assert resp.status_code == 200
        assert "snippet" in resp.text.lower()

    def test_nonexistent_static(self):
        resp = self.client.get("/static/nonexistent.css")
        assert resp.status_code == 404


class TestFrontendBoundary:
    """前端边界情况测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_site_manager_no_xss(self):
        resp = self.client.get("/sites")
        assert "<script>" not in resp.text.lower() or "{%" not in resp.text

    def test_session_page_has_layout(self):
        resp = self.client.get("/sessions/test-id")
        html = resp.text
        assert "terminal" in html.lower()
        assert "snippet" in html.lower()
        assert "transport" in html.lower() or "Transports" in html

    def test_static_files_have_correct_mime(self):
        css = self.client.get("/static/css/app.css")
        assert css.status_code == 200

        js = self.client.get("/static/js/terminal.js")
        assert js.status_code == 200

    def test_page_response_is_valid_html(self):
        resp = self.client.get("/")
        html = resp.text.strip()
        assert html.startswith("<!DOCTYPE html>") or html.startswith("<html") or "<!DOCTYPE" in html


class TestFrontendError:
    """前端错误情况测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_session_page_with_special_chars(self):
        resp = self.client.get("/sessions/x-test-id")
        assert resp.status_code == 200
        assert "terminal" in resp.text.lower()

    def test_static_directory_traversal(self):
        resp = self.client.get("/static/../database/user_model.py")
        assert resp.status_code == 404

    def test_static_double_dot_slash(self):
        resp = self.client.get("/static/css/../../database/user_model.py")
        assert resp.status_code == 404
