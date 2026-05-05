import pytest


class TestPageRoutesNormal:
    """页面路由正常情况测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_root_returns_200(self):
        resp = self.client.get("/")
        assert resp.status_code == 200

    def test_sites_returns_200(self):
        resp = self.client.get("/sites")
        assert resp.status_code == 200

    def test_session_page_returns_200(self):
        resp = self.client.get("/sessions/test-id")
        assert resp.status_code == 200

    def test_root_is_html(self):
        resp = self.client.get("/")
        ct = resp.headers.get("content-type", "")
        assert "text/html" in ct

    def test_root_contains_brand(self):
        resp = self.client.get("/")
        assert "QuickSFTP" in resp.text

    def test_sites_contains_form(self):
        resp = self.client.get("/sites")
        assert "Host" in resp.text or "password" in resp.text.lower()

    def test_non_empty_session_id(self):
        resp = self.client.get("/sessions/abc123-xyz")
        assert resp.status_code == 200

    def test_session_page_has_terminal_div(self):
        resp = self.client.get("/sessions/test-id")
        assert "terminal-container" in resp.text or "terminal" in resp.text.lower()

    def test_session_page_has_filebrowser(self):
        resp = self.client.get("/sessions/test-id")
        assert "filebrowser" in resp.text or "Files" in resp.text

    def test_session_page_has_snippets(self):
        resp = self.client.get("/sessions/test-id")
        assert "snippet" in resp.text.lower()

    def test_session_page_has_transport(self):
        resp = self.client.get("/sessions/test-id")
        assert "transport" in resp.text.lower() or "Transports" in resp.text


class TestStaticFilesNormal:
    """静态文件正常情况测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_css_served(self):
        resp = self.client.get("/static/css/app.css")
        assert resp.status_code == 200
        assert "text/css" in resp.headers["content-type"]

    def test_terminal_js(self):
        resp = self.client.get("/static/js/terminal.js")
        assert resp.status_code == 200

    def test_filebrowser_js(self):
        resp = self.client.get("/static/js/filebrowser.js")
        assert resp.status_code == 200

    def test_transport_js(self):
        resp = self.client.get("/static/js/transport.js")
        assert resp.status_code == 200

    def test_snippets_js(self):
        resp = self.client.get("/static/js/snippets.js")
        assert resp.status_code == 200

    def test_xterm_js(self):
        resp = self.client.get("/static/js/xterm/xterm.min.js")
        assert resp.status_code == 200

    def test_xterm_css(self):
        resp = self.client.get("/static/js/xterm/xterm.min.css")
        assert resp.status_code == 200

    def test_xterm_fit_addon(self):
        resp = self.client.get("/static/js/xterm/xterm-addon-fit.min.js")
        assert resp.status_code == 200

    def test_all_js_files_non_empty(self):
        files = [
            "/static/js/terminal.js",
            "/static/js/filebrowser.js",
            "/static/js/transport.js",
            "/static/js/snippets.js",
        ]
        for path in files:
            resp = self.client.get(path)
            assert resp.status_code == 200
            assert len(resp.content) > 0, f"{path} is empty"


class TestTemplateContentNormal:
    """模板内容正常测试"""

    @pytest.fixture(autouse=True)
    def setup(self, client):
        self.client = client

    def test_base_nav_structure(self):
        resp = self.client.get("/")
        html = resp.text
        assert "class=\"topbar\"" in html or "<nav" in html
        assert "main" in html.lower()

    def test_script_tags_present(self):
        resp = self.client.get("/sessions/test-id")
        html = resp.text
        assert "terminal.js" in html
        assert "filebrowser.js" in html
        assert "snippets.js" in html
        assert "transport.js" in html

    def test_xterm_scripts_present(self):
        resp = self.client.get("/sessions/test-id")
        html = resp.text
        assert "xterm.min.js" in html
        assert "xterm-addon-fit.min.js" in html

    def test_css_file_linked(self):
        resp = self.client.get("/")
        html = resp.text
        assert "app.css" in html
