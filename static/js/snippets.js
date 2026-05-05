// static/js/snippets.js
(function () {
    try {
        var container = document.getElementById('snippets-panel');
        if (!container) return;

        var sessionId = container.getAttribute('data-session-id') || '';

        function loadSnippets() {
            var url = '/api/snippets?site_id=' + encodeURIComponent(sessionId);
            fetch(url)
                .then(function (r) {
                    if (!r.ok) throw new Error('HTTP ' + r.status);
                    return r.json();
                })
                .then(function (data) { renderSnippets(data); })
                .catch(function () {
                    var list = container.querySelector('.snippet-list');
                    if (list) list.innerHTML = '<div style="padding:12px;text-align:center;color:var(--danger);font-size:12px;">Failed to load snippets</div>';
                });
        }

        function renderSnippets(data) {
            var list = container.querySelector('.snippet-list');
            if (!list) return;
            list.innerHTML = '';

            var hasGlobal = data.global && data.global.length > 0;
            var hasSite = data.site && data.site.length > 0;

            if (hasGlobal) {
                var globalHeader = document.createElement('div');
                globalHeader.style.cssText = 'padding:6px 10px;font-size:11px;color:var(--text-muted);font-weight:600;';
                globalHeader.textContent = '🌐 Global';
                list.appendChild(globalHeader);
                data.global.forEach(function (snip, idx) {
                    list.appendChild(createSnippetEl(snip, 'global', idx));
                });
            }

            if (hasSite) {
                var siteHeader = document.createElement('div');
                siteHeader.style.cssText = 'padding:6px 10px;font-size:11px;color:var(--text-muted);font-weight:600;margin-top:4px;';
                siteHeader.textContent = '💻 Site';
                list.appendChild(siteHeader);
                data.site.forEach(function (snip, idx) {
                    list.appendChild(createSnippetEl(snip, 'site', idx));
                });
            }

            if (!hasGlobal && !hasSite) {
                var empty = document.createElement('div');
                empty.style.cssText = 'padding:12px;text-align:center;color:var(--text-muted);font-size:12px;';
                empty.textContent = 'No snippets. Click + to add.';
                list.appendChild(empty);
            }
        }

        function createSnippetEl(snip, scope, idx) {
            var div = document.createElement('div');
            div.className = 'snippet-item';
            div.innerHTML = '<div style="font-weight:500;">' + escapeHtml(snip.name) + '</div>' +
                '<div class="cmd">' + escapeHtml(snip.cmd) + '</div>';
            div.title = snip.cmd || '';

            div.onclick = function () {
                var terminalInput = new CustomEvent('sendToTerminal', {
                    detail: { command: (snip.cmd || '') + '\n' },
                });
                try { document.dispatchEvent(terminalInput); } catch (e) {}
            };

            div.oncontextmenu = function (e) {
                e.preventDefault();
                if (confirm('Delete snippet "' + snip.name + '"?')) {
                    fetch('/api/snippets/' + idx + '?scope=' + encodeURIComponent(scope) + '&site_id=' + encodeURIComponent(sessionId), {
                        method: 'DELETE',
                    })
                        .then(function (r) { return r.json(); })
                        .then(function (data) { if (data.ok) loadSnippets(); })
                        .catch(function () {});
                }
            };

            return div;
        }

        function escapeHtml(str) {
            var div = document.createElement('div');
            div.textContent = str || '';
            return div.innerHTML;
        }

        var addBtn = document.getElementById('btn-add-snippet');
        if (addBtn) {
            addBtn.onclick = function () {
                var name = prompt('Snippet name:');
                if (!name || !name.trim()) return;
                var cmd = prompt('Command:');
                if (!cmd || !cmd.trim()) return;
                var scope = confirm('Press OK for Global scope, Cancel for Site scope.') ? 'global' : 'site';

                fetch('/api/snippets?site_id=' + encodeURIComponent(sessionId), {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: name.trim(), cmd: cmd.trim(), scope: scope }),
                })
                    .then(function (r) { return r.json(); })
                    .then(function () { loadSnippets(); })
                    .catch(function () {});
            };
        }

        loadSnippets();
    } catch (e) {
        console.error('Snippets init error:', e);
    }
})();
