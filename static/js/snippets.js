// static/js/snippets.js
(function () {
    const container = document.getElementById('snippets-panel');
    if (!container) return;

    const sessionId = container.dataset.sessionId;

    function loadSnippets() {
        const url = `/api/snippets?site_id=${encodeURIComponent(sessionId || '')}`;
        fetch(url)
            .then(r => r.json())
            .then(data => {
                renderSnippets(data);
            })
            .catch(() => {});
    }

    function renderSnippets(data) {
        const list = container.querySelector('.snippet-list');
        if (!list) return;
        list.innerHTML = '';

        if (data.global && data.global.length > 0) {
            const globalHeader = document.createElement('div');
            globalHeader.style.cssText = 'padding:6px 10px;font-size:11px;color:var(--text-muted);font-weight:600;';
            globalHeader.textContent = '🌐 Global';
            list.appendChild(globalHeader);
            data.global.forEach((snip, idx) => {
                list.appendChild(createSnippetEl(snip, 'global', idx));
            });
        }

        if (data.site && data.site.length > 0) {
            const siteHeader = document.createElement('div');
            siteHeader.style.cssText = 'padding:6px 10px;font-size:11px;color:var(--text-muted);font-weight:600;margin-top:4px;';
            siteHeader.textContent = '💻 Site';
            list.appendChild(siteHeader);
            data.site.forEach((snip, idx) => {
                list.appendChild(createSnippetEl(snip, 'site', idx));
            });
        }

        if ((!data.global || data.global.length === 0) && (!data.site || data.site.length === 0)) {
            const empty = document.createElement('div');
            empty.style.cssText = 'padding:12px;text-align:center;color:var(--text-muted);font-size:12px;';
            empty.textContent = 'No snippets. Click + to add.';
            list.appendChild(empty);
        }
    }

    function createSnippetEl(snip, scope, idx) {
        const div = document.createElement('div');
        div.className = 'snippet-item';
        div.innerHTML = `
            <div style="font-weight:500;">${escapeHtml(snip.name)}</div>
            <div class="cmd">${escapeHtml(snip.cmd)}</div>
        `;
        div.title = snip.cmd;

        div.onclick = () => {
            const terminalInput = new CustomEvent('sendToTerminal', {
                detail: { command: snip.cmd + '\n' },
            });
            document.dispatchEvent(terminalInput);
        };

        div.oncontextmenu = (e) => {
            e.preventDefault();
            if (confirm(`Delete snippet "${snip.name}"?`)) {
                fetch(`/api/snippets/${idx}?scope=${scope}&site_id=${encodeURIComponent(sessionId || '')}`, {
                    method: 'DELETE',
                })
                    .then(r => r.json())
                    .then(data => {
                        if (data.ok) loadSnippets();
                    })
                    .catch(() => {});
            }
        };

        return div;
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    const addBtn = document.getElementById('btn-add-snippet');
    if (addBtn) {
        addBtn.onclick = () => {
            const name = prompt('Snippet name:');
            if (!name) return;
            const cmd = prompt('Command:');
            if (!cmd) return;
            const scope = confirm('Press OK for Global scope, Cancel for Site scope.') ? 'global' : 'site';

            fetch(`/api/snippets?site_id=${encodeURIComponent(sessionId || '')}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name, cmd, scope }),
            })
                .then(r => r.json())
                .then(() => loadSnippets())
                .catch(() => {});
        };
    }

    loadSnippets();
})();
