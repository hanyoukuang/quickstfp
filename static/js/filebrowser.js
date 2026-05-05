// static/js/filebrowser.js
(function () {
    const container = document.getElementById('filebrowser');
    if (!container) return;

    const sessionId = container.dataset.sessionId;
    let currentPath = '/';

    function buildUrl(path) {
        return `/api/sftp/${sessionId}/list?path=${encodeURIComponent(path || '/')}`;
    }

    function fetchDir(path) {
        currentPath = path;
        fetch(buildUrl(path))
            .then(r => r.json())
            .then(data => {
                if (data.entries !== undefined) {
                    renderTable(data.current_path, data.entries);
                } else {
                    showToast(data.message || 'Error listing directory', 'error');
                }
            })
            .catch(err => {
                showToast('Failed to list directory: ' + err.message, 'error');
            });
    }

    function formatSize(size) {
        if (!size || size <= 0) return '-';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let unitIdx = 0;
        let s = size;
        while (s >= 1024 && unitIdx < units.length - 1) { s /= 1024; unitIdx++; }
        return unitIdx === 0 ? `${s} ${units[unitIdx]}` : `${s.toFixed(2)} ${units[unitIdx]}`;
    }

    function renderTable(path, entries) {
        const tbody = container.querySelector('tbody');
        if (!tbody) return;

        tbody.innerHTML = '';
        if (path !== '/') {
            const parentPath = path.substring(0, path.lastIndexOf('/')) || '/';
            const tr = document.createElement('tr');
            tr.innerHTML = `<td class="name" style="color:var(--primary)">..</td><td>-</td><td>-</td><td>-</td>`;
            tr.onclick = () => fetchDir(parentPath);
            tbody.appendChild(tr);
        }

        entries.sort((a, b) => {
            if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
            return a.name.localeCompare(b.name);
        });

        entries.forEach(entry => {
            const tr = document.createElement('tr');
            tr.className = 'file-row';
            tr.dataset.path = entry.path;
            tr.dataset.type = entry.type;

            const icon = entry.type === 'dir' ? '📁' : '📄';
            tr.innerHTML = `
                <td class="name"><span class="type-${entry.type}">${icon} ${escapeHtml(entry.name)}</span></td>
                <td>${formatSize(entry.size)}</td>
                <td>${entry.permissions || '-'}</td>
                <td>${entry.mtime_display || '-'}</td>
            `;

            tr.onclick = (e) => {
                if (entry.type === 'dir') {
                    fetchDir(entry.path);
                }
            };

            tr.oncontextmenu = (e) => {
                e.preventDefault();
                showContextMenu(e.clientX, e.clientY, entry);
            };

            tr.ondblclick = (e) => {
                if (entry.type === 'file') {
                    openFileEditor(entry.path, entry.name);
                }
            };

            tbody.appendChild(tr);
        });
    }

    function showContextMenu(x, y, entry) {
        let menu = document.getElementById('file-context-menu');
        if (!menu) {
            menu = document.createElement('div');
            menu.id = 'file-context-menu';
            menu.style.cssText = 'position:fixed;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:4px;z-index:200;min-width:160px;box-shadow:0 4px 12px rgba(0,0,0,0.4);';
            document.body.appendChild(menu);
        }

        const items = [];
        if (entry.type === 'dir') {
            items.push({ label: '📂 Open', action: () => fetchDir(entry.path) });
        } else {
            items.push({ label: '✏️ Edit', action: () => openFileEditor(entry.path, entry.name) });
            items.push({ label: '⬇️ Download', action: () => downloadFile(entry.path) });
        }
        items.push({ label: '📋 Copy', action: () => showCopyMoveDialog('copy', entry.path) });
        items.push({ label: '📌 Move', action: () => showCopyMoveDialog('move', entry.path) });
        items.push({ label: '✏️ Rename', action: () => showRenameDialog(entry.path) });
        items.push({ label: '🔒 Permissions', action: () => showChmodDialog(entry.path) });
        items.push({ label: '🗑️ Delete', action: () => deletePath(entry.path) });

        menu.innerHTML = items.map((item, i) =>
            `<div class="context-item" style="padding:6px 12px;cursor:pointer;font-size:13px;border-radius:4px;" 
                  onmouseover="this.style.background='var(--bg)'" 
                  onmouseout="this.style.background='none'"
                  onclick="document.getElementById('file-context-menu').style.display='none'; arguments[0].stopPropagation();"
             >${item.label}</div>`
        ).join('');

        menu.style.display = 'block';
        menu.style.left = `${Math.min(x, window.innerWidth - 170)}px`;
        menu.style.top = `${Math.min(y, window.innerHeight - 200)}px`;

        menu.querySelectorAll('.context-item').forEach((el, i) => {
            el.onclick = (e) => { e.stopPropagation(); items[i].action(); menu.style.display = 'none'; };
        });

        setTimeout(() => {
            document.addEventListener('click', function hideMenu() {
                menu.style.display = 'none';
                document.removeEventListener('click', hideMenu);
            });
        }, 10);
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function showToast(msg, type) {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type || 'success'}`;
        toast.textContent = msg;
        let container = document.querySelector('.toast-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        container.appendChild(toast);
        setTimeout(() => { toast.remove(); }, 3000);
    }

    function downloadFile(path) {
        window.open(`/api/transport/${sessionId}/download?path=${encodeURIComponent(path)}`, '_blank');
    }

    function openFileEditor(path, name) {
        const modal = document.getElementById('editor-modal');
        const editorTitle = document.getElementById('editor-title');
        const editorContainer = document.getElementById('editor-container');
        if (!modal || !editorContainer) return;

        editorTitle.textContent = name;
        modal.classList.add('open');

        fetch(`/api/sftp/${sessionId}/read?path=${encodeURIComponent(path)}`)
            .then(r => r.json())
            .then(data => {
                const content = data.content || '';
                if (window._monacoEditor) {
                    window._monacoEditor.setValue(content);
                    window._monacoEditor._filePath = path;
                }
            })
            .catch(err => {
                showToast('Failed to read: ' + err.message, 'error');
            });
    }

    function showRenameDialog(path) {
        const newName = prompt('Enter new name:', path.split('/').pop());
        if (newName && newName !== path.split('/').pop()) {
            const newPath = path.substring(0, path.lastIndexOf('/') + 1) + newName;
            fetch(`/api/sftp/${sessionId}/rename`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ old_path: path, new_name: newPath }),
            })
                .then(r => r.json())
                .then(data => {
                    if (data.ok) { fetchDir(currentPath); showToast('Renamed', 'success'); }
                })
                .catch(err => showToast('Rename failed: ' + err.message, 'error'));
        }
    }

    function showCopyMoveDialog(action, src) {
        const dst = prompt(`Enter destination path for ${action}:`);
        if (dst) {
            const endpoint = action === 'copy' ? 'copy' : 'move';
            fetch(`/api/sftp/${sessionId}/${endpoint}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ src: src, dst: dst }),
            })
                .then(r => r.json())
                .then(data => {
                    if (data.ok) { fetchDir(currentPath); showToast(`${action} completed`, 'success'); }
                })
                .catch(err => showToast(`${action} failed: ` + err.message, 'error'));
        }
    }

    function showChmodDialog(path) {
        const perms = prompt('Enter permissions (e.g. 755):', '755');
        if (perms) {
            const permInt = parseInt(perms, 8);
            fetch(`/api/sftp/${sessionId}/chmod?path=${encodeURIComponent(path)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ permissions: permInt }),
            })
                .then(r => r.json())
                .then(data => {
                    if (data.ok) { showToast('Permissions updated', 'success'); }
                })
                .catch(err => showToast('Chmod failed: ' + err.message, 'error'));
        }
    }

    function deletePath(path) {
        if (confirm(`Delete ${path}?`)) {
            fetch(`/api/sftp/${sessionId}/delete?path=${encodeURIComponent(path)}`, { method: 'DELETE' })
                .then(r => r.json())
                .then(data => {
                    if (data.ok) { fetchDir(currentPath); showToast('Deleted', 'success'); }
                })
                .catch(err => showToast('Delete failed: ' + err.message, 'error'));
        }
    }

    // refresh trigger
    document.body.addEventListener('refreshFileBrowser', () => fetchDir(currentPath));

    // mkdir
    const mkdirBtn = document.getElementById('btn-mkdir');
    if (mkdirBtn) {
        mkdirBtn.onclick = () => {
            const name = prompt('Directory name:');
            if (name) {
                const newPath = currentPath === '/' ? `/${name}` : `${currentPath}/${name}`;
                fetch(`/api/sftp/${sessionId}/mkdir?path=${encodeURIComponent(newPath)}`, { method: 'POST' })
                    .then(r => r.json())
                    .then(data => {
                        if (data.ok) { fetchDir(currentPath); showToast('Directory created', 'success'); }
                    })
                    .catch(err => showToast('Failed: ' + err.message, 'error'));
            }
        };
    }

    // upload via drag-drop
    container.addEventListener('dragover', (e) => { e.preventDefault(); });
    container.addEventListener('drop', (e) => {
        e.preventDefault();
        const files = e.dataTransfer.files;
        for (const file of files) {
            const formData = new FormData();
            formData.append('file', file);
            fetch(`/api/transport/${sessionId}/upload?path=${encodeURIComponent(currentPath)}`, {
                method: 'POST',
                body: formData,
            })
                .then(r => r.json())
                .then(data => {
                    if (data.ok) {
                        showToast(`Uploaded ${file.name}`, 'success');
                        fetchDir(currentPath);
                    }
                })
                .catch(err => showToast('Upload failed: ' + err.message, 'error'));
        }
    });

    // upload button
    const uploadBtn = document.getElementById('btn-upload');
    if (uploadBtn) {
        uploadBtn.onclick = () => {
            const input = document.createElement('input');
            input.type = 'file';
            input.multiple = true;
            input.onchange = () => {
                for (const file of input.files) {
                    const formData = new FormData();
                    formData.append('file', file);
                    fetch(`/api/transport/${sessionId}/upload?path=${encodeURIComponent(currentPath)}`, {
                        method: 'POST',
                        body: formData,
                    })
                        .then(r => r.json())
                        .then(data => {
                            if (data.ok) {
                                showToast(`Uploaded ${file.name}`, 'success');
                                fetchDir(currentPath);
                            }
                        })
                        .catch(err => showToast('Upload failed: ' + err.message, 'error'));
                }
            };
            input.click();
        };
    }

    // editor modal close
    const closeEditorBtn = document.getElementById('btn-editor-close');
    if (closeEditorBtn) {
        closeEditorBtn.onclick = () => {
            document.getElementById('editor-modal').classList.remove('open');
        };
    }

    // editor save
    const saveEditorBtn = document.getElementById('btn-editor-save');
    if (saveEditorBtn && window._monacoEditor) {
        saveEditorBtn.onclick = () => {
            const content = window._monacoEditor.getValue();
            const path = window._monacoEditor._filePath || '';
            fetch(`/api/sftp/${sessionId}/write?path=${encodeURIComponent(path)}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content }),
            })
                .then(r => r.json())
                .then(data => {
                    if (data.ok) { showToast('Saved', 'success'); }
                })
                .catch(err => showToast('Save failed: ' + err.message, 'error'));
        };
    }

    fetchDir(currentPath);
})();
