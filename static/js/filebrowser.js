// static/js/filebrowser.js
(function () {
    try {
        var container = document.getElementById('filebrowser');
        if (!container) return;

        var sessionId = container.getAttribute('data-session-id');
        if (!sessionId) { container.textContent = 'No session ID'; return; }

        var currentPath = '/';
        var loading = false;

        function apiUrl(path) {
            return '/api/sftp/' + encodeURIComponent(sessionId) + '/list?path=' + encodeURIComponent(path || '/');
        }

        function fetchDir(path) {
            if (loading) return;
            loading = true;
            currentPath = path;

            showLoading(true);

            fetch(apiUrl(path))
                .then(function (r) {
                    if (!r.ok) throw new Error('HTTP ' + r.status);
                    return r.json();
                })
                .then(function (data) {
                    if (data.entries !== undefined) {
                        renderTable(data.current_path || path, data.entries);
                    } else if (data.message) {
                        showToast(data.message, 'error');
                    } else {
                        showToast('Error listing directory', 'error');
                    }
                })
                .catch(function (err) {
                    showToast('Failed to list directory: ' + err.message, 'error');
                    var tbody = container.querySelector('tbody');
                    if (tbody) tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:20px;color:var(--danger);">Failed to load</td></tr>';
                })
                .finally(function () {
                    loading = false;
                    showLoading(false);
                });
        }

        function showLoading(on) {
            var tbody = container.querySelector('tbody');
            if (!tbody) return;
            if (on) {
                tbody.style.opacity = '0.5';
                tbody.style.pointerEvents = 'none';
            } else {
                tbody.style.opacity = '1';
                tbody.style.pointerEvents = '';
            }
        }

        function formatSize(size) {
            if (!size || size <= 0) return '-';
            var units = ['B', 'KB', 'MB', 'GB', 'TB'];
            var unitIdx = 0;
            var s = size;
            while (s >= 1024 && unitIdx < units.length - 1) { s /= 1024; unitIdx++; }
            return unitIdx === 0 ? s + ' ' + units[unitIdx] : s.toFixed(2) + ' ' + units[unitIdx];
        }

        function renderTable(path, entries) {
            var tbody = container.querySelector('tbody');
            if (!tbody) return;
            tbody.innerHTML = '';

            if (path !== '/' && path !== '') {
                var parentPath = path.substring(0, path.lastIndexOf('/')) || '/';
                var tr = document.createElement('tr');
                tr.innerHTML = '<td class="name" style="color:var(--primary);cursor:pointer;">📂 ..</td><td>-</td><td>-</td><td>-</td>';
                tr.onclick = function () { fetchDir(parentPath); };
                tbody.appendChild(tr);
            }

            if (!entries || entries.length === 0) {
                var emptyTr = document.createElement('tr');
                emptyTr.innerHTML = '<td colspan="4" style="text-align:center;padding:20px;color:var(--text-muted);">Empty directory</td>';
                tbody.appendChild(emptyTr);
                return;
            }

            entries.sort(function (a, b) {
                if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
                return a.name.localeCompare(b.name);
            });

            entries.forEach(function (entry) {
                var tr = document.createElement('tr');
                tr.className = 'file-row';
                tr.dataset.path = entry.path || '';
                tr.dataset.type = entry.type || '';

                var icon = entry.type === 'dir' ? '📁' : '📄';
                var nameEscaped = escapeHtml(entry.name || '');
                tr.innerHTML = '<td class="name"><span class="type-' + (entry.type || 'file') + '">' + icon + ' ' + nameEscaped + '</span></td>' +
                    '<td>' + formatSize(entry.size) + '</td>' +
                    '<td style="font-family:monospace;font-size:11px;">' + escapeHtml(entry.permissions || '-') + '</td>' +
                    '<td>' + escapeHtml(entry.mtime_display || '-') + '</td>';

                tr.onclick = function (e) {
                    if (entry.type === 'dir') {
                        fetchDir(entry.path);
                    }
                };

                tr.oncontextmenu = function (e) {
                    e.preventDefault();
                    showContextMenu(e.clientX, e.clientY, entry);
                };

                tr.ondblclick = function (e) {
                    if (entry.type === 'file') {
                        openFileEditor(entry.path, entry.name);
                    }
                };

                tbody.appendChild(tr);
            });
        }

        function showContextMenu(x, y, entry) {
            var old = document.getElementById('file-context-menu');
            if (old) old.remove();

            var menu = document.createElement('div');
            menu.id = 'file-context-menu';
            menu.style.cssText = 'position:fixed;background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:4px;z-index:200;min-width:160px;box-shadow:0 4px 12px rgba(0,0,0,0.4);';

            var items = [];
            if (entry.type === 'dir') {
                items.push({ label: '📂 Open', action: function () { fetchDir(entry.path); } });
            } else {
                items.push({ label: '✏️ Edit', action: function () { openFileEditor(entry.path, entry.name); } });
                items.push({ label: '⬇️ Download', action: function () { downloadFile(entry.path); } });
            }
            items.push({ label: '📋 Copy', action: function () { showCopyMoveDialog('copy', entry.path); } });
            items.push({ label: '📌 Move', action: function () { showCopyMoveDialog('move', entry.path); } });
            items.push({ label: '✏️ Rename', action: function () { showRenameDialog(entry.path); } });
            items.push({ label: '🔒 Permissions', action: function () { showChmodDialog(entry.path); } });
            items.push({ label: '🗑️ Delete', action: function () { deletePath(entry.path); } });

            menu.innerHTML = items.map(function (item) {
                return '<div class="context-item" style="padding:6px 12px;cursor:pointer;font-size:13px;border-radius:4px;" ' +
                    'onmouseover="this.style.background=\'var(--bg)\'" ' +
                    'onmouseout="this.style.background=\'none\'">' + item.label + '</div>';
            }).join('');

            menu.querySelectorAll('.context-item').forEach(function (el, i) {
                el.onclick = function (e) { e.stopPropagation(); items[i].action(); menu.remove(); };
            });

            document.body.appendChild(menu);

            var rect = menu.getBoundingClientRect();
            menu.style.left = Math.min(x, window.innerWidth - rect.width - 8) + 'px';
            menu.style.top = Math.min(y, window.innerHeight - rect.height - 8) + 'px';

            setTimeout(function () {
                function hideMenu(e) { menu.remove(); document.removeEventListener('click', hideMenu); }
                document.addEventListener('click', hideMenu);
            }, 10);
        }

        function escapeHtml(str) {
            var div = document.createElement('div');
            div.textContent = str || '';
            return div.innerHTML;
        }

        function showToast(msg, type) {
            try {
                var toast = document.createElement('div');
                toast.className = 'toast toast-' + (type || 'success');
                toast.textContent = msg;
                var container = document.querySelector('.toast-container') || document.getElementById('toast-container');
                if (!container) {
                    container = document.createElement('div');
                    container.className = 'toast-container';
                    document.body.appendChild(container);
                }
                container.appendChild(toast);
                setTimeout(function () { toast.remove(); }, 3000);
            } catch (e) {}
        }

        function downloadFile(path) {
            window.open('/api/transport/' + encodeURIComponent(sessionId) + '/download?path=' + encodeURIComponent(path), '_blank');
        }

        function openFileEditor(path, name) {
            var modal = document.getElementById('editor-modal');
            var editorTitle = document.getElementById('editor-title');
            var editorContainer = document.getElementById('editor-container');
            if (!modal || !editorContainer) return;

            editorTitle.textContent = name || 'Editor';
            modal.classList.add('open');

            fetch('/api/sftp/' + encodeURIComponent(sessionId) + '/read?path=' + encodeURIComponent(path))
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    var content = data.content || '';
                    if (window._monacoEditor) {
                        window._monacoEditor.setValue(content);
                        window._monacoEditor._filePath = path;
                    }
                })
                .catch(function (err) {
                    showToast('Failed to read: ' + err.message, 'error');
                });
        }

        function showRenameDialog(path) {
            var name = path.split('/').pop() || '';
            var newName = prompt('Enter new name:', name);
            if (!newName || newName === name) return;
            var newPath = path.substring(0, path.lastIndexOf('/') + 1) + newName;

            fetch('/api/sftp/' + encodeURIComponent(sessionId) + '/rename', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ old_path: path, new_name: newPath }),
            })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (data.ok) { fetchDir(currentPath); showToast('Renamed', 'success'); }
                    else { showToast(data.message || 'Rename failed', 'error'); }
                })
                .catch(function (err) { showToast('Rename failed: ' + err.message, 'error'); });
        }

        function showCopyMoveDialog(action, src) {
            var dst = prompt('Enter destination path for ' + action + ':');
            if (!dst) return;
            var endpoint = action === 'copy' ? 'copy' : 'move';

            fetch('/api/sftp/' + encodeURIComponent(sessionId) + '/' + endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ src: src, dst: dst }),
            })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (data.ok) { fetchDir(currentPath); showToast(action + ' completed', 'success'); }
                    else { showToast(data.message || action + ' failed', 'error'); }
                })
                .catch(function (err) { showToast(action + ' failed: ' + err.message, 'error'); });
        }

        function showChmodDialog(path) {
            var perms = prompt('Enter permissions (e.g. 755):', '755');
            if (!perms) return;
            var permInt = parseInt(perms, 8);
            if (isNaN(permInt)) { showToast('Invalid permissions', 'error'); return; }

            fetch('/api/sftp/' + encodeURIComponent(sessionId) + '/chmod?path=' + encodeURIComponent(path), {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ permissions: permInt }),
            })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (data.ok) { showToast('Permissions updated', 'success'); fetchDir(currentPath); }
                    else { showToast(data.message || 'Chmod failed', 'error'); }
                })
                .catch(function (err) { showToast('Chmod failed: ' + err.message, 'error'); });
        }

        function deletePath(path) {
            if (!confirm('Delete ' + path + '?')) return;

            fetch('/api/sftp/' + encodeURIComponent(sessionId) + '/delete?path=' + encodeURIComponent(path), { method: 'DELETE' })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (data.ok) { fetchDir(currentPath); showToast('Deleted', 'success'); }
                    else { showToast(data.message || 'Delete failed', 'error'); }
                })
                .catch(function (err) { showToast('Delete failed: ' + err.message, 'error'); });
        }

        // refresh trigger from other components
        document.body.addEventListener('refreshFileBrowser', function () { fetchDir(currentPath); });

        // mkdir button
        var mkdirBtn = document.getElementById('btn-mkdir');
        if (mkdirBtn) {
            mkdirBtn.onclick = function () {
                var name = prompt('Directory name:');
                if (!name) return;
                var newPath = currentPath === '/' ? '/' + name : currentPath + '/' + name;

                fetch('/api/sftp/' + encodeURIComponent(sessionId) + '/mkdir?path=' + encodeURIComponent(newPath), { method: 'POST' })
                    .then(function (r) { return r.json(); })
                    .then(function (data) {
                        if (data.ok) { fetchDir(currentPath); showToast('Directory created', 'success'); }
                        else { showToast(data.message || 'Failed', 'error'); }
                    })
                    .catch(function (err) { showToast('Failed: ' + err.message, 'error'); });
            };
        }

        // drag-drop upload
        container.addEventListener('dragover', function (e) { e.preventDefault(); });
        container.addEventListener('drop', function (e) {
            e.preventDefault();
            var files = e.dataTransfer.files;
            if (!files || files.length === 0) return;

            Array.from(files).forEach(function (file) {
                var formData = new FormData();
                formData.append('file', file);
                fetch('/api/transport/' + encodeURIComponent(sessionId) + '/upload?path=' + encodeURIComponent(currentPath), {
                    method: 'POST',
                    body: formData,
                })
                    .then(function (r) { return r.json(); })
                    .then(function (data) {
                        if (data.ok) { showToast('Uploaded ' + file.name, 'success'); fetchDir(currentPath); }
                        else { showToast('Upload failed: ' + (data.message || ''), 'error'); }
                    })
                    .catch(function (err) { showToast('Upload failed: ' + err.message, 'error'); });
            });
        });

        // upload button
        var uploadBtn = document.getElementById('btn-upload');
        if (uploadBtn) {
            uploadBtn.onclick = function () {
                var input = document.createElement('input');
                input.type = 'file';
                input.multiple = true;
                input.onchange = function () {
                    if (!input.files || input.files.length === 0) return;
                    Array.from(input.files).forEach(function (file) {
                        var formData = new FormData();
                        formData.append('file', file);
                        fetch('/api/transport/' + encodeURIComponent(sessionId) + '/upload?path=' + encodeURIComponent(currentPath), {
                            method: 'POST',
                            body: formData,
                        })
                            .then(function (r) { return r.json(); })
                            .then(function (data) {
                                if (data.ok) { showToast('Uploaded ' + file.name, 'success'); fetchDir(currentPath); }
                                else { showToast('Upload failed: ' + (data.message || ''), 'error'); }
                            })
                            .catch(function (err) { showToast('Upload failed: ' + err.message, 'error'); });
                    });
                };
                input.click();
            };
        }

        // editor close
        var closeEditorBtn = document.getElementById('btn-editor-close');
        if (closeEditorBtn) {
            closeEditorBtn.onclick = function () {
                var modal = document.getElementById('editor-modal');
                if (modal) modal.classList.remove('open');
            };
        }

        // editor save
        var saveEditorBtn = document.getElementById('btn-editor-save');
        if (saveEditorBtn) {
            saveEditorBtn.onclick = function () {
                if (!window._monacoEditor) return;
                var content = window._monacoEditor.getValue();
                var path = window._monacoEditor._filePath || '';
                if (!path) return;

                fetch('/api/sftp/' + encodeURIComponent(sessionId) + '/write?path=' + encodeURIComponent(path), {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ content: content }),
                })
                    .then(function (r) { return r.json(); })
                    .then(function (data) {
                        if (data.ok) { showToast('Saved', 'success'); }
                        else { showToast(data.message || 'Save failed', 'error'); }
                    })
                    .catch(function (err) { showToast('Save failed: ' + err.message, 'error'); });
            };
        }

        // error display in container
        window._filebrowserError = function (msg) {
            var tbody = container.querySelector('tbody');
            if (tbody) tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;padding:20px;color:var(--danger);">' + escapeHtml(msg) + '</td></tr>';
        };

        fetchDir(currentPath);
    } catch (e) {
        var el = document.getElementById('filebrowser');
        if (el) el.textContent = 'File browser error: ' + e.message;
    }
})();
