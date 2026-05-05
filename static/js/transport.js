// static/js/transport.js
(function () {
    try {
        var container = document.getElementById('transport-panel');
        if (!container) return;

        var sessionId = container.getAttribute('data-session-id');
        if (!sessionId) return;

        var listEl = container.querySelector('.transport-list');
        var hintEl = container.querySelector('.transport-drop-hint');

        function formatSize(size) {
            if (!size || size <= 0) return '0 B';
            var units = ['B', 'KB', 'MB', 'GB', 'TB'];
            var idx = 0;
            var s = size;
            while (s >= 1024 && idx < units.length - 1) { s /= 1024; idx++; }
            return idx === 0 ? s + ' ' + units[idx] : s.toFixed(2) + ' ' + units[idx];
        }

        function createProgressBar(id, name, size) {
            var div = document.createElement('div');
            div.className = 'transport-item';
            div.id = id;
            div.innerHTML = '<div style="display:flex;justify-content:space-between;margin-bottom:4px;">' +
                '<span class="name">' + escapeHtml(name) + '</span><span class="speed">-</span></div>' +
                '<div class="progress-bar"><div class="fill" style="width:0%"></div></div>' +
                '<div style="display:flex;justify-content:space-between;margin-top:2px;font-size:11px;color:var(--text-muted);">' +
                '<span class="current">0 B</span><span class="total">' + formatSize(size) + '</span></div>';
            if (listEl) listEl.appendChild(div);
            if (hintEl) hintEl.style.display = 'none';
            return div;
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
                var tc = document.querySelector('.toast-container') || document.getElementById('toast-container');
                if (!tc) {
                    tc = document.createElement('div');
                    tc.className = 'toast-container';
                    document.body.appendChild(tc);
                }
                tc.appendChild(toast);
                setTimeout(function () { toast.remove(); }, 3000);
            } catch (e) {}
        }

        function uploadFile(file, remotePath) {
            var id = 'transport-' + Date.now();
            var el = createProgressBar(id, '↑ ' + file.name, file.size);

            var formData = new FormData();
            formData.append('file', file);

            var xhr = new XMLHttpRequest();
            xhr.open('POST', '/api/transport/' + encodeURIComponent(sessionId) + '/upload?path=' + encodeURIComponent(remotePath));

            var fill = el.querySelector('.fill');
            var currentEl = el.querySelector('.current');
            var speedEl = el.querySelector('.speed');
            var startTime = Date.now();
            var lastLoaded = 0;

            xhr.upload.onprogress = function (e) {
                if (e.lengthComputable) {
                    var pct = Math.min(100, (e.loaded / e.total) * 100);
                    if (fill) fill.style.width = pct + '%';
                    if (currentEl) currentEl.textContent = formatSize(e.loaded);

                    var now = Date.now();
                    var delta = now - startTime;
                    var bytesPerSec = delta > 0 ? e.loaded / (delta / 1000) : 0;
                    if (speedEl) speedEl.textContent = formatSpeed(bytesPerSec);
                    lastLoaded = e.loaded;
                }
            };

            xhr.onload = function () {
                try {
                    var resp = JSON.parse(xhr.responseText);
                    if (resp.ok) {
                        if (fill) { fill.style.width = '100%'; fill.style.background = 'var(--success)'; }
                        if (speedEl) speedEl.textContent = '✓';
                        if (el.querySelector('.name')) el.querySelector('.name').textContent += ' ✓';
                        document.body.dispatchEvent(new CustomEvent('refreshFileBrowser'));
                        showToast('Uploaded ' + file.name, 'success');
                    } else {
                        if (fill) { fill.style.background = 'var(--danger)'; fill.style.width = '100%'; }
                        if (speedEl) speedEl.textContent = '✗';
                        showToast('Upload failed: ' + (resp.message || ''), 'error');
                    }
                } catch (e) {
                    if (fill) { fill.style.background = 'var(--danger)'; fill.style.width = '100%'; }
                    if (speedEl) speedEl.textContent = '✗';
                    showToast('Upload failed', 'error');
                }
            };

            xhr.onerror = function () {
                if (fill) { fill.style.background = 'var(--danger)'; fill.style.width = '100%'; }
                if (speedEl) speedEl.textContent = '✗';
                showToast('Upload connection error', 'error');
            };

            xhr.send(formData);
        }

        function downloadFile(remotePath, filename, totalSize) {
            var id = 'transport-' + Date.now();
            var el = createProgressBar(id, '↓ ' + filename, totalSize || 0);

            var xhr = new XMLHttpRequest();
            xhr.open('GET', '/api/transport/' + encodeURIComponent(sessionId) + '/download?path=' + encodeURIComponent(remotePath));
            xhr.responseType = 'blob';

            var fill = el.querySelector('.fill');
            var currentEl = el.querySelector('.current');
            var totalEl = el.querySelector('.total');
            var speedEl = el.querySelector('.speed');
            var startTime = Date.now();

            xhr.onprogress = function (e) {
                if (e.lengthComputable) {
                    var pct = Math.min(100, (e.loaded / e.total) * 100);
                    if (fill) fill.style.width = pct + '%';
                    if (currentEl) currentEl.textContent = formatSize(e.loaded);
                    if (totalEl) totalEl.textContent = formatSize(e.total);

                    var now = Date.now();
                    var delta = now - startTime;
                    var bytesPerSec = delta > 0 ? e.loaded / (delta / 1000) : 0;
                    if (speedEl) speedEl.textContent = formatSpeed(bytesPerSec);
                }
            };

            xhr.onload = function () {
                if (xhr.status === 200 || xhr.status === 0) {
                    var blob = xhr.response;
                    var url = URL.createObjectURL(blob);
                    var a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);

                    if (fill) { fill.style.width = '100%'; fill.style.background = 'var(--success)'; }
                    if (speedEl) speedEl.textContent = '✓';
                    showToast('Downloaded ' + filename, 'success');
                } else {
                    if (fill) { fill.style.background = 'var(--danger)'; fill.style.width = '100%'; }
                    if (speedEl) speedEl.textContent = '✗';
                    showToast('Download failed', 'error');
                }
            };

            xhr.onerror = function () {
                if (fill) { fill.style.background = 'var(--danger)'; fill.style.width = '100%'; }
                if (speedEl) speedEl.textContent = '✗';
                showToast('Download connection error', 'error');
            };

            xhr.send();
        }

        window.downloadFileWithProgress = downloadFile;

        function formatSpeed(bytesPerSec) {
            if (bytesPerSec >= 1024 * 1024 * 1024) return (bytesPerSec / (1024 * 1024 * 1024)).toFixed(2) + ' GB/s';
            if (bytesPerSec >= 1024 * 1024) return (bytesPerSec / (1024 * 1024)).toFixed(2) + ' MB/s';
            if (bytesPerSec >= 1024) return (bytesPerSec / 1024).toFixed(2) + ' KB/s';
            return bytesPerSec.toFixed(2) + ' B/s';
        }

        function getRemotePath() {
            return (window._filebrowserPath) || '/';
        }

        // drag-drop to transport panel
        container.addEventListener('dragover', function (e) {
            e.preventDefault();
            e.stopPropagation();
            container.classList.add('drop-active');
        });

        container.addEventListener('dragleave', function (e) {
            e.preventDefault();
            e.stopPropagation();
            container.classList.remove('drop-active');
        });

        container.addEventListener('drop', function (e) {
            e.preventDefault();
            e.stopPropagation();
            container.classList.remove('drop-active');

            var files = e.dataTransfer.files;
            if (!files || files.length === 0) return;

            var path = getRemotePath();
            Array.from(files).forEach(function (file) {
                uploadFile(file, path);
            });
        });

        // upload button
        var uploadBtn = document.getElementById('btn-transport-upload');
        if (uploadBtn) {
            uploadBtn.onclick = function () {
                var input = document.createElement('input');
                input.type = 'file';
                input.multiple = true;
                input.onchange = function () {
                    if (!input.files || input.files.length === 0) return;
                    var path = getRemotePath();
                    Array.from(input.files).forEach(function (file) {
                        uploadFile(file, path);
                    });
                };
                input.click();
            };
        }

        // WebSocket-based batch transport (for backward compat / advanced use)
        window.startTransport = function (type, src, dst, coNum, speedLimit) {
            if (!type || !src || !dst) {
                console.error('Missing transport parameters');
                return null;
            }

            type = type.toUpperCase();
            coNum = coNum || 4;
            speedLimit = speedLimit || 0;

            var id = 'transport-ws-' + Date.now();
            var el = createProgressBar(id, type + ': ' + (src.split('/').pop() || src), 0);

            var protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            var wsUrl = protocol + '//' + location.host + '/ws/transport/' + encodeURIComponent(sessionId);
            var ws;

            try {
                ws = new WebSocket(wsUrl);
            } catch (e) {
                var fillEl = el.querySelector('.fill');
                if (fillEl) { fillEl.style.background = 'var(--danger)'; fillEl.style.width = '100%'; }
                var nameEl = el.querySelector('.name');
                if (nameEl) nameEl.textContent = 'WebSocket error: ' + e.message;
                return null;
            }

            var totalSize = 0;

            ws.onopen = function () {
                try {
                    ws.send(JSON.stringify({
                        action: 'start',
                        type: type,
                        src: src,
                        dst: dst,
                        co_num: coNum,
                        speed_limit: speedLimit,
                    }));
                } catch (e) {}
            };

            ws.onmessage = function (event) {
                try {
                    var msg = JSON.parse(event.data);
                    var fill = el.querySelector('.fill');
                    var nameEl = el.querySelector('.name');
                    var speedEl = el.querySelector('.speed');
                    var currentEl = el.querySelector('.current');
                    var totalEl = el.querySelector('.total');

                    switch (msg.type) {
                        case 'range':
                            totalSize = msg.data || 0;
                            if (totalEl) totalEl.textContent = formatSize(totalSize);
                            break;
                        case 'progress':
                            var pct = totalSize > 0 ? Math.min(100, (msg.data / totalSize) * 100) : 0;
                            if (fill) fill.style.width = pct + '%';
                            if (currentEl) currentEl.textContent = formatSize(msg.data);
                            break;
                        case 'speed':
                            if (speedEl) speedEl.textContent = msg.data;
                            break;
                        case 'done':
                            if (fill) { fill.style.width = '100%'; fill.style.background = 'var(--success)'; }
                            if (nameEl) nameEl.textContent += ' ✓';
                            document.body.dispatchEvent(new CustomEvent('refreshFileBrowser'));
                            try { ws.close(); } catch (e) {}
                            break;
                        case 'error':
                            if (fill) { fill.style.background = 'var(--danger)'; fill.style.width = '100%'; }
                            if (nameEl) nameEl.textContent += ' ❌ ' + (msg.data || '');
                            try { ws.close(); } catch (e) {}
                            break;
                        case 'cancelled':
                            if (fill) { fill.style.background = 'var(--warning)'; }
                            if (nameEl) nameEl.textContent += ' ⏸ Cancelled';
                            try { ws.close(); } catch (e) {}
                            break;
                    }
                } catch (e) {}
            };

            ws.onerror = function () {
                var fill = el.querySelector('.fill');
                if (fill) { fill.style.background = 'var(--danger)'; fill.style.width = '100%'; }
                var nameEl = el.querySelector('.name');
                if (nameEl) nameEl.textContent += ' ❌ Connection error';
            };

            ws.onclose = function () {};

            return ws;
        };
    } catch (e) {
        console.error('Transport init error:', e);
    }
})();
