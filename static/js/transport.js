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
            div.innerHTML = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">' +
                '<span class="name">' + escapeHtml(name) + '</span>' +
                '<div style="display:flex;align-items:center;gap:4px;">' +
                    '<span class="speed">-</span>' +
                    '<button class="ti-btn ti-btn-pause" title="Pause" style="display:none;">⏸</button>' +
                    '<button class="ti-btn ti-btn-cancel" title="Cancel" style="display:none;">✕</button>' +
                '</div>' +
            '</div>' +
            '<div class="progress-bar"><div class="fill" style="width:0%"></div></div>' +
            '<div style="display:flex;justify-content:space-between;margin-top:2px;font-size:11px;color:var(--text-muted);">' +
                '<span class="current">0 B</span><span class="total">' + formatSize(size) + '</span></div>';
            if (listEl) listEl.appendChild(div);
            if (hintEl) hintEl.style.display = 'none';
            return div;
        }

        function showTransportControls(el) {
            var pauseBtn = el.querySelector('.ti-btn-pause');
            var cancelBtn = el.querySelector('.ti-btn-cancel');
            if (pauseBtn) pauseBtn.style.display = '';
            if (cancelBtn) cancelBtn.style.display = '';
        }

        function hideTransportControls(el) {
            var pauseBtn = el.querySelector('.ti-btn-pause');
            var cancelBtn = el.querySelector('.ti-btn-cancel');
            if (pauseBtn) pauseBtn.style.display = 'none';
            if (cancelBtn) cancelBtn.style.display = 'none';
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

        function formatSpeed(bytesPerSec) {
            if (bytesPerSec >= 1024 * 1024 * 1024) return (bytesPerSec / (1024 * 1024 * 1024)).toFixed(2) + ' GB/s';
            if (bytesPerSec >= 1024 * 1024) return (bytesPerSec / (1024 * 1024)).toFixed(2) + ' MB/s';
            if (bytesPerSec >= 1024) return (bytesPerSec / 1024).toFixed(2) + ' KB/s';
            return bytesPerSec.toFixed(2) + ' B/s';
        }

        function getRemotePath() {
            return (window._filebrowserPath) || '/';
        }

        // ─── Upload (XHR) ────────────────────────────────────────

        function uploadFile(file, remotePath) {
            var id = 'transport-' + Date.now();
            var el = createProgressBar(id, '↑ ' + file.name, file.size);
            showTransportControls(el);

            var fill = el.querySelector('.fill');
            var currentEl = el.querySelector('.current');
            var speedEl = el.querySelector('.speed');
            var nameEl = el.querySelector('.name');
            var pauseBtn = el.querySelector('.ti-btn-pause');
            var cancelBtn = el.querySelector('.ti-btn-cancel');
            var startTime = Date.now();
            var lastLoaded = 0;

            var formData = new FormData();
            formData.append('file', file);

            var xhr = new XMLHttpRequest();
            xhr.open('POST', '/api/transport/' + encodeURIComponent(sessionId) + '/upload?path=' + encodeURIComponent(remotePath));

            var cancelled = false;
            var paused = false;

            function doCancel() {
                cancelled = true;
                xhr.abort();
                if (fill) { fill.style.background = 'var(--warning)'; }
                if (nameEl) nameEl.textContent = nameEl.textContent.replace(' ⏸', '') + ' ✕';
                hideTransportControls(el);
            }

            function doPause() {
                paused = true;
                xhr.abort();
                if (pauseBtn) pauseBtn.textContent = '▶';
                if (nameEl) nameEl.textContent = nameEl.textContent.replace(' ⏸', '') + ' ⏸';
                if (speedEl) speedEl.textContent = '-';
            }

            if (cancelBtn) cancelBtn.onclick = doCancel;
            if (pauseBtn) pauseBtn.onclick = doPause;

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
                if (paused || cancelled) return;
                hideTransportControls(el);
                try {
                    var resp = JSON.parse(xhr.responseText);
                    if (resp.ok) {
                        if (fill) { fill.style.width = '100%'; fill.style.background = 'var(--success)'; }
                        if (speedEl) speedEl.textContent = '✓';
                        if (nameEl) nameEl.textContent = nameEl.textContent.replace(' ⏸', '') + ' ✓';
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
                if (paused || cancelled) return;
                hideTransportControls(el);
                if (fill) { fill.style.background = 'var(--danger)'; fill.style.width = '100%'; }
                if (speedEl) speedEl.textContent = '✗';
                showToast('Upload connection error', 'error');
            };

            xhr.send(formData);
        }

        // ─── Download (fetch + ReadableStream, resumable) ─────────

        function downloadFile(remotePath, filename, totalSize) {
            var id = 'transport-' + Date.now();
            var el = createProgressBar(id, '↓ ' + filename, totalSize || 0);
            showTransportControls(el);

            var fill = el.querySelector('.fill');
            var currentEl = el.querySelector('.current');
            var totalEl = el.querySelector('.total');
            var speedEl = el.querySelector('.speed');
            var nameEl = el.querySelector('.name');
            var pauseBtn = el.querySelector('.ti-btn-pause');
            var cancelBtn = el.querySelector('.ti-btn-cancel');

            var state = {
                controller: null,
                cancelled: false,
                paused: false,
                receivedBytes: 0,
                chunks: [],
                fetchesStarted: 0,
                fetchStartTime: Date.now(),
                bytesAtFetchStart: 0,
                url: '/api/transport/' + encodeURIComponent(sessionId) + '/download?path=' + encodeURIComponent(remotePath),
            };

            function updateProgress() {
                var pct = totalSize > 0 ? Math.min(100, (state.receivedBytes / totalSize) * 100) : 0;
                if (fill) fill.style.width = pct + '%';
                if (currentEl) currentEl.textContent = formatSize(state.receivedBytes);

                var now = Date.now();
                var fetchDelta = now - state.fetchStartTime;
                var fetchBytes = state.receivedBytes - state.bytesAtFetchStart;
                var speed = fetchDelta > 0 ? fetchBytes / (fetchDelta / 1000) : 0;
                if (speedEl) speedEl.textContent = formatSpeed(speed);
            }

            async function doFetch(fromByte) {
                state.fetchesStarted++;
                state.controller = new AbortController();
                state.fetchStartTime = Date.now();
                state.bytesAtFetchStart = state.receivedBytes;

                var headers = {};
                if (fromByte > 0) {
                    headers['Range'] = 'bytes=' + fromByte + '-';
                }

                try {
                    var response = await fetch(state.url, {
                        headers: headers,
                        signal: state.controller.signal,
                    });

                    if (!response.ok && response.status !== 206) {
                        throw new Error('HTTP ' + response.status);
                    }

                    var contentRange = response.headers.get('Content-Range');
                    if (contentRange) {
                        var match = contentRange.match(/bytes \d+-\d+\/(\d+)/);
                        if (match) {
                            totalSize = parseInt(match[1]);
                            if (totalEl) totalEl.textContent = formatSize(totalSize);
                        }
                    }

                    if (totalSize === 0 || !totalSize) {
                        var cl = response.headers.get('Content-Length');
                        if (cl) {
                            totalSize = state.receivedBytes + parseInt(cl);
                            if (totalEl) totalEl.textContent = formatSize(totalSize);
                        }
                    }

                    if (!response.body) throw new Error('No response body');

                    var reader = response.body.getReader();

                    while (true) {
                        if (state.cancelled) {
                            reader.cancel();
                            return;
                        }

                        var result = await reader.read();
                        if (result.done) break;

                        state.chunks.push(result.value);
                        state.receivedBytes += result.value.length;
                        updateProgress();
                    }

                    finishDownload();

                } catch (e) {
                    if (e.name === 'AbortError' || state.cancelled) return;
                    if (fill) { fill.style.background = 'var(--danger)'; fill.style.width = '100%'; }
                    if (speedEl) speedEl.textContent = '✗';
                    hideTransportControls(el);
                    showToast('Download failed', 'error');
                }
            }

            function finishDownload() {
                if (state.cancelled) return;
                var blob = new Blob(state.chunks);
                var downloadUrl = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = downloadUrl;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                setTimeout(function () { URL.revokeObjectURL(downloadUrl); }, 1000);

                if (fill) { fill.style.width = '100%'; fill.style.background = 'var(--success)'; }
                if (speedEl) speedEl.textContent = '✓';
                if (nameEl) nameEl.textContent = nameEl.textContent.replace(' ⏸', '') + ' ✓';
                hideTransportControls(el);
                showToast('Downloaded ' + filename, 'success');
            }

            function doPause() {
                if (state.paused) {
                    state.paused = false;
                    if (pauseBtn) pauseBtn.textContent = '⏸';
                    if (nameEl) nameEl.textContent = nameEl.textContent.replace(' ⏸', '');
                    if (speedEl) speedEl.textContent = '-';
                    doFetch(state.receivedBytes);
                } else {
                    state.paused = true;
                    if (pauseBtn) pauseBtn.textContent = '▶';
                    if (nameEl) nameEl.textContent = nameEl.textContent.replace(' ⏸', '') + ' ⏸';
                    if (state.controller) state.controller.abort();
                }
            }

            function doCancel() {
                state.cancelled = true;
                if (state.controller) state.controller.abort();
                if (fill) { fill.style.background = 'var(--warning)'; }
                if (nameEl) nameEl.textContent = nameEl.textContent.replace(' ⏸', '') + ' ✕';
                if (speedEl) speedEl.textContent = '-';
                hideTransportControls(el);
            }

            if (pauseBtn) pauseBtn.onclick = doPause;
            if (cancelBtn) cancelBtn.onclick = doCancel;

            doFetch(0);
        }

        window.downloadFileWithProgress = downloadFile;

        // ─── WebSocket batch transport ────────────────────────────

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
            showTransportControls(el);

            var fill = el.querySelector('.fill');
            var nameEl = el.querySelector('.name');
            var speedEl = el.querySelector('.speed');
            var currentEl = el.querySelector('.current');
            var totalEl = el.querySelector('.total');
            var pauseBtn = el.querySelector('.ti-btn-pause');
            var cancelBtn = el.querySelector('.ti-btn-cancel');

            var protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
            var wsUrl = protocol + '//' + location.host + '/ws/transport/' + encodeURIComponent(sessionId);
            var ws;

            try {
                ws = new WebSocket(wsUrl);
            } catch (e) {
                if (fill) { fill.style.background = 'var(--danger)'; fill.style.width = '100%'; }
                if (nameEl) nameEl.textContent = 'WebSocket error: ' + e.message;
                return null;
            }

            var totalSize = 0;
            var paused = false;
            var cancelled = false;

            function doPause() {
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ action: 'pause' }));
                }
            }

            function doCancel() {
                cancelled = true;
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify({ action: 'cancel' }));
                }
            }

            if (pauseBtn) pauseBtn.onclick = doPause;
            if (cancelBtn) cancelBtn.onclick = doCancel;

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
                            if (nameEl) nameEl.textContent = nameEl.textContent.replace(' ⏸', '') + ' ✓';
                            hideTransportControls(el);
                            document.body.dispatchEvent(new CustomEvent('refreshFileBrowser'));
                            try { ws.close(); } catch (e) {}
                            break;
                        case 'error':
                            if (fill) { fill.style.background = 'var(--danger)'; fill.style.width = '100%'; }
                            if (nameEl) nameEl.textContent += ' ❌ ' + (msg.data || '');
                            hideTransportControls(el);
                            try { ws.close(); } catch (e) {}
                            break;
                        case 'cancelled':
                            if (fill) { fill.style.background = 'var(--warning)'; }
                            if (nameEl) nameEl.textContent += ' ✕';
                            hideTransportControls(el);
                            try { ws.close(); } catch (e) {}
                            break;
                        case 'paused':
                            paused = true;
                            if (pauseBtn) pauseBtn.textContent = '▶';
                            if (nameEl) nameEl.textContent = nameEl.textContent.replace(' ⏸', '') + ' ⏸';
                            break;
                        case 'resumed':
                            paused = false;
                            if (pauseBtn) pauseBtn.textContent = '⏸';
                            if (nameEl) nameEl.textContent = nameEl.textContent.replace(' ⏸', '');
                            break;
                    }
                } catch (e) {}
            };

            ws.onerror = function () {
                if (fill) { fill.style.background = 'var(--danger)'; fill.style.width = '100%'; }
                if (nameEl) nameEl.textContent += ' ❌ Connection error';
                hideTransportControls(el);
            };

            ws.onclose = function () {};

            return ws;
        };

        // ─── drag-drop handlers ───────────────────────────────────

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
    } catch (e) {
        console.error('Transport init error:', e);
    }
})();
