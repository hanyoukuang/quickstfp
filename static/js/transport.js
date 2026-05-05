// static/js/transport.js
(function () {
    try {
        var container = document.getElementById('transport-panel');
        if (!container) return;

        var sessionId = container.getAttribute('data-session-id');
        if (!sessionId) return;

        function createProgressBar(id) {
            var div = document.createElement('div');
            div.className = 'transport-item';
            div.id = id;
            div.innerHTML = '<div style="display:flex;justify-content:space-between;margin-bottom:4px;">' +
                '<span class="name">-</span><span class="speed">-</span></div>' +
                '<div class="progress-bar"><div class="fill" style="width:0%"></div></div>' +
                '<div style="display:flex;justify-content:space-between;margin-top:2px;font-size:11px;color:var(--text-muted);">' +
                '<span class="current">0 B</span><span class="total">0 B</span></div>';
            return div;
        }

        function formatSize(size) {
            if (!size || size <= 0) return '0 B';
            var units = ['B', 'KB', 'MB', 'GB', 'TB'];
            var idx = 0;
            var s = size;
            while (s >= 1024 && idx < units.length - 1) { s /= 1024; idx++; }
            return idx === 0 ? s + ' ' + units[idx] : s.toFixed(2) + ' ' + units[idx];
        }

        window.startTransport = function (type, src, dst, coNum, speedLimit) {
            if (!type || !src || !dst) {
                console.error('Missing transport parameters');
                return null;
            }

            type = type.toUpperCase();
            coNum = coNum || 4;
            speedLimit = speedLimit || 0;

            var id = 'transport-' + Date.now();
            var el = createProgressBar(id);

            var list = container.querySelector('.transport-list');
            if (list) {
                list.appendChild(el);
            } else {
                container.appendChild(el);
            }

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
                            if (nameEl) nameEl.textContent = type + ': ' + (src.split('/').pop() || src);
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
