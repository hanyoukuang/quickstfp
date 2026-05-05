// static/js/transport.js
(function () {
    const container = document.getElementById('transport-panel');
    if (!container) return;

    const sessionId = container.dataset.sessionId;
    let activeTransport = null;

    function createProgressBar(id) {
        const div = document.createElement('div');
        div.className = 'transport-item';
        div.id = id;
        div.innerHTML = `
            <div style="display:flex;justify-content:space-between;margin-bottom:4px;">
                <span class="name">-</span>
                <span class="speed">-</span>
            </div>
            <div class="progress-bar"><div class="fill" style="width:0%"></div></div>
            <div style="display:flex;justify-content:space-between;margin-top:2px;font-size:11px;color:var(--text-muted);">
                <span class="current">0 B</span>
                <span class="total">0 B</span>
            </div>
        `;
        return div;
    }

    function formatSize(size) {
        if (!size || size <= 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let idx = 0;
        let s = size;
        while (s >= 1024 && idx < units.length - 1) { s /= 1024; idx++; }
        return idx === 0 ? `${s} ${units[idx]}` : `${s.toFixed(2)} ${units[idx]}`;
    }

    window.startTransport = function (type, src, dst, coNum, speedLimit) {
        const id = 'transport-' + Date.now();
        const el = createProgressBar(id);
        container.appendChild(el);

        const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${location.host}/ws/transport/${sessionId}`;
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            ws.send(JSON.stringify({
                action: 'start',
                type: type,
                src: src,
                dst: dst,
                co_num: coNum || 4,
                speed_limit: speedLimit || 0,
            }));
        };

        let totalSize = 0;
        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                const fill = el.querySelector('.fill');
                const nameEl = el.querySelector('.name');
                const speedEl = el.querySelector('.speed');
                const currentEl = el.querySelector('.current');
                const totalEl = el.querySelector('.total');

                if (msg.type === 'range') {
                    totalSize = msg.data || 0;
                    totalEl.textContent = formatSize(totalSize);
                    nameEl.textContent = `${type}: ${src.split('/').pop()}`;
                } else if (msg.type === 'progress') {
                    const pct = totalSize > 0 ? Math.min(100, (msg.data / totalSize) * 100) : 0;
                    fill.style.width = `${pct}%`;
                    currentEl.textContent = formatSize(msg.data);
                } else if (msg.type === 'speed') {
                    speedEl.textContent = msg.data;
                } else if (msg.type === 'done') {
                    fill.style.width = '100%';
                    fill.style.background = 'var(--success)';
                    nameEl.textContent += ' ✓';
                    ws.close();
                } else if (msg.type === 'error') {
                    fill.style.background = 'var(--danger)';
                    nameEl.textContent += ` ❌ ${msg.data}`;
                    ws.close();
                } else if (msg.type === 'cancelled') {
                    fill.style.background = 'var(--warning)';
                    nameEl.textContent += ' ⏸ Cancelled';
                    ws.close();
                }
            } catch (e) {}
        };

        ws.onerror = () => {
            const fill = el.querySelector('.fill');
            if (fill) fill.style.background = 'var(--danger)';
        };

        return ws;
    };
})();
