// static/js/terminal.js
(function () {
    try {
        var container = document.getElementById('terminal-container');
        if (!container) return;

        var sessionId = container.getAttribute('data-session-id');
        if (!sessionId) return;

        var term = new Terminal({
            cursorBlink: true,
            fontSize: 14,
            fontFamily: "'Menlo', 'Monaco', 'Courier New', monospace",
            theme: {
                background: '#000000',
                foreground: '#cdd6f4',
                cursor: '#89b4fa',
            },
        });

        var fitAddon = new FitAddon.FitAddon();
        term.loadAddon(fitAddon);

        try {
            term.open(container);
        } catch (e) {
            container.textContent = 'Terminal init error: ' + e.message;
            return;
        }

        var protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
        var wsUrl = protocol + '//' + location.host + '/ws/terminal/' + encodeURIComponent(sessionId);
        var ws = null;
        var reconnectTimer = null;
        var reconnectDelay = 2000;
        var maxReconnectDelay = 30000;

        function connectWS() {
            if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
            try {
                ws = new WebSocket(wsUrl);
            } catch (e) {
                scheduleReconnect();
                return;
            }

            ws.onopen = function () {
                if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
                reconnectDelay = 2000;
                fitAddon.fit();
            };

            ws.onmessage = function (event) {
                try {
                    if (typeof event.data === 'string') {
                        term.write(event.data);
                    }
                } catch (e) {}
            };

            ws.onclose = function (event) {
                ws = null;
                scheduleReconnect();
            };

            ws.onerror = function () {
                if (ws) { ws.close(); ws = null; }
                scheduleReconnect();
            };

            window._terminalWS = ws;
        }

        function scheduleReconnect() {
            if (reconnectTimer) return;
            reconnectTimer = setTimeout(function () {
                reconnectTimer = null;
                connectWS();
                reconnectDelay = Math.min(reconnectDelay * 1.5, maxReconnectDelay);
            }, reconnectDelay);
        }

        term.onData(function (data) {
            try {
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send(data);
                }
            } catch (e) {}
        });

        connectWS();

        function resizeTerminal() {
            try { fitAddon.fit(); } catch (e) {}
        }

        var resizeTimeout = null;
        window.addEventListener('resize', function () {
            if (resizeTimeout) clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(resizeTerminal, 100);
        });

        var wheelAccumulator = 0;
        container.addEventListener('wheel', function (e) {
            if (e.ctrlKey || e.metaKey) {
                e.preventDefault();
                wheelAccumulator += e.deltaY;
                if (Math.abs(wheelAccumulator) >= 50) {
                    var step = wheelAccumulator > 0 ? -1 : 1;
                    wheelAccumulator = 0;
                    var currentSize = term.options.fontSize || 14;
                    var newSize = currentSize + step;
                    if (newSize >= 8 && newSize <= 48) {
                        term.options.fontSize = newSize;
                        try { fitAddon.fit(); } catch (e) {}
                    }
                }
            }
        }, { passive: false });

        var observer = null;
        try {
            observer = new ResizeObserver(function () { resizeTerminal(); });
            observer.observe(container);
        } catch (e) {}

        // expose for cleanup
        window._terminalCleanup = function () {
            if (observer) { observer.disconnect(); }
            if (reconnectTimer) { clearTimeout(reconnectTimer); }
            if (ws) { try { ws.close(); } catch (e) {} }
        };
    } catch (e) {
        var el = document.getElementById('terminal-container');
        if (el) el.textContent = 'Terminal failed: ' + e.message;
    }
})();
