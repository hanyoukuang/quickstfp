// static/js/terminal.js
(function () {
    const container = document.getElementById('terminal-container');
    if (!container) return;

    const sessionId = container.dataset.sessionId;
    if (!sessionId) return;

    const term = new Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontFamily: "'Menlo', 'Monaco', 'Courier New', monospace",
        theme: {
            background: '#000000',
            foreground: '#cdd6f4',
            cursor: '#89b4fa',
        },
    });

    const fitAddon = new FitAddon.FitAddon();
    term.loadAddon(fitAddon);
    term.open(container);

    const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${location.host}/ws/terminal/${sessionId}`;
    let ws = null;
    let reconnectTimer = null;

    function connectWS() {
        if (ws && ws.readyState === WebSocket.OPEN) return;
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            fitAddon.fit();
            if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
        };

        ws.onmessage = (event) => {
            if (typeof event.data === 'string') {
                term.write(event.data);
            }
        };

        ws.onclose = (event) => {
            if (!reconnectTimer) {
                reconnectTimer = setTimeout(connectWS, 3000);
            }
        };

        ws.onerror = () => {
            ws.close();
        };
    }

    term.onData((data) => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(data);
        }
    });

    connectWS();

    function resizeTerminal() {
        fitAddon.fit();
    }

    window.addEventListener('resize', resizeTerminal);

    let wheelAccumulator = 0;
    container.addEventListener('wheel', (e) => {
        if (e.ctrlKey || e.metaKey) {
            e.preventDefault();
            wheelAccumulator += e.deltaY;
            if (Math.abs(wheelAccumulator) >= 50) {
                let step = wheelAccumulator > 0 ? -1 : 1;
                wheelAccumulator = 0;
                let currentSize = term.options.fontSize;
                let newSize = currentSize + step;
                if (newSize >= 8 && newSize <= 48) {
                    term.options.fontSize = newSize;
                    fitAddon.fit();
                }
            }
        }
    }, { passive: false });

    // initial resize
    const observer = new ResizeObserver(() => { resizeTerminal(); });
    observer.observe(container);
})();
