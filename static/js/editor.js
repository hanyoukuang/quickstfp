// static/js/editor.js
// Monaco Editor 嵌入 - 通过 CDN 加载
(function () {
    const container = document.getElementById('editor-container');
    if (!container) return;

    if (typeof monaco === 'undefined') {
        container.textContent = 'Loading editor...';
        return;
    }

    const editor = monaco.editor.create(container, {
        value: '',
        language: 'plaintext',
        theme: 'vs-dark',
        automaticLayout: true,
        minimap: { enabled: false },
        fontSize: 13,
        lineNumbers: 'on',
        scrollBeyondLastLine: false,
    });

    editor._filePath = '';

    window._monacoEditor = editor;
})();
