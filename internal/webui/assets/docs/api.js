'use strict';

for (const example of document.querySelectorAll('pre[data-copy]')) {
  const toolbar = document.createElement('div');
  toolbar.className = 'code-toolbar';
  const button = toolbar.appendChild(document.createElement('button'));
  button.className = 'copy';
  button.type = 'button';
  button.textContent = '复制命令';
  button.setAttribute('aria-live', 'polite');
  example.before(toolbar);
  button.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(example.textContent);
      button.textContent = '已复制';
    } catch {
      const range = document.createRange();
      range.selectNodeContents(example);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      button.textContent = document.execCommand('copy') ? '已复制' : '已选中，请手动复制';
    }
  });
}
