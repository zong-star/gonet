/* GoNet 统一分页器（P3）。
 *
 * 纯函数负责页数计算、页码归一、当前页切片与跳转校验；create() 负责统一分页栏的
 * 渲染与事件约定，页面只提供列表状态与回调。合同见 docs/ui-contract-2026-11-01.md §5。
 *
 * 可被浏览器直接加载（window.GoNetPager），也可被 Node 原生测试 require，
 * 不依赖打包工具、不引入第三方库。render() 只更新文本与状态，不重建 DOM。
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module && module.exports) module.exports = api;
  if (root && !root.GoNetPager) root.GoNetPager = api;
})(typeof globalThis !== 'undefined' ? globalThis : null, function () {
  'use strict';

  const DEFAULT_PAGE_SIZE = 25;
  const DEFAULT_LABELS = { prev: '上一页', next: '下一页', jump: '跳转', input: '跳到页码', unit: '条' };
  let seq = 0;

  function toItems(items) { return Array.isArray(items) ? items : []; }

  function normalizePageSize(pageSize) {
    const n = Math.floor(Number(pageSize));
    return Number.isFinite(n) && n >= 1 ? n : DEFAULT_PAGE_SIZE;
  }

  // 越界页码回到最后有效页；无数据或无页时固定为 0
  function clampIndex(pageIndex, totalPages) {
    const pages = Math.floor(Number(totalPages));
    if (!Number.isFinite(pages) || pages <= 0) return 0;
    const index = Math.floor(Number(pageIndex));
    if (!Number.isFinite(index) || index < 0) return 0;
    return index > pages - 1 ? pages - 1 : index;
  }

  function paginate(items, pageIndex, pageSize) {
    const list = toItems(items);
    const size = normalizePageSize(pageSize);
    const totalItems = list.length;
    const totalPages = totalItems === 0 ? 0 : Math.ceil(totalItems / size);
    const index = clampIndex(pageIndex, totalPages);
    const start = index * size;
    const pageItems = list.slice(start, start + size);
    const from = totalItems === 0 ? 0 : start + 1;
    const to = totalItems === 0 ? 0 : start + pageItems.length;
    return {
      pageItems,
      pageIndex: index,
      pageSize: size,
      totalItems,
      totalPages,
      from,
      to,
      canPrev: index > 0,
      canNext: totalPages > 0 && index < totalPages - 1,
      empty: totalItems === 0,
    };
  }

  // 只接受十进制正整数（允许前导零）；空、0、负数、小数、科学计数法、混合文字与越界都不跳转
  function parseJump(raw, totalPages) {
    const pages = Math.floor(Number(totalPages));
    const hasPages = Number.isFinite(pages) && pages > 0;
    const text = raw === null || raw === undefined ? '' : String(raw).trim();
    const range = () => (hasPages ? '请输入 1–' + pages + ' 的整数' : '暂无可跳转的页');
    if (text === '') return { ok: false, code: 'empty', message: '请输入页码' };
    // 没有页可跳时，任何非空输入都给出同一条提示，不再区分格式
    if (!hasPages) return { ok: false, code: 'out_of_range', message: range() };
    if (!/^[0-9]+$/.test(text)) return { ok: false, code: 'not_decimal', message: range() };
    const page = Number(text);
    if (page < 1 || page > pages) return { ok: false, code: 'out_of_range', message: range() };
    return { ok: true, pageIndex: page - 1, page };
  }

  function formatInfo(result, opts) {
    const unit = (opts && opts.unit) || DEFAULT_LABELS.unit;
    if (!result || result.totalItems === 0) return '第 0 / 0 页 · 0 ' + unit;
    return '第 ' + (result.pageIndex + 1) + ' / ' + result.totalPages + ' 页 · 显示 ' + result.from + '–' + result.to + '，共 ' + result.totalItems + ' ' + unit;
  }

  function create(rootEl, options) {
    if (!rootEl || typeof rootEl.appendChild !== 'function') throw new TypeError('分页器需要一个容器元素');
    const opt = options || {};
    const labels = Object.assign({}, DEFAULT_LABELS, opt.labels);
    const onPageChange = typeof opt.onPageChange === 'function' ? opt.onPageChange : function () {};
    const doc = rootEl.ownerDocument || (typeof document !== 'undefined' ? document : null);
    if (!doc) throw new TypeError('分页器需要 DOM 环境');
    const errorId = 'go-pager-error-' + (++seq);

    let result = paginate([], 0, opt.pageSize);
    let errorText = '';

    const info = doc.createElement('p');
    info.className = 'pager-info';
    info.setAttribute('data-role', 'info');
    info.setAttribute('role', 'status');
    info.setAttribute('aria-atomic', 'true');
    const controls = doc.createElement('div');
    controls.className = 'pager-controls';
    const mkButton = (role, text) => {
      const b = doc.createElement('button');
      b.type = 'button';
      b.className = 'button secondary compact';
      b.setAttribute('data-role', role);
      b.textContent = text;
      return b;
    };
    const prevBtn = mkButton('prev', labels.prev);
    const nextBtn = mkButton('next', labels.next);
    const jumpBtn = mkButton('jump', labels.jump);
    const wrap = doc.createElement('label');
    wrap.className = 'pager-jump';
    const hidden = doc.createElement('span');
    hidden.className = 'sr-only';
    hidden.textContent = labels.input;
    const input = doc.createElement('input');
    input.type = 'text';
    input.setAttribute('inputmode', 'numeric');
    input.setAttribute('data-role', 'input');
    input.setAttribute('aria-label', labels.input);
    wrap.appendChild(hidden);
    wrap.appendChild(input);
    const error = doc.createElement('p');
    error.className = 'pager-error';
    error.id = errorId;
    error.setAttribute('data-role', 'error');
    error.setAttribute('role', 'alert');
    error.hidden = true;
    controls.appendChild(prevBtn);
    controls.appendChild(wrap);
    controls.appendChild(jumpBtn);
    controls.appendChild(nextBtn);
    rootEl.classList.add('pager');
    rootEl.appendChild(info);
    rootEl.appendChild(controls);
    rootEl.appendChild(error);

    function showError(message) {
      errorText = message || '';
      error.textContent = errorText;
      error.hidden = !errorText;
      input.setAttribute('aria-invalid', errorText ? 'true' : 'false');
      if (errorText) input.setAttribute('aria-describedby', errorId);
      else input.removeAttribute('aria-describedby');
    }

    function go(index) {
      const target = clampIndex(index, result.totalPages);
      if (target === result.pageIndex) return;
      onPageChange(target);
    }

    prevBtn.addEventListener('click', function () { go(result.pageIndex - 1); });
    nextBtn.addEventListener('click', function () { go(result.pageIndex + 1); });
    jumpBtn.addEventListener('click', function () { submitJump(); });
    input.addEventListener('input', function () { if (errorText) showError(''); });
    input.addEventListener('keydown', function (event) {
      if (event.key === 'Enter') { event.preventDefault(); submitJump(); }
    });

    function submitJump() {
      const parsed = parseJump(input.value, result.totalPages);
      if (!parsed.ok) { showError(parsed.message); return; }
      showError('');
      go(parsed.pageIndex);
    }

    function render(nextState, renderOpts) {
      if (nextState) result = nextState;
      if (!errorText) info.textContent = formatInfo(result, { unit: (renderOpts && renderOpts.unit) || opt.unit });
      prevBtn.disabled = !result.canPrev;
      nextBtn.disabled = !result.canNext;
      const noPages = result.totalPages === 0;
      jumpBtn.disabled = noPages;
      input.disabled = noPages;
      // 轮询刷新不能覆盖用户正在输入的页码
      if (doc.activeElement !== input) input.value = noPages ? '' : String(result.pageIndex + 1);
      return result;
    }

    function destroy() {
      rootEl.textContent = '';
      rootEl.classList.remove('pager');
    }

    return { render, destroy, go, element: rootEl, state: function () { return result; } };
  }

  return { paginate, clampIndex, parseJump, formatInfo, create, DEFAULT_PAGE_SIZE };
});
