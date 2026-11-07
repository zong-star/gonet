/* P3 分页器纯函数与边界数据测试：node --test internal/webui/ui-pagination.test.cjs
 *
 * 只测计算与校验，不碰数据库、不碰 SNMP、不启动服务，也不依赖浏览器 DOM。
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const pager = require('./assets/ui-pagination.js');

const distinct = (n) => Array.from({ length: n }, (_, i) => i + 1);

test('paginate: 空数据是 0 页而不是 1 页', () => {
  const r = pager.paginate([], 0, 25);
  assert.strictEqual(r.totalItems, 0);
  assert.strictEqual(r.totalPages, 0);
  assert.strictEqual(r.pageIndex, 0);
  assert.strictEqual(r.from, 0);
  assert.strictEqual(r.to, 0);
  assert.deepStrictEqual(r.pageItems, []);
  assert.strictEqual(r.canPrev, false);
  assert.strictEqual(r.canNext, false);
  assert.strictEqual(r.empty, true);
});

test('paginate: null/undefined/非数组都当成空列表', () => {
  for (const bad of [null, undefined, 0, '', {}, 'abc']) {
    const r = pager.paginate(bad, 3, 25);
    assert.strictEqual(r.totalItems, 0, String(bad));
    assert.strictEqual(r.totalPages, 0, String(bad));
    assert.strictEqual(r.pageIndex, 0, String(bad));
  }
});

test('paginate: 边界条数 1/24/25/26/50/51/1000 的页数与切页', () => {
  const expected = [
    [1, 1], [24, 1], [25, 1], [26, 2], [50, 2], [51, 3], [1000, 40],
  ];
  for (const [count, pages] of expected) {
    const items = distinct(count);
    const r = pager.paginate(items, 0, 25);
    assert.strictEqual(r.totalPages, pages, 'count=' + count);
    assert.strictEqual(r.totalItems, count);
    assert.strictEqual(r.from, 1, 'count=' + count);
    assert.strictEqual(r.to, Math.min(count, 25), 'count=' + count);
    assert.strictEqual(r.pageItems.length, Math.min(count, 25), 'count=' + count);
    assert.strictEqual(r.pageItems[0], 1);
    assert.strictEqual(r.canPrev, false);
    assert.strictEqual(r.canNext, pages > 1);
  }
});

test('paginate: 最后一页只含剩余条目，且 from/to 连续', () => {
  const items = distinct(51);
  const last = pager.paginate(items, 2, 25);
  assert.strictEqual(last.pageIndex, 2);
  assert.strictEqual(last.pageItems.length, 1);
  assert.strictEqual(last.pageItems[0], 51);
  assert.strictEqual(last.from, 51);
  assert.strictEqual(last.to, 51);
  assert.strictEqual(last.canNext, false);
  assert.strictEqual(last.canPrev, true);
});

test('paginate: 所有页拼起来等于原数据且顺序不变', () => {
  const items = distinct(113);
  const seen = [];
  for (let i = 0; i < pager.paginate(items, 0, 25).totalPages; i++) {
    seen.push(...pager.paginate(items, i, 25).pageItems);
  }
  assert.deepStrictEqual(seen, items);
});

test('paginate: 不修改入参，切片是新数组', () => {
  const items = Object.freeze(distinct(60));
  const r = pager.paginate(items, 1, 25);
  assert.strictEqual(items.length, 60);
  assert.strictEqual(items[0], 1);
  assert.notStrictEqual(r.pageItems, items);
});

test('paginate: 越界页码归一到最后有效页，负页码归一到第一页', () => {
  const items = distinct(60);
  assert.strictEqual(pager.paginate(items, 99, 25).pageIndex, 2);
  assert.strictEqual(pager.paginate(items, -5, 25).pageIndex, 0);
  assert.strictEqual(pager.paginate(items, 2.9, 25).pageIndex, 2);
  assert.strictEqual(pager.paginate(items, NaN, 25).pageIndex, 0);
  assert.strictEqual(pager.paginate(items, '1', 25).pageIndex, 1);
  assert.strictEqual(pager.paginate([], 7, 25).pageIndex, 0);
});

test('paginate: 页大小支持 5/10/25，非法页大小回落到 25', () => {
  const items = distinct(100);
  assert.strictEqual(pager.paginate(items, 0, 5).totalPages, 20);
  assert.strictEqual(pager.paginate(items, 0, 10).totalPages, 10);
  assert.strictEqual(pager.paginate(items, 0, 25).totalPages, 4);
  for (const bad of [0, -1, NaN, Infinity, null, undefined, 'x']) {
    const r = pager.paginate(items, 0, bad);
    assert.strictEqual(r.pageSize, 25, String(bad));
  }
  assert.strictEqual(pager.paginate(items, 0, 2.7).pageSize, 2, '小数页大小向下取整');
  assert.strictEqual(pager.paginate(items, 0, '10').pageSize, 10, '数字字符串可用');
});

test('clampIndex: 无页数据始终返回 0', () => {
  for (const pages of [0, -3, NaN, undefined, null, 'x']) {
    assert.strictEqual(pager.clampIndex(5, pages), 0, String(pages));
  }
  assert.strictEqual(pager.clampIndex(0, 3), 0);
  assert.strictEqual(pager.clampIndex(2, 3), 2);
  assert.strictEqual(pager.clampIndex(3, 3), 2);
  assert.strictEqual(pager.clampIndex(-1, 3), 0);
});

test('parseJump: 合法页码', () => {
  assert.deepStrictEqual(pager.parseJump('1', 4), { ok: true, pageIndex: 0, page: 1 });
  assert.deepStrictEqual(pager.parseJump('4', 4), { ok: true, pageIndex: 3, page: 4 });
  assert.deepStrictEqual(pager.parseJump('03', 4), { ok: true, pageIndex: 2, page: 3 });
  assert.deepStrictEqual(pager.parseJump('  2  ', 4), { ok: true, pageIndex: 1, page: 2 });
  assert.deepStrictEqual(pager.parseJump(3, 4), { ok: true, pageIndex: 2, page: 3 });
});

test('parseJump: 空值与空白是 empty', () => {
  for (const raw of ['', '   ', null, undefined]) {
    const r = pager.parseJump(raw, 4);
    assert.strictEqual(r.ok, false, String(raw));
    assert.strictEqual(r.code, 'empty', String(raw));
    assert.strictEqual(r.message, '请输入页码');
  }
});

test('parseJump: 非十进制整数是 not_decimal', () => {
  for (const raw of ['abc', '-1', '1.0', '1e2', '一', '1 2', '0x2', '+2', '２']) {
    const r = pager.parseJump(raw, 4);
    assert.strictEqual(r.ok, false, raw);
    assert.strictEqual(r.code, 'not_decimal', raw);
    assert.strictEqual(r.message, '请输入 1–4 的整数', raw);
  }
});

test('parseJump: 0 与越界是 out_of_range', () => {
  for (const raw of ['0', '5', '999']) {
    const r = pager.parseJump(raw, 4);
    assert.strictEqual(r.ok, false, raw);
    assert.strictEqual(r.code, 'out_of_range', raw);
    assert.strictEqual(r.message, '请输入 1–4 的整数', raw);
  }
});

test('parseJump: 没有页时任何输入都不跳转', () => {
  for (const raw of ['1', '0', 'abc', '']) {
    const r = pager.parseJump(raw, 0);
    assert.strictEqual(r.ok, false, raw);
    assert.ok(r.code === 'out_of_range' || r.code === 'empty', raw + ' -> ' + r.code);
  }
  for (const raw of ['1', '0', 'abc', '999']) {
    assert.strictEqual(pager.parseJump(raw, 0).message, '暂无可跳转的页', raw);
  }
});

test('formatInfo: 有数据与无数据两种文案', () => {
  const full = pager.paginate(distinct(96), 1, 25);
  assert.strictEqual(pager.formatInfo(full), '第 2 / 4 页 · 显示 26–50，共 96 条');
  assert.strictEqual(pager.formatInfo(full, { unit: '台设备' }), '第 2 / 4 页 · 显示 26–50，共 96 台设备');
  assert.strictEqual(pager.formatInfo(pager.paginate([], 0, 25)), '第 0 / 0 页 · 0 条');
});

test('页面尺寸常量与方案一致', () => {
  assert.strictEqual(pager.DEFAULT_PAGE_SIZE, 25);
});
