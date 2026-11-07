const {chromium} = require('../../../.tools/node_modules/playwright');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

(async () => {
  const output = process.env.GONET_UPLINK_BROWSER_OUTPUT;
  const base = process.env.GONET_UPLINK_TEST_URL;
  const [cookieName, cookieValue] = process.env.GONET_UPLINK_TEST_COOKIE.split('=');
  fs.mkdirSync(output, {recursive: true});
  const browser = await chromium.launch({channel: 'chrome', headless: true});
  const context = await browser.newContext({ignoreHTTPSErrors: true, reducedMotion: 'reduce', viewport: {width: 1440, height: 900}});
  const report = {source: 'isolated GoNet HTTPS fixture; synthetic rendering cases are explicitly injected', checks: [], errors: []};
  try {
    await context.addCookies([{name: cookieName, value: cookieValue, url: base, httpOnly: true, secure: true}]);
    const page = await context.newPage();
    page.setDefaultTimeout(12000);
    page.on('pageerror', error => report.errors.push(error.message));
    page.on('requestfailed', request => report.errors.push(new URL(request.url()).pathname + ': ' + request.failure()?.errorText));
    await page.goto(base + '/?page=devices');
    try { await page.locator('#devicesBody button[data-device="1"]').click(); }
    catch (error) {
      const diagnostic = {url: page.url(), errors: report.errors, text: (await page.locator('body').innerText()).slice(0, 1800)};
      throw Error(error.message + '\n' + JSON.stringify(diagnostic));
    }
    await page.locator('.uplink-graph svg').waitFor();
    await page.locator('.uplink-view section').last().getByRole('heading', {name: '直接邻居', exact: true}).waitFor();
    assert.equal(await page.locator('.uplink-graph [role="button"]').count(), 2);
    assert.ok((await page.locator('.uplink-view').innerText()).includes('运行状态未知'));
    assert.ok((await page.locator('.uplink-view').innerText()).includes('全网采集有缺口'));
    await page.locator('.uplink-graph [role="button"]').first().focus();
    await page.keyboard.press('Enter');
    assert.equal(await page.locator('.uplink-edge-detail').first().getAttribute('open'), '');
    assert.equal(await page.locator('.uplink-edge-detail summary').first().evaluate(node => node === document.activeElement), true);
    await page.locator('.uplink-edge-detail').first().evaluate(node => { node.open = false; });
    const scrollToPath = () => page.evaluate(() => {
      const panel = document.getElementById('detailPanel');
      panel.scrollTop = document.querySelector('.uplink-view').offsetTop - 15;
    });
    await scrollToPath();
    await page.screenshot({path: path.join(output, 'P4-wide.png'), fullPage: true, animations: 'disabled'});
    report.checks.push('real device details entry, two-hop graph and table, keyboard edge details, network gap and unknown oper state');
    await page.setViewportSize({width: 390, height: 844});
    await page.waitForTimeout(100);
    const narrow = await page.locator('.uplink-graph svg').evaluate(svg => ({width: svg.viewBox.baseVal.width, height: svg.viewBox.baseVal.height}));
    assert.ok(narrow.height > narrow.width);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
    await scrollToPath();
    await page.screenshot({path: path.join(output, 'P4-narrow.png'), fullPage: true, animations: 'disabled'});
    report.checks.push('390px vertical graph, scrollable table and no document overflow');

    const payload = await page.evaluate(async () => (await (await fetch('/api/v1/devices/1/uplink-path?schema_version=2')).json()).data);
    const checkRendering = async data => page.evaluate(data => {
      const root = document.querySelector('.uplink-view section');
      GoNetUplink.render(root, data);
      return {text: root.textContent, images: root.querySelectorAll('img').length, svg: root.querySelectorAll('svg').length};
    }, data);
    const partial = structuredClone(payload);
    partial.path.edges[0].from.interface_description = '<img src=x onerror="window.__injected=1">';
    partial.path.edges[0].from.interface_name = 'GigabitEthernet' + '1/0/1234567890'.repeat(5);
    partial.path.edges[0].oper_status = 'down';
    partial.path.edges[0].oper_observed_at = '2026-11-05T00:00:00Z';
    partial.path.edges[0].aggregation.member_data_status = 'partial';
    const rendered = await checkRendering(partial);
    assert.equal(rendered.images, 0);
    assert.ok(rendered.text.includes('<img src=x'));
    assert.ok(rendered.text.includes('列表不完整'));
    assert.ok(rendered.text.includes('观测为 down'));
    assert.equal(await page.evaluate(() => window.__injected), undefined);
    report.checks.push('synthetic long labels, HTML literal, partial members and timestamped down observation');
    const unknown = structuredClone(payload);
    unknown.path.edges[0].aggregation.member_data_status = 'unknown';
    unknown.path.edges[0].aggregation.member_links = null;
    assert.ok((await checkRendering(unknown)).text.includes('成员未知'));
    const broken = structuredClone(payload);
    broken.path.edges[0].to.device_id = 'broken';
    const rejected = await checkRendering(broken);
    assert.equal(rejected.svg, 0);
    assert.ok(rejected.text.includes('校验失败'));
    report.checks.push('unknown member data and disconnected graph rejection');
    const v3 = await page.evaluate(async () => (await (await fetch('/api/v1/devices/1/uplink-path?schema_version=3')).json()).data);
    const member0 = v3.path.edges[0].aggregation.member_links[0];
    const half = structuredClone(v3), halfEdge = half.path.edges[0];
    halfEdge.kind = 'physical'; halfEdge.edge_id = 'physical:' + member0.link_id; halfEdge.link_id = member0.link_id;
    halfEdge.from = structuredClone(member0.from); halfEdge.to = structuredClone(member0.to);
    halfEdge.aggregation_status = halfEdge.aggregation.status = 'partial';
    halfEdge.aggregation.aggregate_id = null; halfEdge.aggregation.member_data_status = 'partial';
    halfEdge.aggregation.remote_group = null;
    halfEdge.aggregation.member_links.forEach(m => { m.membership_status = 'local_only'; });
    assert.ok((await checkRendering(half)).text.includes('聚合信息不完整'));
    const missing = structuredClone(half), missingEdge = missing.path.edges[0];
    missingEdge.aggregation_status = missingEdge.aggregation.status = 'unknown';
    missingEdge.aggregation.member_data_status = 'unknown'; missingEdge.aggregation.member_links = null;
    missingEdge.aggregation.known_member_link_count = missingEdge.aggregation.returned_member_link_count = 0;
    missingEdge.aggregation.local_group = missingEdge.aggregation.remote_group = null;
    assert.ok((await checkRendering(missing)).text.includes('聚合状态未知'));
    const conflicted = structuredClone(half);
    conflicted.path.edges[0].aggregation_status = conflicted.path.edges[0].aggregation.status = 'conflict';
    conflicted.path.edges[0].aggregation.member_links.forEach(m => { m.membership_status = 'conflict'; });
    assert.ok((await checkRendering(conflicted)).text.includes('聚合证据冲突'));
    report.checks.push('schema 3 partial, unknown and conflict remain distinct and retain physical member links');

    const emptyPath = structuredClone(payload);
    emptyPath.path_status = 'not_found';
    emptyPath.path = null;
    assert.ok((await checkRendering(emptyPath)).text.includes('当前可用的确认数据'));
    emptyPath.path_status = 'no_core_configured';
    assert.ok((await checkRendering(emptyPath)).text.includes('未配置核心设备'));
    const zero = structuredClone(payload);
    zero.source_device_id = '3';
    zero.path = {target_core_device_id: '3', hop_count: 0, nodes: [{device_id: '3', display_name: 'Core', role: 'source_core'}], edges: []};
    assert.ok((await checkRendering(zero)).text.includes('该设备已是核心'));
    report.checks.push('no-path, unconfigured-core and zero-hop rendering');
    const noSvg = await page.evaluate(data => {
      const original = document.createElementNS;
      document.createElementNS = () => { throw Error('synthetic SVG failure'); };
      try { GoNetUplink.render(document.querySelector('.uplink-view section'), data); }
      finally { document.createElementNS = original; }
      return document.querySelector('.uplink-view section').textContent;
    }, payload);
    assert.ok(noSvg.includes('图形不可用'));
    assert.ok(noSvg.includes('Bridge-Aggregation1'));
    const legacy = await page.evaluate(async () => (await (await fetch('/api/v1/devices/1/uplink-path?max_paths=1')).json()).data);
    const fallback = await page.evaluate(data => {
      const root = document.querySelector('.uplink-view section');
      GoNetUplink.renderLegacy(root, data);
      return {text: root.textContent, svg: root.querySelectorAll('svg').length};
    }, legacy);
    assert.equal(fallback.svg, 0);
    assert.ok(fallback.text.includes('接口名未知'));
    assert.ok(fallback.text.includes('旧端口文本'));
    report.checks.push('SVG failure table and verified legacy text fallback');
    await page.route(/\/uplink-path\?schema_version=[23]$/, route => route.fulfill({status: 400, contentType: 'application/json', body: JSON.stringify({error: {code: 'INVALID_ARGUMENT', message: 'synthetic older server'}})}));
    await page.locator('#closeDetail').click();
    await page.locator('#devicesBody button[data-device="1"]').click();
    await page.getByText('当前使用旧版逐跳数据，接口名未知。', {exact: true}).waitFor();
    assert.equal(await page.locator('.uplink-graph svg').count(), 0);
    report.checks.push('normal device entry retries schema-unsupported server with validated legacy table');
    assert.equal(report.errors.length, 0, report.errors.join('\n'));
    report.result = 'PASS';
    fs.writeFileSync(path.join(output, 'P4-browser.json'), JSON.stringify(report, null, 2) + '\n');
    console.log('PASS ' + report.checks.length + ' browser checks');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
