const {chromium}=require('../../../.tools/node_modules/playwright');
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
(async()=>{
 const output=process.env.GONET_CURRENT_BROWSER_OUTPUT,base=process.env.GONET_CURRENT_TEST_URL;
 const browser=await chromium.launch({channel:'chrome',headless:true});
 const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:950},reducedMotion:'reduce'});
 const report={source:'Real consoleBackend -> repeatable-read PostgreSQL export with evidence -> authenticated HTTPS /api/state -> browser; captured and scrubbed direct LLDP/IF/LAG pair',checks:[],errors:[]};
 try{
  const login=await context.request.post(base+'/api/v1/auth/login',{headers:{'X-GoNet-Login':'1'},data:{username:'test-admin',password:'fixture-password'}});assert.equal(login.status(),200);
  const payload=await (await context.request.get(base+'/api/state')).json(),graph=payload.topology.graph;
  const ids=graph.links.map(l=>l.id);assert.equal(ids.length,2);assert.ok(ids.includes(249));assert.equal(graph.aggregate_connections.length,1);
  const page=await context.newPage();page.setDefaultTimeout(12000);page.on('pageerror',e=>report.errors.push(e.message));
  await page.goto(base+'/?page=topology');
  const member=id=>page.locator('#mainGraph [data-edge="link:'+id+'"]');
  await member(ids[0]).waitFor();await page.locator('[data-graph-mode="all"]').click();
  assert.equal(await page.locator('#mainGraph [data-edge]').count(),2);
  assert.equal(await page.locator('#mainGraph [data-node]').count(),2);
  assert.equal(await page.locator('#mainGraph [data-edge="link:2308"]').count(),0);
  assert.equal(await page.locator('#focusDevice option').count(),2);
  assert.equal(await page.locator('#mainGraph [data-node="3"]').count(),0);
  assert.ok((await page.locator('#topologyUpdatedAt').innerText()).includes('采集有缺口'));
  const group=await member(ids[0]).getAttribute('data-aggregate-id');assert.ok(group);assert.equal(group,await member(ids[1]).getAttribute('data-aggregate-id'));
  assert.notEqual(await member(ids[0]).locator('.nms-edge').getAttribute('d'),await member(ids[1]).locator('.nms-edge').getAttribute('d'));
  report.checks.push('Main graph hides historical active L2308 and history-only node; independent physical IDs share one inferred aggregation with distinct routes');
  for(const id of ids){
   const point=await member(id).locator('.nms-edge-hit').evaluate(p=>{const q=p.getPointAtLength(p.getTotalLength()-12);return new DOMPoint(q.x,q.y).matrixTransform(p.getScreenCTM()).toJSON()});
   await page.mouse.click(point.x,point.y);await page.locator('#detailPanel:not(.hidden)').waitFor();
   const text=await page.locator('#detailContent').innerText();assert.ok(text.includes('1 条物理链路 · L'+id),text);
   for(const other of ids)assert.ok(text.includes('L'+other),text);
   assert.ok(text.includes('对端推断'),text);await page.locator('#closeDetail').click();
  }
  report.checks.push('Both physical routes are independently mouse-clickable and group detail lists both member IDs');
  await page.screenshot({path:path.join(output,'topology-wide.png'),fullPage:true});
  await page.locator('[data-graph-mode="focus"]').click();await page.locator('#focusDevice').selectOption('2');
  assert.equal(await page.locator('#mainGraph [data-edge]').count(),2);
  await page.locator('.nav[data-page="overview"]').click();await page.locator('#miniGraph [data-edge]').first().waitFor();
  assert.equal(await page.locator('#miniGraph [data-edge]').count(),2);
  assert.equal(await page.locator('#miniGraph [data-edge="link:2308"]').count(),0);
  report.checks.push('Focus and mini graphs use the same current snapshot and retain both physical uplinks');
  await page.locator('.nav[data-page="devices"]').click();await page.locator('#devicesBody button[data-device="3"]').waitFor();
  report.checks.push('Historical device remains available in the device list');
  await page.locator('.nav[data-page="topology"]').click();await page.setViewportSize({width:390,height:844});await page.locator('#zoomFit').click();
  await page.screenshot({path:path.join(output,'topology-narrow.png'),fullPage:true});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+2));
  // Exercise refresh cleanup with the real response's next empty projection.
  // Backend zero-snapshot/attempt rules are separately tested against PostgreSQL.
  const same=structuredClone(payload),replacement=ids.find(id=>id!==249)+1;
  same.topology.graph.snapshot_id=graph.snapshot_id+1;
  for(const l of same.topology.graph.links)if(l.id!==249)l.id=replacement;
  for(const g of same.topology.graph.aggregate_connections)g.member_link_ids=g.member_link_ids.map(id=>String(id)==='249'?id:String(replacement));
  let nextPayload=same;
  await member(ids[0]).press('Enter');await page.locator('#detailPanel:not(.hidden)').waitFor();
  await page.route('**/api/state',route=>route.fulfill({status:200,contentType:'application/json',body:JSON.stringify(nextPayload)}));
  await page.locator('#mainGraph [data-edge="link:'+replacement+'"]').waitFor();
  assert.equal(await page.locator('#mainGraph [data-edge]').count(),2);
  assert.equal(await member(ids.find(id=>id!==249)).count(),0);
  assert.ok(await page.locator('#detailPanel').evaluate(el=>el.classList.contains('hidden')));
  report.checks.push('Same-count new snapshot replaces old physical ID and closes stale detail');
  const empty=structuredClone(payload);empty.topology.graph={...graph,snapshot_id:graph.snapshot_id+2,device_ids:[1],links:[],aggregate_connections:[],neighbor_candidates:[]};
  nextPayload=empty;
  await page.waitForFunction(()=>document.querySelectorAll('#mainGraph [data-edge]').length===0);
  assert.equal(await page.locator('#focusDevice option').count(),1);
  await page.locator('[data-graph-mode="all"]').click();assert.equal(await page.locator('#mainGraph [data-edge]').count(),0);
  await page.locator('.nav[data-page="overview"]').click();assert.equal(await page.locator('#miniGraph [data-edge]').count(),0);
  report.checks.push('390px layout has no document overflow; committed empty refresh clears all/focus/mini edges and stale center selection without history fallback');
  assert.deepEqual(report.errors,[]);
  fs.writeFileSync(path.join(output,'browser.json'),JSON.stringify(report,null,2)+'\n');console.log('PASS '+report.checks.length+' current topology browser checks');
 }catch(error){fs.writeFileSync(path.join(output,'browser-failure.json'),JSON.stringify({...report,error:String(error.stack)},null,2));throw error}
 finally{await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1});
