const {chromium}=require('../../../.tools/node_modules/playwright');
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
(async()=>{
 const output=process.env.GONET_PEER_LAG_BROWSER_OUTPUT,base=process.env.GONET_PEER_TEST_URL;
 const [cookieName,cookieValue]=process.env.GONET_PEER_TEST_COOKIE.split('=');fs.mkdirSync(output,{recursive:true});
 const browser=await chromium.launch({channel:'chrome',headless:true});
 const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:950},reducedMotion:'reduce'});
 const report={source:'Isolated GoNet HTTPS handler with synthetic graph and captured H3C member indices',checks:[],errors:[]};
 try{
  await context.addCookies([{name:cookieName,value:cookieValue,url:base,httpOnly:true,secure:true}]);
  const page=await context.newPage();page.setDefaultTimeout(12000);page.on('pageerror',e=>report.errors.push(e.message));
  await page.goto(base+'/?page=topology');await page.locator('.nav[data-page="topology"]').click();await page.locator('#mainGraph [data-edge="link:240"]').waitFor();
  await page.locator('[data-graph-mode="all"]').click();
  const member=id=>page.locator('#mainGraph [data-edge="link:'+id+'"]');
  await member(253).waitFor();assert.equal(await page.locator('#mainGraph [data-edge]').count(),5);
  const groupA=await member(240).getAttribute('data-aggregate-id'),groupB=await member(253).getAttribute('data-aggregate-id');assert.ok(groupA);assert.equal(groupA,groupB);
  assert.notEqual(await member(240).locator('.nms-edge').getAttribute('d'),await member(253).locator('.nms-edge').getAttribute('d'));
  report.checks.push('Five physical edges retained; 240/253 share an inferred group and have distinct routes');
  for(const [id,status] of [[240,'up'],[253,'degraded'],[65,'admin_down'],[66,'unknown']])assert.equal(await member(id).getAttribute('data-oper-status'),status);
  report.checks.push('UP, degraded, admin-down and collection failure are projected independently from LLDP and aggregation');
  for(const id of [240,253]){
   const point=await member(id).locator('.nms-edge-hit').evaluate(p=>{const q=p.getPointAtLength(Math.max(0,p.getTotalLength()-12));return new DOMPoint(q.x,q.y).matrixTransform(p.getScreenCTM()).toJSON()});
   await page.mouse.click(point.x,point.y);await page.locator('#detailPanel:not(.hidden)').waitFor();
   const text=await page.locator('#detailContent').innerText();assert.ok(text.includes('1 条物理链路 · L'+id),text);assert.ok(text.includes('L240')&&text.includes('L253')&&text.includes('对端推断'));assert.ok(text.includes('接口运行：')&&text.includes('采集：')); 
   await page.locator('#closeDetail').click();
  }
  report.checks.push('Mouse hits select each physical ID independently; group details include both members');
  await page.screenshot({path:path.join(output,'topology-wide.png'),fullPage:true});
  await page.goto(base+'/?page=devices');await page.locator('.nav[data-page="devices"]').click();await page.locator('#devicesBody button[data-device="74"]').click();
  await page.locator('.uplink-edge-detail[open] table tbody tr').first().waitFor();
  assert.equal(await page.locator('.uplink-edge-detail[open] table tbody tr').count(),2);
  await page.locator('.uplink-view section').last().getByRole('heading',{name:'直接邻居',exact:true}).waitFor();
  const text=await page.locator('.uplink-view').innerText();assert.ok(text.includes('对端推断'));assert.ok(!text.includes('查询失败'),text);
  report.checks.push('v4 path shows both physical rows by default; inferred and directly confirmed neighbor summaries render');
  await page.screenshot({path:path.join(output,'details-wide.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:path.join(output,'details-narrow.png'),fullPage:true});
  await page.locator('.uplink-edge-detail[open]').scrollIntoViewIfNeeded();
  await page.screenshot({path:path.join(output,'members-narrow.png'),fullPage:true});
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+2));
  report.checks.push('390px details retain all member rows without document overflow');
  await page.route('**/api/v1/devices/*/*?schema_version=4',route=>route.fulfill({status:400,contentType:'application/json',body:JSON.stringify({error:{code:'INVALID_ARGUMENT',message:'fixture legacy server'}})}));
  await page.locator('#closeDetail').click();await page.locator('#devicesBody button[data-device="74"]').click();
  await page.locator('.uplink-view').getByText('聚合信息不完整',{exact:false}).first().waitFor();
  report.checks.push('Unsupported v4 falls back to v3 and preserves its one-sided partial contract');
  assert.deepEqual(report.errors,[]);
  fs.writeFileSync(path.join(output,'browser.json'),JSON.stringify(report,null,2)+'\n');console.log('PASS '+report.checks.length+' peer aggregation browser checks');
 }catch(error){fs.writeFileSync(path.join(output,'browser-failure.json'),JSON.stringify({...report,error:String(error.stack)},null,2));throw error}
 finally{await browser.close()}
})().catch(error=>{console.error(error);process.exitCode=1});
