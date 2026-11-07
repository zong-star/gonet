const {chromium}=require('../../../.tools/node_modules/playwright');
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
(async()=>{
 const dir=process.env.GONET_TOPOLOGY_SCHEDULE_BROWSER_OUTPUT,base=process.env.GONET_FREQUENCY_TEST_URL;fs.mkdirSync(dir,{recursive:true});const [name,value]=process.env.GONET_FREQUENCY_TEST_COOKIE.split('=');
 const browser=await chromium.launch({channel:'chrome',headless:true});const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:950},reducedMotion:'reduce'});const checks=[],errors=[];
 try{
  await context.addCookies([{name,value,url:base,httpOnly:true,secure:true}]);const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto(base+'/?page=settings');
  const current=page.locator('#topologyFrequencyCurrent'),number=page.locator('#topologyIntervalValue'),unit=page.locator('#topologyIntervalUnit');
  await page.getByText('当前扫描频率：已关闭自动更新（数值为 0）',{exact:true}).waitFor();assert.equal(await number.inputValue(),'0');assert.deepEqual(await unit.locator('option').allTextContents(),['分','时','日']);
  const left=await page.locator('#panel-collection-frequency').boundingBox(),right=await page.locator('#panel-topology-frequency').boundingBox();assert.ok(right.x>left.x&&Math.abs(right.y-left.y)<2);checks.push('Topology controls appear to the right of interface polling controls; default zero is visibly disabled');
  for(const [v,u,label] of [['1','day','每 1 天更新一次'],['2','hour','每 2 小时更新一次'],['5','minute','每 5 分钟更新一次'],['0','minute','已关闭自动更新（数值为 0）']]){
   const prior=await current.innerText();await number.fill(v);await unit.selectOption(u);assert.equal(await current.innerText(),prior);
   const response=page.waitForResponse(r=>r.url().endsWith('/api/settings')&&r.request().method()==='PUT');await page.locator('#saveSettings').click();const saved=await response;assert.equal(saved.status(),200);const settings=(await saved.json()).settings;assert.deepEqual(settings.topology_scan_interval,{value:Number(v),unit:u});assert.deepEqual(settings.collection_interval,{value:4,unit:'minute'});
   await page.getByText('当前扫描频率：'+label,{exact:true}).waitFor();await page.reload();await page.getByText('当前扫描频率：'+label,{exact:true}).waitFor();assert.equal(await number.inputValue(),v);assert.equal(await unit.inputValue(),u);
  }
  checks.push('Day/hour/minute values and zero save through the real endpoint and survive reload; interface polling stays at four minutes');
  let writes=0;page.on('request',r=>{if(r.url().endsWith('/api/settings')&&r.method()==='PUT')writes++});await number.fill('-1');await page.locator('#saveSettings').click();await page.locator('#settingsFormError:not(.hidden)').waitFor();assert.equal(writes,0);assert.match(await current.innerText(),/已关闭自动更新/);
  await number.fill('0');const restored=page.waitForResponse(r=>r.url().endsWith('/api/settings')&&r.request().method()==='PUT');await page.locator('#saveSettings').click();assert.equal((await restored).status(),200);await page.getByText('已是最新',{exact:true}).waitFor();await page.locator('#closeToast').click();checks.push('Negative values are rejected without modifying the active schedule');
  await page.screenshot({path:path.join(dir,'settings-wide.png'),fullPage:true});await page.setViewportSize({width:390,height:844});await page.locator('#panel-topology-frequency').scrollIntoViewIfNeeded();await page.screenshot({path:path.join(dir,'settings-narrow.png'),fullPage:true});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));const narrowLeft=await page.locator('#panel-collection-frequency').boundingBox(),narrowRight=await page.locator('#panel-topology-frequency').boundingBox();assert.ok(narrowRight.y>narrowLeft.y);assert.deepEqual(errors,[]);checks.push('Narrow screens stack both cards without horizontal overflow');
  fs.writeFileSync(path.join(dir,'browser.json'),JSON.stringify({checks,errors},null,2));console.log('PASS '+checks.length+' topology frequency browser checks');
 }catch(e){fs.writeFileSync(path.join(dir,'browser-failure.json'),JSON.stringify({checks,errors,error:String(e.stack)},null,2));throw e}finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
