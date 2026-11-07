const {chromium}=require('../../../.tools/node_modules/playwright');
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
(async()=>{
 const dir=process.env.GONET_FREQUENCY_BROWSER_OUTPUT,base=process.env.GONET_FREQUENCY_TEST_URL;
 fs.mkdirSync(dir,{recursive:true});const [name,value]=process.env.GONET_FREQUENCY_TEST_COOKIE.split('=');
 const browser=await chromium.launch({channel:'chrome',headless:true});const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:950},reducedMotion:'reduce'});
 const checks=[],errors=[];
 try{
  await context.addCookies([{name,value,url:base,httpOnly:true,secure:true}]);const page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));await page.goto(base+'/?page=settings');
  const current=page.locator('#collectionFrequencyCurrent'),number=page.locator('#collectionIntervalValue'),unit=page.locator('#collectionIntervalUnit');
  await page.getByText('当前采集频率：每 4 分钟采集一次',{exact:true}).waitFor();
  assert.deepEqual(await unit.locator('option').allTextContents(),['分','时','日']);checks.push('Current configured frequency and manual minute/hour/day choices are displayed');
  for(const [v,u,label] of [['2','day','每 2 天采集一次'],['3','hour','每 3 小时采集一次'],['7','minute','每 7 分钟采集一次']]){
   const before=await current.innerText();await number.fill(v);await unit.selectOption(u);assert.equal(await current.innerText(),before,'draft must not be reported as active');
   const saved=page.waitForResponse(r=>r.url().endsWith('/api/settings')&&r.request().method()==='PUT');await page.locator('#saveSettings').click();const response=await saved;assert.equal(response.status(),200);const body=await response.json();assert.equal(body.settings.collection_interval.value,Number(v));assert.equal(body.settings.collection_interval.unit,u);
   await page.getByText('当前采集频率：'+label,{exact:true}).waitFor();await page.reload();await page.getByText('当前采集频率：'+label,{exact:true}).waitFor();assert.equal(await number.inputValue(),v);assert.equal(await unit.inputValue(),u);
  }
  checks.push('Minute, hour and day values save to the real settings endpoint and survive reload; drafts never replace current frequency');
  let writes=0;page.on('request',r=>{if(r.url().endsWith('/api/settings')&&r.method()==='PUT')writes++});
  await number.fill('0');await page.locator('#saveSettings').click();await page.locator('#settingsFormError:not(.hidden)').waitFor();assert.equal(writes,0);assert.match(await current.innerText(),/每 7 分钟/);
  await number.fill('7');const recovered=page.waitForResponse(r=>r.url().endsWith('/api/settings')&&r.request().method()==='PUT');await page.locator('#saveSettings').click();assert.equal((await recovered).status(),200);await page.locator('#closeToast').click();checks.push('Invalid zero is rejected without changing the saved frequency');
  await page.screenshot({path:path.join(dir,'settings-wide.png'),fullPage:true});await page.setViewportSize({width:390,height:844});await page.locator('#panel-collection-frequency').scrollIntoViewIfNeeded();await page.screenshot({path:path.join(dir,'settings-narrow.png'),fullPage:true});assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+2));checks.push('Desktop and 390px settings layouts have no document overflow');assert.deepEqual(errors,[]);
  fs.writeFileSync(path.join(dir,'browser.json'),JSON.stringify({checks,errors},null,2));console.log('PASS '+checks.length+' collection frequency browser checks');
 }catch(e){fs.writeFileSync(path.join(dir,'browser-failure.json'),JSON.stringify({checks,errors,error:String(e.stack)},null,2));throw e}finally{await browser.close()}
})().catch(e=>{console.error(e);process.exitCode=1});
