'use strict';
const $=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const kindLabel=k=>({switch:'交换机',router:'路由器',wireless_controller:'无线 AC',unknown:'待识别'}[k]||'待识别');
const pages={overview:['总览','网络总览','查看已确认设备与连接，持续发现网络变化。'],devices:['设备列表','现有设备','设备按 Chassis 去重，历史记录与本轮采集状态分开显示。'],topology:['拓扑视图','网络拓扑','查看核心与邻居连接，点击节点了解设备与物理端口。'],candidates:['未知邻居','未知邻居','LLDP 观察先保留，身份和型号核验后再计入正式设备。'],probes:['SNMP 探测池','SNMP 探测池','查看直接访问证据、身份状态与分批覆盖进度。'],settings:['扫描设置','扫描设置','管理发现起点与访问范围，让 LLDP 带路。'],api:['API 管理','API 管理','管理外部 AI 平台及自动化工具访问 GoNet 的 API Key。']};
let state={data:null,settings:null,token:'',job:{},page:'overview',devicePage:0,candidatePage:0,probePage:0,focus:null,graphMode:'all',zoom:1,scopeDirty:false,lastFingerprint:'',polling:false,requesting:false,draft:null,settingsFingerprint:'',settingsRenderKey:'',segmentPage:0,seedPage:0,exclusionPage:0,drawer:null,editingSegment:null,settingsError:'',scanError:'',settingsSaving:false,undo:null,
 /* P9：区域化变化判据与增量渲染 */
 signatures:null,pendingRender:{},regionStatus:{},serverSettingsChanged:false,lastError:null,lastPayloadBytes:0,lastRefreshMs:0,renderQueue:[],renderPending:false,slowHint:null};
/* P10：抽屉共用焦点、背景与滚动生命周期；关闭清理不依赖动画事件或计时器。 */
const reducedMotion=window.matchMedia('(prefers-reduced-motion: reduce)');
const FOCUSABLE='button:not(:disabled),a[href],input:not(:disabled),select:not(:disabled),textarea:not(:disabled),[tabindex]:not([tabindex="-1"])';
let activeDialog=null,toastTimer,announceTimer;
function canFocus(el){return !!el&&el.isConnected&&!el.closest('[inert],.hidden,[hidden]')&&!el.disabled&&el.getClientRects().length>0}
function focusables(root){return [...root.querySelectorAll(FOCUSABLE)].filter(canFocus)}
function focusTarget(el){if(canFocus(el)){el.focus({preventScroll:true});return document.activeElement===el}return false}
function focusBookmark(el){
 if(!el)return null;
 const root=el.closest('.page')||el.closest('[role="dialog"]')||document;
 const attrs=['data-edge','data-collapse','data-device','data-node','data-probe','data-candidate','data-drawer','data-segment-edit-start','data-segment-edit','data-segment-save','data-segment-cancel','data-remove-segment','data-remove-seed','data-remove-exclusion','data-undo'];
 const attr=attrs.find(key=>el.hasAttribute(key));
 return {el,root,id:el.id,attr,value:attr?el.getAttribute(attr):null};
}
function restoreBookmark(mark){
 if(!mark)return false;
 if(focusTarget(mark.el))return true;
 if(mark.id&&focusTarget($(mark.id)))return true;
 if(mark.attr){const match=[...mark.root.querySelectorAll('['+mark.attr+']')].find(el=>el.matches(FOCUSABLE)&&el.getAttribute(mark.attr)===mark.value);if(focusTarget(match))return true}
 return false;
}
function listEntry(page=state.page){return $({devices:'deviceSearch',candidates:'candidateSearch',probes:'probeSearch',settings:'segmentInput',topology:'focusDevice'}[page])||focusables($('page-'+page))[0]}
function openDialog(id,backdropId,initial,trigger){
 if(activeDialog)closeDialog(activeDialog.id,false);
 const panel=$(id),background=[document.querySelector('main'),document.querySelector('aside.sidebar')];
 activeDialog={id,backdropId,trigger:focusBookmark(trigger||document.activeElement),page:state.page,background:background.map(el=>({el,inert:el.inert})),overflow:document.body.style.overflow};
 panel.classList.remove('hidden');$(backdropId).classList.remove('hidden');panel.appendChild($('toast'));
 /* 滚动条槽由 html 的 scrollbar-gutter 保留，body 锁定不会改变内容宽度。 */
 document.body.style.overflow='hidden';background.forEach(el=>{el.inert=true});
 panel.scrollTop=0;focusTarget($(initial))||focusTarget(panel);
 if(!reducedMotion.matches)panel.animate([{opacity:0,transform:'translateX(8px)'},{opacity:1,transform:'none'}],{duration:parseFloat(getComputedStyle(document.documentElement).getPropertyValue('--motion-drawer')),easing:getComputedStyle(document.documentElement).getPropertyValue('--ease-standard').trim()});
}
function closeDialog(id,restore=true){
 if(!activeDialog||activeDialog.id!==id)return;
 const closing=activeDialog;activeDialog=null;
 $(id).getAnimations().forEach(animation=>animation.cancel());document.body.appendChild($('toast'));$(id).classList.add('hidden');$(closing.backdropId).classList.add('hidden');
 closing.background.forEach(({el,inert})=>{el.inert=inert});document.body.style.overflow=closing.overflow;
 if(restore&&!restoreBookmark(closing.trigger))focusTarget(listEntry(closing.page))||focusTarget(document.querySelector('.nav[aria-current="page"]'));
}
document.addEventListener('keydown',event=>{
 if(!activeDialog)return;
 if(event.key==='Escape'){event.preventDefault();event.stopImmediatePropagation();activeDialog.id==='exclusionDrawer'?closeDrawer():closeDetail();return}
 if(event.key==='Tab'){
  const panel=$(activeDialog.id),items=focusables(panel),first=items[0]||panel,last=items.at(-1)||panel;
  if(event.shiftKey&&(document.activeElement===first||!items.includes(document.activeElement))){event.preventDefault();focusTarget(last)}
  else if(!event.shiftKey&&(document.activeElement===last||!items.includes(document.activeElement))){event.preventDefault();focusTarget(first)}
 }
},true);
document.addEventListener('focusin',event=>{if(activeDialog&&!$(activeDialog.id).contains(event.target))focusTarget(focusables($(activeDialog.id))[0]||$(activeDialog.id))});
reducedMotion.addEventListener('change',event=>{if(event.matches&&activeDialog)$(activeDialog.id).getAnimations().forEach(animation=>animation.cancel())});
function announce(message){clearTimeout(announceTimer);$('uiAnnouncement').textContent='';announceTimer=setTimeout(()=>{$('uiAnnouncement').textContent=message},30)}
function dismissToast(){clearTimeout(toastTimer);if(document.activeElement===$('closeToast'))focusTarget(activeDialog?focusables($(activeDialog.id))[0]:listEntry());$('toast').classList.add('hidden')}
function toast(message,error=false){if(redirecting)return;$('toastMessage').textContent=message;$('toast').classList.toggle('error',error);$('toast').classList.remove('hidden');announce((error?'操作失败：':'')+message);clearTimeout(toastTimer);toastTimer=setTimeout(()=>{if(!$('toast').matches(':hover,:focus-within'))dismissToast()},6500)}
function date(v){if(!v)return '—';const d=new Date(v);return Number.isNaN(d.valueOf())?'—':d.toLocaleString('zh-CN',{hour12:false})}
function mac(v){return /^[0-9a-f]{12}$/i.test(v??'')?v.match(/.{2}/g).join(':'):v||'—'}
function name(d){return d?.inventory_name||d?.sys_name||`设备 #${d?.id??''}`}
function addr(d){return d?.access_addresses?.join(', ')||'无已验证地址'}
function primaryAddr(d){return d?.access_addresses?.[0]||'无已验证地址'}
function depthLabel(depth){return depth===0?'核心设备':depth===1?'第2层汇聚层':depth===2?'第3层接入层':Number.isInteger(depth)&&depth>2?'第'+(depth+1)+'层':'历史记录'}
function discoveryLabel(d){return current(d)?depthLabel(d.discovery_depth):'历史记录'}
function current(d){return d?.collection_status==='collected'}
function badge(d){return `<span class="badge ${current(d)?'green':'amber'}">${current(d)?'本轮已采集':'仅有历史记录'}</span>`}
function currentGraph(){return state.data?.graph||{snapshot_id:state.data?.latest_scan_id,device_ids:(state.data?.devices||[]).map(d=>d.id),links:state.data?.links||[],aggregate_connections:state.data?.aggregate_connections||[],neighbor_candidates:state.data?.neighbor_candidates||[]}}
function graphKnownDevices(){const ids=new Set((currentGraph().device_ids||[]).map(String));return(state.data?.devices||[]).filter(d=>ids.has(String(d.id)))}
function graphDevices(){const pending=(currentGraph().neighbor_candidates||[]).filter(n=>['router','wireless_controller'].includes(n.device_kind)).map(n=>({id:'pending:'+n.key,inventory_name:n.system_name||n.model,model:n.model,device_kind:n.device_kind,collection_status:'pending',access_addresses:[],link_count:0,is_pending:true,candidate:n}));return [...graphKnownDevices(),...pending]}
function graphByID(id){return graphKnownDevices().find(d=>String(d.id)===String(id))}
function graphSnapshotLabel(){const g=currentGraph();if(!g.snapshot_id)return '尚无已提交拓扑';const attempt=g.latest_attempt,extra=attempt&&String(attempt.scan_id)!==String(g.snapshot_id)?' · 最近尝试 #'+attempt.scan_id+' '+({running:'扫描中',failed:'失败',aborted:'已中止'}[attempt.status]||attempt.status):'';return '展示第 '+g.snapshot_id+' 轮 · 采集 '+date(g.snapshot_finished_at)+(g.snapshot_status==='partial'?' · 采集有缺口':'')+extra}
function deviceMap(){return new Map(graphDevices().map(d=>[String(d.id),d]))}
function byID(id){return state.data?.devices?.find(d=>String(d.id)===String(id))}
let sessionReady=false,redirecting=false,pollTimer=null,sessionRequests=new AbortController(),apiManagement=null;
function clearSession(next){
 if(redirecting)return;redirecting=true;sessionReady=false;clearInterval(pollTimer);clearTimeout(state.slowHint);clearTimeout(toastTimer);clearTimeout(announceTimer);sessionRequests.abort();
 if(activeDialog)closeDialog(activeDialog.id,false);
 apiManagement?.clear();mainTopology?.dispose();miniTopology?.dispose();mainTopology=null;miniTopology=null;
 state={page:state.page,data:null,settings:null,token:'',job:{},draft:null,undo:null,signatures:null,renderQueue:[],renderPending:false,pendingRender:{},regionStatus:{},drawer:null,hinted:[],polling:false,requesting:false};
 document.body.replaceChildren();
 location.replace('/login?next='+encodeURIComponent(next||('/?page='+state.page)));
}
async function sessionFetch(path,options={}){
 const response=await fetch(path,{credentials:'same-origin',...options,signal:sessionRequests.signal});
 if(response.status===401){clearSession();const error=Error('登录已失效');error.status=401;throw error}
 if(redirecting){const error=Error('登录已失效');error.status=401;throw error}return response;
}
async function request(path,body,method='POST'){
 if(!sessionReady)throw Error('请等待登录状态确认');
 const response=await sessionFetch(path,{method,headers:{'Content-Type':'application/json','X-GoNet-Token':state.token},body:JSON.stringify(body)});
 const data=response.status===204?null:await response.json();if(redirecting){const error=Error('登录已失效');error.status=401;throw error}if(!response.ok){const error=Error(data?.error?.message||data?.error||'请求未完成');error.status=response.status;throw error}return data;
}
function navigate(page){if(!pages[page])return;if(state.page==='api'&&page!=='api')apiManagement?.leave();if(activeDialog){activeDialog.id==='exclusionDrawer'?closeDrawer():closeDetail()}state.page=page;document.body.dataset.view=page;$('overviewMetrics').hidden=page!=='overview';$('scanMeta').hidden=page!=='overview';for(const [key]of Object.entries(pages))$(`page-${key}`).classList.toggle('hidden',key!==page);document.querySelectorAll('.nav').forEach(n=>{n.classList.toggle('active',n.dataset.page===page);if(n.dataset.page===page)n.setAttribute('aria-current','page');else n.removeAttribute('aria-current')});$('pageCrumb').textContent=pages[page][0];$('pageTitle').textContent=pages[page][1];$('pageDescription').textContent=pages[page][2];
 /* 进入页面时补渲染被标记的区域；首次数据未到则先放骨架（合同 §8） */
 if(page==='devices'){state.data?flushPendingFor('devices'):renderRegion('devices')}
 else if(page==='candidates'){state.data?flushPendingFor('candidates'):renderRegion('candidates')}
 else if(page==='probes'){state.data?flushPendingFor('probes'):renderRegion('probes')}
 else if(page==='overview')flushPendingFor('overview');
 else if(page==='topology')flushPendingFor('topology');
 else if(page==='settings')openSettings();
 else if(page==='api')apiManagement?.show();
 if(location.search!=='?page='+page)history.replaceState(null,'','/?page='+page);
 window.scrollTo({top:0,behavior:reducedMotion.matches?'instant':'smooth'});announce('已进入'+pages[page][0]);if(document.activeElement.closest('.hidden'))focusTarget(document.querySelector('.nav[aria-current="page"]'))}
let announcedStage='';
function updateJob(){
 if(redirecting)return;
 const j=state.job||{};const busy=!!j.running;const anyBusy=busy||state.requesting;
 $('scanButton').disabled=anyBusy;$('scanButton').setAttribute('aria-busy',String(anyBusy));$('scanIcon').classList.toggle('spinner',busy);$('scanIcon').textContent=busy?'':'↻';$('scanLabel').textContent=busy?'正在更新':'更新拓扑';$('cancelScan').classList.toggle('hidden',!busy);$('region-job').classList.toggle('hidden',!busy);
 const stageKey=busy?String(j.progress?.stage||'preparing'):'';if(stageKey&&stageKey!==announcedStage)announce('正在更新拓扑：'+({preparing:'准备递归发现',scanning:'沿 LLDP 采集',preprobe:'全范围 SNMP 探测',core_collection:'核心采集',recursive_collection:'递归采集',address_lookup:'补全访问地址',saving:'保存扫描结果',finished:'完成更新'}[stageKey]||'处理中'));announcedStage=stageKey;
 const locked=anyBusy||state.settingsSaving;
 $('saveSettings').disabled=locked;$('saveAndScan').disabled=locked;$('settingsRetryScan').disabled=locked;
 if(state.page==='settings')renderSettings();
 if(busy){const p=j.progress||{};const stage={preparing:'准备递归发现',scanning:'沿 LLDP 采集',preprobe:'全范围 SNMP 探测',core_collection:'核心采集',recursive_collection:'邻居匹配 / 递归',address_lookup:'补全访问地址',saving:'保存扫描结果',finished:'完成更新'}[p.stage]||'正在更新';$('progressTitle').textContent=/停止/.test(j.message||'')?j.message:stage;$('progressDetail').textContent=[Number.isInteger(p.depth)?depthLabel(p.depth):'',p.scheduled?`已处理 ${p.completed||0} / ${p.scheduled} 个任务`:'等待任务',p.target||'',p.probe?`允许 ${p.probe.range_hosts} 个主机 · 已识别 ${p.probe.identified||0}`:''].filter(Boolean).join(' · ');$('progressFill').style.transform='scaleX('+((p.scheduled?Math.min(98,Math.max(6,(p.completed||0)/p.scheduled*100)):8)/100)+')'}
}
/* ===== P9：区域化变化判据 + 增量渲染 =====
 * 每个区域独立判据（GoNetRegion）、独立状态、独立 DOM 根（#region-*）。
 * 只有签名变化的区域才渲染，且渲染统一合并到一次 requestAnimationFrame；
 * 隐藏页面只标记待渲染，进入页面时再更新（合同 §8）。 */
function scheduleRender(fn){
 state.renderQueue.push(fn);if(state.renderPending)return;state.renderPending=true;
 /* 合并到一次刷新：优先 rAF；页面被节流（后台标签/无头环境）时用定时器兜底，保证更新不丢 */
 const flush=()=>{if(!state.renderPending)return;state.renderPending=false;const queue=state.renderQueue;state.renderQueue=[];for(const task of queue)task()};
 if(typeof requestAnimationFrame==='function')requestAnimationFrame(flush);
 setTimeout(flush,50);
}
function regionPage(region){return GoNetRegion.REGION_PAGE[region]}
const REGION_UPDATE_ID={devices:'devicesUpdatedAt',candidates:'candidatesUpdatedAt',probes:'probesUpdatedAt',topology:'topologyUpdatedAt'};
const REGION_ERROR_ID={devices:['devicesError','devicesErrorText'],candidates:['candidatesError','candidatesErrorText'],probes:['probesError','probesErrorText']};
function setRegionError(region,message){const ids=REGION_ERROR_ID[region];if(!ids)return;const box=$(ids[0]);if(!box)return;const shown=!box.classList.contains('hidden');if(shown&&!message)showRegionError(ids[0],ids[1],'');else if(message&&(!shown||$(ids[1]).textContent!==message))showRegionError(ids[0],ids[1],message)}
function renderRegion(region){
 if(region==='job'){updateJob();return}
 if(region==='summary'){renderMetrics();return}
 if(region==='settings'){
  if(state.scopeDirty){if(state.serverSettingsChanged)renderSettings();return}
  if(state.page==='settings'&&!settingsEditing()&&syncDraft(false))renderSettings();
  return
 }
 if(region==='topology'){
  populateFocus();
  if(state.page==='overview')renderMiniGraph();else state.pendingRender.miniGraph=true;
  if(state.page==='topology')renderMainGraph();else state.pendingRender.mainGraph=true;
  markUpdated(REGION_UPDATE_ID.topology);return
 }
 const page=regionPage(region);
 if(region==='devices'){
  populateFilters();
  if(state.page==='overview')renderRecent();else state.pendingRender.recent=true;
  if(page&&state.page!==page){state.pendingRender.devices=true;return}
  renderDevices();markUpdated(REGION_UPDATE_ID.devices);return
 }
 if(page&&state.page!==page){state.pendingRender[region]=true;return}
 if(region==='candidates')renderCandidates();else if(region==='probes')renderProbes();
 markUpdated(REGION_UPDATE_ID[region]);
}
function flushPendingFor(page){
 for(const region of GoNetRegion.pendingFor(page,state.pendingRender)){state.pendingRender[region]=false;scheduleRender(()=>renderRegion(region))}
 if(page==='overview'&&state.pendingRender.miniGraph){state.pendingRender.miniGraph=false;scheduleRender(renderMiniGraph)}
 if(page==='overview'&&state.pendingRender.recent){state.pendingRender.recent=false;scheduleRender(renderRecent)}
 if(page==='topology'&&state.pendingRender.mainGraph){state.pendingRender.mainGraph=false;scheduleRender(renderMainGraph)}
}
async function refresh(){
 if(state.polling||!sessionReady||redirecting)return;state.polling=true;
 const started=performance.now();
 state.slowHint=setTimeout(()=>{if(state.polling&&state.data){state.hinted=['devices','candidates','probes'].filter(region=>state.page===regionPage(region));for(const region of state.hinted)markRefreshing(REGION_UPDATE_ID[region])}},300);
 try{
  const response=await sessionFetch('/api/state',{cache:'no-store'});if(!response.ok)throw Error(response.status===403?'请求校验失败，请刷新页面后重试':'本机控制台暂时无法响应');
  const text=await response.text();state.lastPayloadBytes=text.length;
  const incoming=JSON.parse(text);if(redirecting)return;
  state.token=incoming.token;state.job=incoming.job||{};state.settings=incoming.settings;
  if(incoming.topology){
   const previousSnapshot=state.data?.graph?.snapshot_id;
   state.data=incoming.topology;
   if(previousSnapshot!==undefined&&previousSnapshot!==state.data.graph?.snapshot_id){closeDetail();for(const viewer of [mainTopology,miniTopology])if(viewer){viewer.layouts.clear();viewer.collapsed.clear();viewer.selected=null}if(!graphByID(state.focus))state.focus=null}
  }
  const t=state.data||{};
  const next=GoNetRegion.signatures({
   summary:{device_counts:t.device_counts,probe_summary:t.probe_summary,coverage_gap:t.coverage_gap,latest_scan_id:t.latest_scan_id,latest_scan_status:t.latest_scan_status,latest_scan_finished_at:t.latest_scan_finished_at,pending_links:t.pending_links},
   error:incoming.error||'',settings:incoming.settings||{},job:incoming.job||{},topology:t,
  });
  const changed=GoNetRegion.changed(state.signatures,next);state.signatures=next;
  if(state.slowHint){clearTimeout(state.slowHint);state.slowHint=null}
  const errorText=incoming.error||'';
  if(errorText!==state.lastError){state.lastError=errorText;
   const box=$('connectionError');box.classList.toggle('hidden',!errorText);box.textContent=errorText;
   $('dbDot').classList.toggle('error',!!errorText);$('dbState').textContent=errorText?'PostgreSQL 暂不可用':'PostgreSQL 已连接'}
  for(const region of ['devices','candidates','probes'])setRegionError(region,'');
  if(changed.includes('settings')){if(state.scopeDirty)state.serverSettingsChanged=true;else state.serverSettingsChanged=false}
  /* 数据区域合并到一次刷新；进度卡片（job）必须立刻反映用户动作与后端状态，同步更新 */
  if(changed.length)for(const region of changed){if(region==='job')renderRegion('job');else scheduleRender(()=>renderRegion(region))}
  /* 慢请求时打出的“正在更新…”提示必须收回：数据没变的区域不会再走渲染，这里补一次 */
  for(const region of state.hinted||[])if(!changed.includes(region))markUpdated(REGION_UPDATE_ID[region]);
  state.hinted=[];
  flushPendingFor(state.page);
  const wasRunning=state.runningBefore;if(wasRunning&&!state.job.running&&state.runningJobId===state.job.id)toast(state.job.message||'更新完成',state.job.state==='failed');
  state.runningBefore=!!state.job.running;state.runningJobId=state.job.id;
 }catch(e){
  if(redirecting)return;
  const message=e.message||'无法连接本机控制台，请确认 GoNet 控制台仍在运行。';
  if(state.lastError!==message){state.lastError=message;
   const box=$('connectionError');box.classList.remove('hidden');box.textContent=message;
   $('dbState').textContent='控制台连接中断';$('dbDot').classList.add('error')}
  const detail=state.data?'最近一次更新失败，显示的是上一次成功的数据。':message;
  for(const region of ['devices','candidates','probes'])setRegionError(region,detail);
  if(state.data)for(const id of Object.values(REGION_UPDATE_ID))markStale(id,'未更新成功');
 }finally{
  if(state.slowHint){clearTimeout(state.slowHint);state.slowHint=null}
  state.lastRefreshMs=Math.round(performance.now()-started);state.polling=false;
 }
}
function renderMetrics(){const t=state.data;if(!t)return;const c=t.device_counts||{};$('metricDevices').textContent=c.confirmed??t.devices.length;$('metricKinds').textContent=`交换机 ${c.switches??t.devices.length} · 路由器 ${c.routers??0} · 无线 AC ${c.wireless_controllers??0}`;$('metricLinks').textContent=currentGraph().links.length;$('metricCandidates').textContent=t.neighbor_candidates.length;$('metricSeeds').textContent=state.settings.seeds.length;$('navCount').textContent=t.devices.length;$('candidateDot').classList.toggle('hidden',!t.neighbor_candidates.length);$('metricCurrent').textContent=`本轮采集 ${c.collected_this_scan??0} 台 · 历史 ${c.historical_only??0} 台`;$('metricSeedIP').textContent=state.settings.seeds.slice(0,2).join('、')+(state.settings.seeds.length>2?'…':'');const currentLinks=currentGraph().links,both=currentLinks.filter(l=>l.confidence==='bidirectional').length;$('metricConfidence').textContent=`双向确认 ${both} 条 · 单向 ${currentLinks.length-both} 条`;$('scanStatus').textContent=t.latest_scan_status==='completed'?'本轮更新完成':t.latest_scan_id?'更新完成 · 有待核验项':'尚无扫描结果';$('scanStatus').classList.toggle('ok',t.latest_scan_status==='completed');$('lastScan').textContent=t.latest_scan_id?`第 ${t.latest_scan_id} 轮 · ${date(t.latest_scan_finished_at||t.devices.map(d=>d.last_seen_at).sort().at(-1))}`:'尚无已提交扫描';$('coverageText').textContent=t.pending_links.length?`${t.pending_links.length} 条端口观察待核验`:''}
function renderRecent(){const devices=(state.data?.devices||[]).slice().sort((a,b)=>(b.discovery_depth===0)-(a.discovery_depth===0)||a.id-b.id).slice(0,8);$('recentDevices').innerHTML=devices.length?devices.map(d=>`<tr data-device="${esc(d.id)}"><td><button class="device-label row-open text-button" data-device="${esc(d.id)}" aria-label="查看 ${esc(name(d))} 详情">${esc(name(d))}</button><span class="sub-label">${esc(d.vendor)} · ${esc(d.model)}</span></td><td class="mono">${esc(addr(d))}</td><td>${badge(d)}</td></tr>`).join(''):'<tr><td colspan="3" class="empty-cell">还没有设备，配置起点后点击更新拓扑。</td></tr>'}
function fillSelect(el,values,label){const old=el.value;el.innerHTML=`<option value="">${label}</option>`+values.map(v=>`<option value="${esc(v)}">${esc(v)}</option>`).join('');el.value=values.includes(old)?old:''}
function populateFilters(){const ds=state.data?.devices||[];fillSelect($('vendorFilter'),[...new Set(ds.map(d=>d.vendor).filter(Boolean))].sort(),'全部厂商')}
/* ===== 列表页：统一 15 条紧凑分页 + 行级增量更新 =====
 * 数据流固定为：完整数据 → 筛选 → 稳定排序 → 分页 → 只渲染当前页（合同 §5）。
 * DOM 更新走 GoNetRegion.planRows：key 与行内容都没变的行整行复用，不重建。 */
const LIST_PAGE=15;
const LIST_PAGERS={devices:null,candidates:null,probes:null};
function listSkeleton(body,columns,rows=LIST_PAGE){let html='';for(let i=0;i<rows;i++)html+='<tr class="skeleton-row" aria-hidden="true"><td colspan="'+columns+'"><span class="skeleton w-60"></span></td></tr>';return html}
function showRegionError(regionId,textId,message){const box=$(regionId);if(!box)return;box.classList.toggle('hidden',!message);const t=$(textId);if(t&&t.textContent!==(message||''))t.textContent=message||''}
function markUpdated(updatedAtId){const el=$(updatedAtId);if(!el)return;const at=new Date();el.textContent=(updatedAtId==='topologyUpdatedAt'?graphSnapshotLabel()+' · 页面刷新 ':'已更新 ')+at.toLocaleTimeString('zh-CN',{hour12:false});el.classList.remove('stale')}
function markStale(updatedAtId,message){const el=$(updatedAtId);if(!el)return;el.textContent=message;el.classList.add('stale')}
function markRefreshing(updatedAtId){const el=$(updatedAtId);if(!el)return;el.textContent='正在更新…';el.classList.remove('stale')}
// 稳定行更新：按 key 复用，只有内容变化的那一行才替换
function applyRows(body,rows,keyOf){
 const nodes=[...body.children];
 const existing=nodes.map(node=>({key:node.dataset.rowKey,hash:node.dataset.rowHash}));
 const target=rows.map(row=>({key:String(keyOf(row.data)),hash:GoNetRegion.hash(row.markup)}));
 const plan=GoNetRegion.planRows(existing,target);
 // 同 key 的节点按 DOM 顺序排队取用；没有 key 的行（骨架行）只能被删除
 const pool=new Map();for(const node of nodes){const k=node.dataset.rowKey||'';if(!pool.has(k))pool.set(k,[]);pool.get(k).push(node)}
 const take=key=>{const list=pool.get(key);return list&&list.length?list.shift():null};
 const placed=[];
 for(let i=0;i<plan.ops.length;i++){
  const op=plan.ops[i];if(op.action==='remove')continue;
  let node=op.action==='reuse'?take(op.key):null;
  if(!node){
   const holder=document.createElement('tbody');holder.innerHTML=rows[i].markup.trim();
   const fresh=holder.firstElementChild;for(const cell of fresh.querySelectorAll('td'))if(!cell.hasAttribute('title'))cell.title=cell.textContent.trim().replace(/\s+/g,' ');fresh.dataset.rowKey=op.key;fresh.dataset.rowHash=target[i].hash;
   const old=take(op.key);if(old)old.replaceWith(fresh);
   node=fresh;
  }
  placed.push(node);
 }
 for(const list of pool.values())for(const node of list)node.remove();
 let cursor=null;
 for(const node of placed){const ref=cursor?cursor.nextElementSibling:body.firstElementChild;if(node!==ref)body.insertBefore(node,ref);cursor=node}
 body.dataset.rowStats='reuse='+plan.stats.reuse+' create='+plan.stats.create+' replace='+plan.stats.replace+' remove='+plan.stats.remove;
 body.dataset.renderTick=String(Number(body.dataset.renderTick||0)+1);
 return plan.stats;
}
function fillListSlots(rows,columns,key){if(!rows.length)return;for(let i=rows.length;i<LIST_PAGE;i++)rows.push({data:{[key]:'__slot__'+i},markup:'<tr class="list-slot" aria-hidden="true" role="presentation">'+('<td></td>'.repeat(columns))+'</tr>'})}
function emptyRow(columns,filtered,clearId,text){const button=clearId?'<button class="button secondary compact" data-clear="'+clearId+'">清除筛选</button>':'';return '<tr class="empty-row"><td colspan="'+columns+'"><div class="empty-state"><strong>'+esc(text[0])+'</strong>'+esc(text[1])+button+'</div></td></tr>'}
function filteredDevices(){const q=$('deviceSearch').value.trim().toLowerCase(),vendor=$('vendorFilter').value,status=$('statusFilter').value,kind=$('kindFilter').value;return(state.data?.devices||[]).filter(d=>(!vendor||d.vendor===vendor)&&(!status||d.collection_status===status)&&(!kind||(d.device_kind||'switch')===kind)&&(!q||[name(d),addr(d),mac(d.chassis_mac),d.chassis_mac,d.model,d.vendor].join(' ').toLowerCase().includes(q)))}
function deviceFiltersActive(){return ['deviceSearch','vendorFilter','statusFilter','kindFilter'].some(id=>$(id).value)}
function renderDevices(){
 if(!state.data){$('devicesBody').innerHTML=listSkeleton($('devicesBody'),9);$('deviceCount').textContent='';return}
 const all=state.data.devices||[],ds=filteredDevices().slice().sort((a,b)=>a.id-b.id);
 const filtered=deviceFiltersActive();
 $('deviceCount').textContent='共 '+ds.length+' 条'+(filtered?'（已筛选，共 '+all.length+' 条）':'');
 $('clearDeviceFilters').classList.toggle('hidden',!filtered||ds.length>0);
 const result=GoNetPager.paginate(ds,state.devicePage,LIST_PAGE);state.devicePage=result.pageIndex;
 const rows=result.pageItems.map(d=>({data:d,markup:'<tr data-device="'+esc(d.id)+'"><td><span class="device-label" title="'+esc(name(d))+'">'+esc(name(d))+'</span></td><td title="'+esc([d.vendor,d.model].filter(Boolean).join(' · '))+'">'+esc(d.model||'—')+'</td><td><span class="badge neutral">'+kindLabel(d.device_kind||'switch')+'</span></td><td class="mono" title="'+esc(primaryAddr(d))+'">'+esc(primaryAddr(d))+'</td><td class="mono">'+esc(mac(d.chassis_mac))+'</td><td>'+esc(discoveryLabel(d))+'</td><td>'+esc(d.link_count)+' 条</td><td>'+badge(d)+'</td><td class="col-open"><button class="button secondary compact row-open" data-device="'+esc(d.id)+'" aria-label="查看设备 '+esc(name(d))+' 的详情">详情</button></td></tr>'}));
 fillListSlots(rows,9,'id');
 if(!rows.length)rows.push({data:{id:'__empty__'},markup:emptyRow(9,filtered,filtered?'devices':null,filtered?['没有符合筛选条件的设备','试试换关键词，或清除筛选后查看全部设备。']:['还没有设备','配置发现起点后点击“更新拓扑”。'])});
 applyRows($('devicesBody'),rows,d=>d.id);
 LIST_PAGERS.devices=LIST_PAGERS.devices||GoNetPager.create($('devicePager'),{pageSize:LIST_PAGE,onPageChange:index=>{state.devicePage=index;renderDevices()}});
 LIST_PAGERS.devices.render(result);
}
function probeFiltersActive(){return !!$('probeSearch').value}
function renderProbes(){
 if(!state.data){$('probesBody').innerHTML=listSkeleton($('probesBody'),7);$('probeCount').textContent='';return}
 const pool=state.data.probe_pool||[],s=state.data.probe_summary||{},q=$('probeSearch').value.trim().toLowerCase();
 const ds=pool.filter(p=>!q||[p.probe_ip,p.last_successful_facts?.sys_name,p.normalized_identity,p.failure_reason,p.failure_code,p.model,probeState(p),probeRemark(p)].join(' ').toLowerCase().includes(q)).slice().sort((a,b)=>compareIP(a.probe_ip,b.probe_ip));
 // A8：统计与列表同源，探测池数量取列表实际长度
 const coverage=['范围 '+(s.range_hosts??0)+' 个主机','本轮尝试 '+(s.probe_completed??0),'可识别 '+(s.identified??0),'本轮未安排/未尝试 '+(s.deferred??0),'探测池 '+pool.length+' 条地址记录 / '+(s.pool_identities??0)+' 组身份','覆盖 '+(s.cursor?.covered_hosts??0)+' / '+(s.range_hosts??0),'已轮询 '+(s.cursor?.completed_cycles??0)+' 轮'];
 if(s.full_range)coverage.unshift(s.deferred===0?'本轮全范围探测完成':'本轮全范围探测未完成');
 if(s.termination_reason==='scope_changed')coverage.push('范围变更后覆盖从 0 重新计算，历史探测记录仍保留');
 const coverageText=coverage.join(' · ');if($('probeCoverage').textContent!==coverageText)$('probeCoverage').textContent=coverageText;
 $('probeCount').textContent=ds.length+' 条地址记录'+(q?'（已筛选，共 '+pool.length+' 条）':'');
 $('clearProbeFilters').classList.toggle('hidden',!q||ds.length>0);
 const result=GoNetPager.paginate(ds,state.probePage,LIST_PAGE);state.probePage=result.pageIndex;
 const rows=result.pageItems.map(p=>{const f=p.last_successful_facts||{},topology={linked:'已关联拓扑',managed:'已纳管',unassociated:'未关联拓扑'}[p.topology_status]||'未关联拓扑';return {data:p,markup:'<tr data-probe="'+esc(p.probe_ip)+'"><td class="mono">'+esc(p.probe_ip)+'</td><td title="'+esc(f.sys_name||'—')+'">'+esc(f.sys_name||'—')+'</td><td title="'+esc(p.model||'—')+'">'+esc(p.model||'—')+'</td><td>'+esc(topology)+'</td><td>'+esc(probeCollectedAt(p))+'</td><td title="'+esc(probeRemark(p))+'">'+esc(probeRemark(p))+'</td><td class="col-open"><button class="button secondary compact row-open" data-probe="'+esc(p.probe_ip)+'" aria-label="查看探测地址 '+esc(p.probe_ip)+' 的完整诊断">诊断</button></td></tr>'}});
 fillListSlots(rows,7,'probe_ip');
 if(!rows.length)rows.push({data:{probe_ip:'__empty__'},markup:emptyRow(7,q,q?'probes':null,q?['没有符合筛选条件的探测记录','试试换关键词，或清除筛选后查看全部记录。']:['还没有探测记录','更新拓扑后会保存直接 SNMP 访问事实。'])});
 applyRows($('probesBody'),rows,p=>p.probe_ip);
 LIST_PAGERS.probes=LIST_PAGERS.probes||GoNetPager.create($('probePager'),{pageSize:LIST_PAGE,onPageChange:index=>{state.probePage=index;renderProbes()}});
 LIST_PAGERS.probes.render(result);
}
function candidateFiltersActive(){return !!$('candidateSearch').value}
function renderCandidates(){
 if(!state.data){$('candidatesBody').innerHTML=listSkeleton($('candidatesBody'),7);$('candidateCount').textContent='';return}
 const all=state.data.neighbor_candidates||[],q=$('candidateSearch').value.trim().toLowerCase();
 const ds=all.filter(n=>!q||[n.system_name,n.key,...(n.observed_by||[]),...(n.reported_management_addresses||[]),n.verification?.failure_code].join(' ').toLowerCase().includes(q)).slice().sort((a,b)=>String(a.key).localeCompare(String(b.key)));
 $('candidateCount').textContent=ds.length+' 条记录 · 不计设备数'+(q?'（已筛选，共 '+all.length+' 条）':'');
 $('clearCandidateFilters').classList.toggle('hidden',!q||ds.length>0);
 const result=GoNetPager.paginate(ds,state.candidatePage,LIST_PAGE);state.candidatePage=result.pageIndex;
 const rows=result.pageItems.map(n=>{const v=n.verification||{},fallback=n.status==='identity_conflict'?'身份冲突':n.status==='port_match_failed'?'身份 / 物理端口待核验':'无访问地址或型号待核验';const code=v.failure_code||'',reason=code?code+' · '+(v.failure_reason||''):fallback;const addresses=(n.reported_management_addresses||[]).join('、')||'未通告';return {data:n,markup:'<tr data-candidate="'+esc(n.key)+'"><td><span class="device-label" title="'+esc(n.system_name||'')+'">'+esc(short(n.system_name||'未通告名称',26))+'</span><span class="sub-label">'+esc(short(n.model||'型号未通告',22))+'</span></td><td><span class="badge neutral">'+kindLabel(n.device_kind||'unknown')+'</span></td><td class="neighbor-key" title="'+esc(n.key)+'">'+esc(short(n.key,28))+'<span class="sub-label">'+esc(short(n.system_description||'',28))+'</span></td><td>'+esc(short((n.observed_by||[]).join('、')||'—',22))+'</td><td class="mono" title="'+esc(addresses)+'">'+esc(short(addresses,24))+((v.selected_snmp_ip||n.reported_management_addresses?.length)?'<span class="sub-label">'+(v.selected_snmp_ip?'核验 '+esc(v.selected_snmp_ip):'本轮未选出核验地址')+'</span>':'')+'</td><td><span class="badge amber">'+esc(short(reason,26))+'</span><span class="sub-label">'+(v.last_verification_at?'最近核验 '+esc(date(v.last_verification_at)):'尚未核验')+' · 后续扫描可重试</span></td><td class="col-open"><button class="button secondary compact row-open" data-candidate="'+esc(n.key)+'" aria-label="查看邻居 '+(esc(n.system_name||'未通告名称'))+' 的完整核验信息">详情</button></td></tr>'}});
 fillListSlots(rows,7,'key');
 if(!rows.length)rows.push({data:{key:'__empty__'},markup:emptyRow(7,q,q?'candidates':null,q?['没有符合筛选条件的邻居记录','这些记录不计入设备数，清除筛选可查看全部。']:['还没有未知邻居','更新拓扑后，未完成身份核验的 LLDP 邻居会出现在这里。'])});
 applyRows($('candidatesBody'),rows,n=>n.key);
 LIST_PAGERS.candidates=LIST_PAGERS.candidates||GoNetPager.create($('candidatePager'),{pageSize:LIST_PAGE,onPageChange:index=>{state.candidatePage=index;renderCandidates()}});
 LIST_PAGERS.candidates.render(result);
}
// IPv4 数值序 / IPv6 字节序，第二排序项原字符串（合同 §5.3）
function compareIP(a,b){const ka=ipKey(String(a||'')),kb=ipKey(String(b||''));if(ka&&kb){if(ka.length!==kb.length)return ka.length-kb.length;for(let i=0;i<ka.length;i++)if(ka[i]!==kb[i])return ka[i]-kb[i];return String(a).localeCompare(String(b))}if(ka)return -1;if(kb)return 1;return String(a).localeCompare(String(b))}
function ipKey(value){const v4=value.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);if(v4){for(let i=1;i<=4;i++)if(Number(v4[i])>255)return null;return [0,Number(v4[1]),Number(v4[2]),Number(v4[3]),Number(v4[4])]}const v6=value.split(':');if(value.includes(':')&&v6.length>1&&/^[0-9a-fA-F:]+$/.test(value)){const groups=[];for(const part of value.split(':')){if(part===''){groups.push(0);continue}const n=parseInt(part,16);groups.push(Number.isNaN(n)?-1:n)}return [1,...groups]}return null}
function clearListFilters(which){if(which==='devices'){for(const id of ['deviceSearch','vendorFilter','kindFilter','statusFilter'])$(id).value='';state.devicePage=0;$('deviceSearch').focus();renderDevices()}if(which==='candidates'){$('candidateSearch').value='';state.candidatePage=0;$('candidateSearch').focus();renderCandidates()}if(which==='probes'){$('probeSearch').value='';state.probePage=0;$('probeSearch').focus();renderProbes()}}
function retryRegion(region){setRegionError(region,'');toast('正在重新读取数据库…');refresh()}
// List summaries describe the latest attempt; older successful facts remain in diagnostics.
function probeSucceeded(p){return p.probe_status==='identified'&&!p.identity_conflict&&!p.failure_code}
function probeCollectedAt(p){return probeSucceeded(p)?date(p.last_success_at||p.last_attempt_at):'尝试-'+date(p.last_attempt_at)}
function probeRemark(p){if(probeSucceeded(p))return '已探测';const reasons={SNMP_TIMEOUT:'SNMP 响应超时',SNMP_AUTH:'SNMP 认证/授权失败',SNMP_AUTH_FAILED:'SNMP 认证失败',SNMP_AUTHORIZATION_FAILED:'SNMP 授权失败',LLDP_LOCAL_UNAVAILABLE:'本机 Chassis 待核验',IDENTITY_CONFLICT:'身份冲突',CANCELED:'探测已取消'};return reasons[p.failure_code]||p.failure_reason||p.failure_code||({unresponsive:'SNMP 未响应',authentication_failed:'SNMP 认证/授权失败',identity_pending:'身份待核验',identity_conflict:'身份冲突',canceled:'探测已取消'}[p.probe_status])||'尚未完成探测'}
function probeTone(p){return p.scope_status!=='allowed'?'neutral':p.identity_conflict?'warning':p.probe_status==='authentication_failed'?'danger':['unresponsive','canceled'].includes(p.probe_status)?'neutral':p.probe_status==='identity_pending'||p.cache_status==='stale'?'warning':'success'}
function probeState(p){
 if(p.scope_status!=='allowed')return '明确排除 / 范围外';
 if(p.identity_conflict)return '身份冲突';
 if(p.probe_status==='authentication_failed')return 'SNMP 认证/授权失败';
 if(p.probe_status==='unresponsive')return '当前未响应';
 if(p.probe_status==='canceled')return '本轮已取消';
 if(p.probe_status==='identity_pending')return 'SNMP 可达，身份待核验';
 if(p.cache_status==='stale')return '缓存过期';
 return 'SNMP 已识别';
}
function pairs(){const g=currentGraph(),edges=GoNetTopologyLayout.physicalEdges(g.links||[],g.aggregate_connections||[]),pending=new Map();for(const n of g.neighbor_candidates||[]){if(!['router','wireless_controller'].includes(n.device_kind))continue;for(const id of n.observed_by_ids||[]){if(graphByID(id)){const key='pending:'+id+':'+n.key;pending.set(key,{key,a:String(id),b:'pending:'+n.key,links:[],pending:true})}}}return [...edges,...pending.values()]}
function getRoot(){return graphByID(state.focus)||graphByID(state.data?.core_ids?.[0])||graphKnownDevices()[0]}
function populateFocus(){const old=state.focus,ds=graphKnownDevices();$('focusDevice').innerHTML=ds.map(d=>`<option value="${esc(d.id)}">${esc(name(d))}</option>`).join('');state.focus=graphByID(old)?.id||graphByID(state.data?.core_ids?.[0])?.id||ds[0]?.id;$('focusDevice').value=String(state.focus??'')}
function short(v,len=18){v=String(v??'');return v.length>len?v.slice(0,len-1)+'…':v}
let mainTopology=null,miniTopology=null;
function topologyInput(mini=false){const all=pairs(),allNodes=graphDevices(),root=mini?(graphByID(state.data?.core_ids?.[0])||graphKnownDevices()[0]):getRoot();if(!root)return{nodes:[],edges:[],roots:[]};if(!mini&&state.graphMode==='all')return{nodes:allNodes,edges:all,roots:state.data?.core_ids||[root.id]};const adjacent=all.filter(e=>e.a===String(root.id)||e.b===String(root.id));adjacent.sort((a,b)=>{const da=byID(a.a===String(root.id)?a.b:a.a),db=byID(b.a===String(root.id)?b.b:b.a);return(db?.link_count||0)-(da?.link_count||0)||String(a.key).localeCompare(String(b.key),'en',{numeric:true})});const peers=[...new Set(adjacent.map(e=>e.a===String(root.id)?e.b:e.a))],shownPeers=new Set(mini?peers.slice(0,6):peers),shown=adjacent.filter(e=>shownPeers.has(e.a===String(root.id)?e.b:e.a)),ids=new Set([String(root.id),...shown.flatMap(e=>[e.a,e.b])]);return{nodes:allNodes.filter(d=>ids.has(String(d.id))),edges:all.filter(e=>ids.has(e.a)&&ids.has(e.b)),roots:[String(root.id)]}}
function renderMiniGraph(){miniTopology=miniTopology||GoNetTopology.create($('miniGraph'),{mini:true});const input=topologyInput(true);miniTopology.update(input,'mini:'+currentGraph().snapshot_id);$('miniGraphHint').textContent='核心及 '+Math.max(0,input.nodes.length-1)+' 台直连设备 · 全网视图可查看其余分支'}
function renderMainGraph(){
 mainTopology=mainTopology||GoNetTopology.create($('mainGraph'),{onNode:(id,trigger)=>showDetail(id,trigger),onEdge:showGraphLinkDetail,onView:view=>{$('zoomLevel').textContent=(view.k<.1?(view.k*100).toFixed(1):Math.round(view.k*100))+'%'},onFullscreen:active=>{$('zoomFullscreen').textContent=active?'退出全屏':'全屏';$('zoomFullscreen').setAttribute('aria-pressed',String(active))},onLayout:layout=>{const count=layout.nodes.filter(n=>!n.data.is_pending).length;const hidden=layout.hiddenCount?' · 已折叠 '+layout.hiddenCount+' 台 / '+layout.hiddenLinks+' 组连接':'';$('graphCaption').textContent=(state.graphMode==='all'?'全网':'邻接')+' · 显示 '+count+' 台设备 / '+layout.edges.reduce((sum,e)=>sum+(e.links?.length||0),0)+' 条物理链路'+(layout.nodes.some(n=>n.data.is_pending)?' · 含未核验端点':'')+hidden;$('expandBranches').disabled=!layout.hiddenCount}});
 document.querySelectorAll('[data-graph-mode]').forEach(b=>{const selected=b.dataset.graphMode===state.graphMode;b.classList.toggle('selected',selected);b.setAttribute('aria-pressed',String(selected))});
 mainTopology.update(topologyInput(),currentGraph().snapshot_id+':'+(state.graphMode==='all'?'all':'focus:'+String(getRoot()?.id)));
 $('topologyUpdatedAt').textContent=graphSnapshotLabel()+' · 页面刷新 '+new Date().toLocaleTimeString('zh-CN',{hour12:false});
}
function locateTopology(){const q=$('topologySearch').value.trim().toLowerCase();if(!q)return;const ds=graphKnownDevices(),matches=ds.filter(d=>[name(d),addr(d),d.chassis_mac].join(' ').toLowerCase().includes(q));if(!matches.length){toast('没有找到匹配的设备',true);return}state.focus=matches[0].id;$('focusDevice').value=String(state.focus);if(state.graphMode==='focus')renderMainGraph();mainTopology?.locate(state.focus);announce('已定位 '+name(matches[0]))}
function interfaceStatusDetail(l){const labels={up:'正常 UP',down:'DOWN',admin_down:'管理关闭',degraded:'两端状态不一致',unknown:'未知',stale:'数据过期'};return '<small>接口运行：'+esc(labels[l.link_oper_status]||'未知')+' · A '+esc(l.source_admin_status||'unknown')+'/'+esc(l.source_oper_status||'unknown')+' ↔ B '+esc(l.target_admin_status||'unknown')+'/'+esc(l.target_oper_status||'unknown')+'</small><small>采集：'+esc(l.source_collection_state||'unknown')+' / '+esc(l.target_collection_state||'unknown')+' · '+esc(l.status_collected_at?date(l.status_collected_at):'尚无成功采样')+'</small>'}
function graphAggregationDetail(group){if(!group)return '';const labels=[group.group_a,group.group_b].filter(Boolean).map(g=>esc(g.display_name||g.interface_name||'聚合接口未知'));const links=new Map((currentGraph().links||[]).map(l=>[String(l.id),l]));return '<div class="detail-caption">聚合 · '+(group.status==='inferred'?'对端推断':'双端确认')+' · '+group.member_link_ids.length+' 条物理成员</div><p>'+labels.join(' ↔ ')+'</p><div class="detail-links">'+group.member_link_ids.map(id=>{const l=links.get(String(id));return l?'<div class="detail-link"><b>L'+esc(id)+'</b><small>'+esc(port(l.port_a_key,l.port_a_name))+' ↔ '+esc(port(l.port_b_key,l.port_b_name))+'</small></div>':''}).join('')+'</div>'+(group.status==='inferred'?'<p>信锐真实聚合口名称与完整成员表未采集，当前依据对端映射建立关系。</p>':'')}
function showGraphLinkDetail(edge,trigger){if(edge.pending){showDetail(edge.a.startsWith('pending:')?edge.a:edge.b,trigger);return}const a=byID(edge.a),b=byID(edge.b);$('detailContent').innerHTML='<h2>'+esc(name(a))+' ↔ '+esc(name(b))+'</h2><div class="detail-caption">'+edge.links.length+' 条物理链路 · L'+esc(edge.links[0]?.id)+'</div>'+graphAggregationDetail(edge.aggregation)+'<div class="detail-links">'+edge.links.map(l=>'<div class="detail-link"><b>L'+esc(l.id)+'</b><small>'+esc(name(byID(l.device_a_id)))+' · '+esc(port(l.port_a_key,l.port_a_name))+'</small><small>↔ '+esc(name(byID(l.device_b_id)))+' · '+esc(port(l.port_b_key,l.port_b_name))+'</small><small>'+(l.confidence==='bidirectional'?'双向确认':'单向证据')+' · '+(l.fresh?'本轮观察':'历史连接')+'</small>'+interfaceStatusDetail(l)+'</div>').join('')+'</div><button class="button secondary" data-device="'+esc(edge.a)+'">查看 '+esc(name(a))+' 的详情</button><button class="button secondary" data-device="'+esc(edge.b)+'">查看 '+esc(name(b))+' 的详情</button>';openDetailPanel(trigger)}
function port(key,description){if(key?.startsWith('lldp:5:')){try{return new TextDecoder().decode(Uint8Array.from(key.slice(7).match(/.{2}/g)||[],v=>parseInt(v,16)))}catch{}}if(key?.startsWith('lldp:3:'))return mac(key.slice(7));return description||key||'待核验'}
function copyValue(value){const text=String(value??'');const done=()=>toast('已复制：'+short(text,40));if(navigator.clipboard?.writeText)return navigator.clipboard.writeText(text).then(done,()=>toast('复制失败，请手动选择文本',true));const previous=document.activeElement,area=document.createElement('textarea');area.value=text;area.tabIndex=-1;(activeDialog?$(activeDialog.id):document.body).append(area);area.select();try{document.execCommand('copy');done()}catch(e){toast('复制失败，请手动选择文本',true)}area.remove();focusTarget(previous)}
function detailFields(fields){return '<div class="detail-fields">'+fields.map(([label,value])=>'<div class="detail-field"><label>'+esc(label)+'</label><div>'+esc(value)+'</div></div>').join('')+'</div>'}
function showProbeDetail(ip,trigger){
 const p=(state.data?.probe_pool||[]).find(x=>String(x.probe_ip)===String(ip));if(!p){toast('该探测记录已不在当前数据中，请刷新后重试',true);return}
 const f=p.last_successful_facts||{},chassis=f.chassis||{};
 const topology={linked:'已纳管，已关联拓扑',managed:'已纳管，未关联拓扑',unassociated:p.last_success_at?'SNMP 可达，未关联拓扑':'未关联拓扑'}[p.topology_status]||'未关联拓扑';
 const next=p.identity_conflict?'等待人工核验身份':p.scope_status!=='allowed'?'停止请求':p.probe_status==='authentication_failed'?'检查 SNMP 认证与访问权限':p.cache_status==='stale'||p.probe_status==='unresponsive'?'后续轮询重试':p.matched_device_id?'按刷新间隔继续核验':'等待核心 / 下游 LLDP 匹配';
 const fields=[['探测结论',probeState(p)],['访问 IP',p.probe_ip],['响应 IP',p.response_ip||'—'],['来源',p.source||'—'],['范围判定',p.scope_status==='allowed'?'在允许范围内':'明确排除 / 范围外'],['身份冲突',p.identity_conflict?'是':'否'],['本机 Chassis',(chassis.subtype!=null?'subtype '+chassis.subtype+' · ':'')+(chassis.raw_hex||'—')],['归一化身份',p.normalized_identity||'身份待核验'],['系统名称',f.sys_name||'—'],['系统 OID',f.sys_object_id||'—'],['型号',p.model||'—'],['型号提示',p.device_kind_hint||'—'],['分类依据',p.classification_rule||'—'],['采集配置',p.profile_name||'—'],['身份缓存',p.cache_status==='fresh'?'新鲜':'待刷新'],['拓扑关联',topology],['关联设备',p.matched_device_id?('设备 #'+p.matched_device_id):'—'],['失败代码',p.failure_code||'—'],['失败原因',p.failure_reason||'—'],['下一步',next],['首次发现',date(p.first_seen_at)],['最近尝试',date(p.last_attempt_at)],['最近成功',date(p.last_success_at)]];
 $('detailContent').innerHTML='<span class="badge '+probeTone(p)+'">'+esc(probeState(p))+'</span><h2 class="mono">'+esc(p.probe_ip)+'</h2><div class="detail-caption">SNMP 探测池记录（按访问 IP 保存，不等同于设备台数）</div>'+detailFields(fields)+'<div class="detail-links"><h3>型号证据（完整系统描述）</h3><p class="detail-pre">'+esc(f.sys_description||'无')+'</p></div><button class="button secondary" data-copy="'+esc(p.probe_ip)+'">复制访问 IP</button><button class="button secondary" data-copy="'+esc(chassis.raw_hex||'')+'">复制 Chassis</button>'+(p.matched_device_id?'<button class="button primary" data-center="'+esc(p.matched_device_id)+'">以此设备为中心查看拓扑</button>':'');
 openDetailPanel(trigger);
}
function showCandidateDetail(key,trigger){
 const n=(state.data?.neighbor_candidates||[]).find(x=>String(x.key)===String(key));if(!n){toast('该邻居记录已不在当前数据中，请刷新后重试',true);return}
 const v=n.verification||{},addresses=(n.reported_management_addresses||[]).join('、')||'未通告';
 const fields=[['邻居状态',n.status||'—'],['设备类型',kindLabel(n.device_kind||'unknown')],['型号',n.model||'—'],['Chassis / 观察标识',n.key],['Chassis 子类型',n.chassis_subtype??'—'],['Chassis 原始值',n.chassis_hex||'—'],['系统描述',n.system_description||'—'],['发现来源',(n.observed_by||[]).join('、')||'—'],['来源设备编号',(n.observed_by_ids||[]).join('、')||'—'],['通告管理地址',addresses],['核验状态',v.verification_status||'未核验'],['本轮核验地址',v.selected_snmp_ip||'—'],['失败代码',v.failure_code||'—'],['失败原因',v.failure_reason||'—'],['最近核验',v.last_verification_at?date(v.last_verification_at):'尚未核验'],['最近观察',date(n.observed_at)]];
 $('detailContent').innerHTML='<span class="badge amber">未知邻居</span><h2>'+esc(n.system_name||'未通告名称')+'</h2><div class="detail-caption">LLDP 邻居记录，不计入已确认设备台数</div>'+detailFields(fields)+'<button class="button secondary" data-copy="'+esc(n.key)+'">复制 Chassis / 观察标识</button><button class="button secondary" data-copy="'+esc(addresses)+'">复制通告地址</button>';
 openDetailPanel(trigger);
}
function openDetailPanel(trigger){const title=$('detailContent').querySelector('h2');if(title)title.id='detailTitle';openDialog('detailPanel','detailBackdrop','closeDetail',trigger)}
function showDeviceDetail(id,trigger){if(String(id).startsWith('probe:')){showProbeDetail(String(id).slice(6),trigger);return}if(String(id).startsWith('candidate:')){showCandidateDetail(String(id).slice(10),trigger);return}if(String(id).startsWith('pending:')){const n=(state.data?.neighbor_candidates||[]).find(n=>'pending:'+n.key===String(id));if(n){$('detailContent').innerHTML=`<span class="badge amber">待核验 ${kindLabel(n.device_kind)}</span><h2>${esc(n.system_name||n.model)}</h2><p class="muted">上游已通过 LLDP 发现，尚未完成本端身份与物理端口核验，暂不计入已确认设备。</p><div class="detail-field"><label>型号</label><div>${esc(n.model)}</div></div><div class="detail-field"><label>通告的 Chassis</label><div>${esc(n.key)}</div></div><div class="detail-field"><label>发现来源</label><div>${esc(n.observed_by.join('、'))}</div></div>`;openDetailPanel(trigger)}return}const d=byID(id);if(!d)return;const links=(state.data.links||[]).filter(l=>String(l.device_a_id)===String(id)||String(l.device_b_id)===String(id));const fields=[['设备类型',kindLabel(d.device_kind||'switch')],['厂商 / 型号',`${d.vendor} / ${d.model}`],['管理地址',addr(d)],['Chassis MAC',mac(d.chassis_mac)],['身份状态',d.identity_state==='verified'?'已核验':'待核验'],['本轮采集',current(d)?'已采集 · '+discoveryLabel(d):'仅有历史记录'],['最近观察',date(d.last_seen_at)],['分类依据',d.classification_rule]];$('detailContent').innerHTML=`<span class="badge ${current(d)?'green':'amber'}">${current(d)?'本轮已采集':'历史设备'}</span><h2>${esc(name(d))}</h2><div class="detail-caption">设备 #${esc(d.id)} · ${links.length} 条物理链路</div><div class="detail-fields">${fields.map(([label,value])=>`<div class="detail-field"><label>${esc(label)}</label><div>${esc(value)}</div></div>`).join('')}</div><button class="button primary" data-center="${esc(d.id)}">以此设备为中心查看拓扑</button><div class="detail-links"><h3>物理连接</h3>${links.map(l=>{const a=String(l.device_a_id)===String(id),peer=byID(a?l.device_b_id:l.device_a_id);return `<div class="detail-link"><b>L${esc(l.id)} · ${esc(name(peer))}</b><small>${esc(port(a?l.port_a_key:l.port_b_key,a?l.port_a_name:l.port_b_name))} ↔ ${esc(port(a?l.port_b_key:l.port_a_key,a?l.port_b_name:l.port_a_name))}</small><small>${l.confidence==='bidirectional'?'双向确认':'单向证据'} · ${l.fresh?'本轮观察':'历史连接'}${l.coverage_gap?' · 有覆盖缺口':''}</small>${interfaceStatusDetail(l)}</div>`}).join('')||'<p class="muted">未确认物理连接，不补画连线。</p>'}</div>`;openDetailPanel(trigger)}
let uplinkCleanup = null;
function showDetail(id, trigger) {
 if (uplinkCleanup) uplinkCleanup();
 uplinkCleanup = null;
 $('detailPanel').classList.remove('has-uplink');
 showDeviceDetail(id, trigger);
 if (!byID(id)) return;
 $('detailContent').querySelector('.detail-links')?.remove();
 const uplink = document.createElement('section');
 $('detailContent').append(uplink);
 $('detailPanel').classList.add('has-uplink');
 uplinkCleanup = GoNetUplink.mount(uplink, id, sessionFetch);
}
function closeDetail() {
 if (uplinkCleanup) uplinkCleanup();
 uplinkCleanup = null;
 $('detailPanel').classList.remove('has-uplink');
 closeDialog('detailPanel');
}
/* ===== 设置页（P5/P6）：草稿 → 校验 → 保存 → 扫描 =====
 * 规则全部来自 ui-settings.js（纯函数，Node 测试覆盖）；这里只负责状态与 DOM。
 * 新增行是表格里的固定一行，脚本只替换数据行，输入框不会被轮询反复重建。 */
const SEGMENT_PAGE=15,EXCLUSION_PAGE=15,SEED_PAGE=15;
const SETTINGS_INPUTS={segmentError:'segmentInput',seedError:'seedInput',exclusionError:'exclusionAddInput'};
const SETTINGS_FIELDS=['segmentInput','seedInput','exclusionAddInput','collectionIntervalValue','collectionIntervalUnit','topologyIntervalValue','topologyIntervalUnit','snmpVersion','snmpCommunity'];
let segmentPager=null,seedPager=null,exclusionPager=null;
const pageOf=(index,size)=>Math.max(0,Math.floor(Math.max(0,index)/size));
function settingsEditing(){const active=document.activeElement;return !!active&&SETTINGS_FIELDS.includes(active.id)}
function syncDraft(force){if(!state.settings)return false;const fingerprint=JSON.stringify(state.settings);if(!force&&fingerprint===state.settingsFingerprint)return false;state.settingsFingerprint=fingerprint;state.draft=GoNetSettings.fromSettings(state.settings);state.scopeDirty=false;state.settingsError='';state.scanError='';state.undo=null;state.editingSegment=null;state.segmentPage=0;state.seedPage=0;state.exclusionPage=0;if(state.drawer&&!state.draft.segments.some(s=>s.uiId===state.drawer))state.drawer=null;return true}
function openSettings(){if(!state.settings)return;syncDraft(!state.draft);renderSettings();updateJob()}
function markDirty(value=true){state.scopeDirty=value;if(value){state.undo=null;state.scanError=''}state.settingsError='';renderSettings();updateJob()}
function showFieldError(errorId,message){const el=$(errorId);if(el){el.hidden=false;el.textContent=message||'无法完成该操作'}const input=$(SETTINGS_INPUTS[errorId]);if(input)input.setAttribute('aria-invalid','true')}
function clearFieldError(errorId){const el=$(errorId);if(el){el.hidden=true;el.textContent=''}const input=$(SETTINGS_INPUTS[errorId]);if(input)input.removeAttribute('aria-invalid')}
function acceptEdit(result,errorId,keepUndo){if(!result||!result.ok){showFieldError(errorId,result&&result.message);return false}clearFieldError(errorId);state.draft=result.draft;state.scopeDirty=true;if(!keepUndo)state.undo=null;state.settingsError='';state.scanError='';return true}
function setUndo(kind,label,key,slot){state.undo={kind:kind,label:label,key:kind+':'+key,slot:slot||'exclusionUndo',snapshot:JSON.stringify(state.draft)}}
function undoEdit(){if(!state.undo)return;state.draft=JSON.parse(state.undo.snapshot);state.scopeDirty=true;state.settingsError='';toast('已撤销：'+state.undo.label);state.undo=null;renderSettings();updateJob()}
function addSegment(){const input=$('segmentInput');const raw=input.value.trim();const result=GoNetSettings.addSegment(state.draft,raw);if(!acceptEdit(result,'segmentError')){input.focus();return}input.value='';state.segmentPage=pageOf(state.draft.segments.length-1,SEGMENT_PAGE);renderSettings();updateJob();input.focus();toast('已添加网段，保存后生效。')}
function startSegmentEdit(uiId){state.editingSegment=uiId;clearFieldError('segmentError');renderSettings();const input=document.querySelector('[data-segment-edit="'+uiId+'"]');if(input){input.focus();input.select()}}
function commitSegmentEdit(uiId){const input=document.querySelector('[data-segment-edit="'+uiId+'"]');if(!input)return;const result=GoNetSettings.editSegment(state.draft,uiId,input.value.trim());if(!result.ok){showFieldError('segmentError',result.message);return}state.editingSegment=null;if(result.unchanged){renderSettings();return}state.draft=result.draft;state.scopeDirty=true;state.undo=null;state.settingsError='';renderSettings();updateJob();toast('网段已修改，保存后生效。')}
function removeSegmentById(uiId){const seg=state.draft.segments.find(s=>s.uiId===uiId);if(!seg)return;setUndo('segment','网段 '+seg.cidr,uiId,'segmentUndo');const result=GoNetSettings.removeSegment(state.draft,uiId);if(!acceptEdit(result,'segmentError',true))return;state.segmentPage=Math.min(state.segmentPage,pageOf(Math.max(0,state.draft.segments.length-1),SEGMENT_PAGE));if(state.drawer===uiId)closeDrawer();renderSettings();updateJob();toast('已删除网段 '+seg.cidr+'。')}
function drawerSegment(){return state.draft&&state.draft.segments.find(s=>s.uiId===state.drawer)||null}
function drawerExclusions(){const seg=drawerSegment();return seg?seg.excludedIPs||[]:[]}
function openDrawer(uiId,trigger){state.drawer=uiId;state.exclusionPage=0;clearFieldError('exclusionError');renderSettings();openDialog('exclusionDrawer','drawerBackdrop','exclusionAddInput',trigger)}
function closeDrawer(){closeDialog('exclusionDrawer');state.drawer=null;renderSettings()}
function addExclusion(){const input=$('exclusionAddInput');const raw=input.value.trim();const result=GoNetSettings.addExclusion(state.draft,state.drawer,raw);if(!acceptEdit(result,'exclusionError')){input.focus();return}input.value='';state.exclusionPage=pageOf(drawerExclusions().length-1,EXCLUSION_PAGE);renderSettings();updateJob();input.focus();toast('已添加排除项，保存后生效。')}
function removeExclusionByKey(key,slot){setUndo('exclusion','排除项 '+key,key,slot);const result=GoNetSettings.removeExclusion(state.draft,key);if(!acceptEdit(result,'exclusionError',true))return;state.exclusionPage=Math.min(state.exclusionPage,pageOf(Math.max(0,drawerExclusions().length-1),EXCLUSION_PAGE));renderSettings();updateJob();toast('已删除排除项，保存后生效。')}
function addSeed(){const input=$('seedInput');const raw=input.value.trim();const result=GoNetSettings.addSeed(state.draft,raw);if(!acceptEdit(result,'seedError')){input.focus();return}input.value='';state.seedPage=pageOf(state.draft.seedIPs.length-1,SEED_PAGE);renderSettings();updateJob();input.focus();toast('已添加起点，保存后生效。')}
function removeSeedByIp(ip){setUndo('seed','起点 '+ip,ip,'seedUndo');const result=GoNetSettings.removeSeed(state.draft,ip);if(!result.ok){state.undo=null;showFieldError('seedError',result.message);renderSettings();return}acceptEdit(result,'seedError',true);state.seedPage=Math.min(state.seedPage,pageOf(Math.max(0,state.draft.seedIPs.length-1),SEED_PAGE));renderSettings();updateJob();toast('已删除起点 '+ip+'，保存后生效。')}
function renderUndo(){const slots={segment:$('segmentUndo'),seed:$('seedUndo'),exclusion:$('exclusionUndo')};const activeId=state.undo?(state.undo.slot||'exclusionUndo'):'';for(const kind of Object.keys(slots)){const el=slots[kind];const active=!!activeId&&el.id===activeId;const markup=active?('<span>已删除 '+esc(state.undo.label)+'</span><button class="text-button" data-undo="1">撤销</button>'):'';if(el.dataset.undoKey===markup)continue;el.dataset.undoKey=markup;el.hidden=!active;el.innerHTML=markup}}
function renderSettingsState(locked,validation){
 $('saveSettings').setAttribute('aria-busy',String(state.settingsSaving));$('saveAndScan').setAttribute('aria-busy',String(state.settingsSaving||state.requesting));
 const status=$('settingsState');status.className='badge '+(state.settingsSaving?'info':state.scopeDirty?'warning':'neutral');status.textContent=state.settingsSaving?'正在保存…':state.scopeDirty?(state.serverSettingsChanged?'有未保存的更改 · 服务端设置已变更':'有未保存的更改'):'已是最新';
 const seeds=state.draft.seedIPs.length;const seedBadge=$('seedState');seedBadge.className='badge '+(seeds?'neutral':'danger');seedBadge.textContent=seeds?seeds+' 个起点':'缺少起点';
 $('settingsDirtyState').textContent=state.scanError||(state.scopeDirty?'有未保存的更改，保存后才会生效':'保存设置不会立即发起扫描');
 $('settingsDirtyState').classList.toggle('dirty',state.scopeDirty&&!state.scanError);
 $('settingsFormError').classList.toggle('hidden',!state.settingsError);$('settingsFormError').textContent=state.settingsError||'';
 $('settingsRetryScan').classList.toggle('hidden',!(state.scanError&&!state.scopeDirty&&!locked));
 for(const id of SETTINGS_FIELDS){const el=$(id);if(el)el.disabled=locked}
 for(const id of ['addSegment','addSeed','exclusionAddButton']){const el=$(id);if(el)el.disabled=locked}
 const warnings=$('settingsWarnings');const list=((validation&&validation.warnings)||[]).filter(w=>w.code!=='legacy_range');warnings.hidden=list.length===0;
 warnings.innerHTML=list.length?('<strong>提示 '+list.length+' 项（不影响保存）</strong><ul>'+list.slice(0,6).map(w=>'<li>'+esc(w.message)+'</li>').join('')+(list.length>6?'<li>还有 '+(list.length-6)+' 项…</li>':'')+'</ul>'):'';
}
function renderSegmentRows(locked){
 const body=$('segmentsBody');const all=state.draft.segments;const result=GoNetPager.paginate(all,state.segmentPage,SEGMENT_PAGE);state.segmentPage=result.pageIndex;
 if(!all.length){body.innerHTML='<tr><td colspan="4"><div class="empty-state" id="segmentsEmpty"><strong>还没有管理 IP 段</strong>先添加一个网段，例如 10.201.109.0/24。</div></td></tr>'}
 else body.innerHTML=result.pageItems.map(seg=>{const p=GoNetSettings.v4Prefix(seg.cidr);const hosts=p?GoNetSettings.intervalHosts([{start:p.start,end:p.end}]):null;const count=(seg.excludedIPs||[]).length;const editing=state.editingSegment===seg.uiId;const cell=editing?`<input class="segment-edit" data-segment-edit="${esc(seg.uiId)}" value="${esc(seg.cidr)}" aria-label="修改管理 IP 段" spellcheck="false" autocomplete="off">`:(`<span class="cell-mono">${esc(seg.cidr)}</span>`+(seg.deferred?' <span class="badge warning">待校验</span>':''));const actions=editing?`<button class="button primary compact" data-segment-save="${esc(seg.uiId)}"${locked?' disabled':''}>保存</button><button class="button secondary compact" data-segment-cancel="1">取消</button>`:`<button class="button secondary compact" data-segment-edit-start="${esc(seg.uiId)}"${locked?' disabled':''}>修改</button><button class="button secondary compact" data-remove-segment="${esc(seg.uiId)}"${locked?' disabled':''}>删除</button>`;return `<tr${editing?' class="row-editor"':''}><td>${cell}</td><td class="cell-note">${hosts===null?'交由后端校验':hosts.toLocaleString('zh-CN')+' 个地址'}</td><td><button class="text-button" data-drawer="${esc(seg.uiId)}"${locked?' disabled':''}>${count?count+' 个排除':'管理排除'}</button></td><td class="col-actions"><div class="row-actions">${actions}</div></td></tr>`}).join('');
 segmentPager=segmentPager||GoNetPager.create($('segmentPager'),{pageSize:SEGMENT_PAGE,unit:'个网段',onPageChange:index=>{state.segmentPage=index;renderSettings()}});
 segmentPager.render(result,{unit:'个网段'});
}
function renderSeedRows(locked){
 const body=$('seedsBody');const all=state.draft.seedIPs;const result=GoNetPager.paginate(all,state.seedPage,SEED_PAGE);state.seedPage=result.pageIndex;
 if(!all.length){body.innerHTML='<tr><td colspan="3"><div class="empty-state" id="seedsEmpty"><strong>还没有发现起点</strong>起点必须在管理 IP 段内且未被排除。</div></td></tr>'}
 else body.innerHTML=result.pageItems.map(seed=>{const index=GoNetSettings.attribute(seed.ip,state.draft.segments);const seg=index>=0?state.draft.segments[index].cidr:'';const status=GoNetSettings.seedStatus(state.draft,seed.ip);const note=seg?`<span class="cell-mono">${esc(seg)}</span>`:`<span class="cell-note">不属于任何网段</span>`;return `<tr><td class="cell-mono">${esc(seed.ip)}</td><td>${note}${status.ok?'':` <span class="badge warning">${esc(status.message)}</span>`}</td><td class="col-actions"><div class="row-actions"><button class="button secondary compact" data-remove-seed="${esc(seed.ip)}"${locked||all.length<=1?' disabled':''}>删除</button></div></td></tr>`}).join('');
 seedPager=seedPager||GoNetPager.create($('seedPager'),{pageSize:SEED_PAGE,unit:'个起点',onPageChange:index=>{state.seedPage=index;renderSettings()}});
 seedPager.render(result,{unit:'个起点'});
}
function renderDrawer(locked){
 const drawer=$('exclusionDrawer');const seg=drawerSegment();
 if(!seg){closeDialog('exclusionDrawer');drawer.classList.add('hidden');$('drawerBackdrop').classList.add('hidden');return}
 $('exclusionTitle').textContent='段内排除';
 $('exclusionSubtitle').textContent=seg.cidr+' · '+(seg.excludedIPs||[]).length+' 个排除 IP · 段内其余地址都会被访问';
 const all=seg.excludedIPs||[];const result=GoNetPager.paginate(all,state.exclusionPage,EXCLUSION_PAGE);state.exclusionPage=result.pageIndex;
 const body=$('exclusionList');
 if(!all.length){body.innerHTML='<tr><td colspan="3"><div class="empty-state" id="exclusionsEmpty"><strong>该网段没有排除 IP</strong>整个网段都会被访问。</div></td></tr>'}
 else body.innerHTML=result.pageItems.map(item=>`<tr><td class="cell-mono">${esc(item.value)}</td><td class="cell-note">${item.deferred?'地址格式待后端校验':'位于本段内，不会被访问'}</td><td class="col-actions"><div class="row-actions"><button class="button secondary compact" data-remove-exclusion="${esc(item.key)}"${locked?' disabled':''}>删除</button></div></td></tr>`).join('');
 exclusionPager=exclusionPager||GoNetPager.create($('exclusionPager'),{pageSize:EXCLUSION_PAGE,unit:'个排除 IP',onPageChange:index=>{state.exclusionPage=index;renderSettings()}});
 exclusionPager.render(result,{unit:'个排除 IP'});

}
function renderSettings(){if(!state.draft)return;
 const locked=!!(state.job&&state.job.running)||state.requesting||state.settingsSaving;
 const key=[state.segmentPage,state.seedPage,state.exclusionPage,state.drawer,state.editingSegment,state.scopeDirty,state.serverSettingsChanged,state.settingsSaving,locked,state.settingsError,state.scanError,state.undo?state.undo.key:'',JSON.stringify(state.draft),JSON.stringify(state.settings?.collection_interval),JSON.stringify(state.settings?.topology_scan_interval)].join('|');
 if(key===state.settingsRenderKey)return;state.settingsRenderKey=key;
 const validation=GoNetSettings.validateDraft(state.draft);
 const active=document.activeElement,mark=focusBookmark(active),hadFocus=active.closest('#region-settings,#exclusionDrawer'),selection=active instanceof HTMLInputElement&&active.type==='text'?{start:active.selectionStart,end:active.selectionEnd}:null;
 renderCollectionFrequency();renderSNMPSettings(locked);renderSettingsState(locked,validation);renderSegmentRows(locked);renderSeedRows(locked);renderDrawer(locked);renderUndo();
 if(hadFocus&&(!active.isConnected||active.closest('.hidden,[hidden]'))){if(!restoreBookmark(mark)){const editId=mark.attr&&mark.attr.startsWith('data-segment-')?mark.value:null;const edit=editId&&[...document.querySelectorAll('[data-segment-edit-start]')].find(el=>el.dataset.segmentEditStart===editId);focusTarget(edit)||focusTarget(activeDialog?$('exclusionAddInput'):listEntry('settings'))}else if(selection&&document.activeElement instanceof HTMLInputElement)document.activeElement.setSelectionRange(selection.start,selection.end)}
}
function renderCollectionFrequency(){
 const interval=state.draft.collectionInterval||{value:4,unit:'minute'};
 const value=$('collectionIntervalValue'),unit=$('collectionIntervalUnit');
 if(value.value!==String(interval.value))value.value=interval.value;
 unit.value=interval.unit;
 $('collectionFrequencyCurrent').textContent='当前采集频率：'+GoNetSettings.collectionFrequency(state.settings?.collection_interval);
 const invalid=!GoNetSettings.validCollectionInterval(interval);$('collectionIntervalError').hidden=!invalid;$('collectionIntervalError').textContent=invalid?'请输入正整数，并选择分、时或日。':'';value.setAttribute('aria-invalid',String(invalid));
 const topology=state.draft.topologyScanInterval||{value:0,unit:'minute'},topologyValue=$('topologyIntervalValue');
 if(topologyValue.value!==String(topology.value))topologyValue.value=topology.value;
 $('topologyIntervalUnit').value=topology.unit;
 $('topologyFrequencyCurrent').textContent='当前扫描频率：'+GoNetSettings.topologyScanFrequency(state.settings?.topology_scan_interval);
 const topologyInvalid=!GoNetSettings.validTopologyScanInterval(topology);$('topologyIntervalError').hidden=!topologyInvalid;$('topologyIntervalError').textContent=topologyInvalid?'请输入 0 或正整数，并选择分、时或日。':'';topologyValue.setAttribute('aria-invalid',String(topologyInvalid));
}
function changeCollectionFrequency(){
 state.draft.collectionInterval={value:$('collectionIntervalValue').value,unit:$('collectionIntervalUnit').value};markDirty();
}
function renderSNMPSettings(locked){
 const s=state.draft.snmp||{version:'2c',community:'',communityConfigured:false},input=$('snmpCommunity');
 $('snmpVersion').value=s.version;
 if(input.value!==(s.community||''))input.value=s.community||'';
 input.disabled=locked;$('snmpVersion').disabled=locked;
 input.placeholder=state.settings?.snmp?.community_configured?'已配置；留空保留现有团体名':'请输入设备的只读团体名';
 $('snmpCurrent').textContent=state.settings?.snmp?.community_configured?'当前团体名：已配置（不回显）':'当前团体名：未配置';
 const error=GoNetSettings.validateDraft(state.draft).errors.find(e=>e.code==='snmp');
 $('snmpError').hidden=!error;$('snmpError').textContent=error?.message||'';input.setAttribute('aria-invalid',String(!!error));
}
function changeSNMPSettings(){
 state.draft.snmp={version:$('snmpVersion').value,community:$('snmpCommunity').value,communityConfigured:!!state.settings?.snmp?.community_configured};markDirty();
}
function changeTopologyScanFrequency(){state.draft.topologyScanInterval={value:$('topologyIntervalValue').value,unit:$('topologyIntervalUnit').value};markDirty()}
function draftPayload(){return GoNetSettings.toSettings(state.draft)}
async function persistSettings(){
 if(!state.draft)return {ok:false,reason:'empty'};
 const trigger=focusBookmark(document.activeElement);
 const validation=GoNetSettings.validateDraft(state.draft);
 if(!validation.ok){state.settingsError='设置未保存，请先修正：'+validation.errors.map(e=>e.message).join('；');renderSettings();toast('设置未保存：还有需要修正的内容。',true);return {ok:false,reason:'validate'}}
 state.settingsSaving=true;state.settingsError='';renderSettings();updateJob();
 try{const result=await request('/api/settings',draftPayload(),'PUT');if(result&&result.settings)state.settings=result.settings;syncDraft(true);toast('设置已保存。');return {ok:true}}
 catch(e){state.settingsError=(e.status===409?'已有更新任务在运行，设置未保存：':'保存失败：')+(e.message||'请求未完成');toast(state.settingsError,true);return {ok:false,reason:'save',status:e.status,error:e.message}}
 finally{state.settingsSaving=false;renderSettings();updateJob();if(document.activeElement===document.body)restoreBookmark(trigger)}
}
async function saveSettings(){const result=await persistSettings();if(result.ok)await refresh()}
async function saveAndScan(){const result=await persistSettings();if(!result.ok)return;await launchScan()}
async function launchScan(){
 if(state.job&&state.job.running){toast('已有更新任务在运行，请等待结束或先取消。',true);await refresh();return}
 state.scanError='';state.requesting=true;renderSettings();updateJob();
 try{state.job=await request('/api/scan',{supplement:false});toast('已开始更新拓扑。')}
 catch(e){state.scanError=(e.status===409?'已有更新任务在运行：':'设置已保存，扫描未启动：')+(e.message||'请求未完成');toast(state.scanError,true)}
 finally{state.requesting=false;renderSettings();updateJob();await refresh()}
}
async function downloadDevices(){
 try{const response=await sessionFetch('/api/devices.csv?ids='+encodeURIComponent(filteredDevices().map(d=>d.id).join(',')));if(!response.ok)throw Error('暂时无法导出设备列表');const blob=await response.blob();if(redirecting)return;const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='GoNet-设备列表.csv';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000)}catch(e){if(!redirecting)toast(e.message,true)}
}
document.addEventListener('click',e=>{const page=e.target.closest('[data-page]');if(page){navigate(page.dataset.page);return}const center=e.target.closest('[data-center]');if(center){state.focus=center.dataset.center;$('focusDevice').value=String(state.focus);state.graphMode='focus';closeDetail();navigate('topology');renderMainGraph();mainTopology.locate(state.focus);focusTarget($('focusDevice'));return}const device=e.target.closest('[data-device],[data-node]');if(device){if(device.dataset.node){miniTopology?.select(device.dataset.node);mainTopology?.select(device.dataset.node)}showDetail(device.dataset.device||device.dataset.node,device.matches(FOCUSABLE)?device:device.querySelector(FOCUSABLE));return}const mode=e.target.closest('[data-graph-mode]');if(mode){state.graphMode=mode.dataset.graphMode;renderMainGraph();mainTopology.reset();return}
 const clear=e.target.closest('[data-clear]');if(clear){clearListFilters(clear.dataset.clear);return}
 const retry=e.target.closest('[data-retry]');if(retry){retryRegion(retry.dataset.retry);return}
 const copy=e.target.closest('[data-copy]');if(copy){copyValue(copy.dataset.copy);return}
 const probe=e.target.closest('[data-probe]');if(probe){showDetail('probe:'+probe.dataset.probe,probe.matches(FOCUSABLE)?probe:probe.querySelector(FOCUSABLE));return}
 const candidate=e.target.closest('[data-candidate]');if(candidate){showDetail('candidate:'+candidate.dataset.candidate,candidate.matches(FOCUSABLE)?candidate:candidate.querySelector(FOCUSABLE));return}
 const settings=e.target.closest('[data-drawer],[data-remove-segment],[data-segment-edit-start],[data-segment-save],[data-segment-cancel],[data-remove-seed],[data-remove-exclusion],[data-undo]');if(!settings)return;
 if(settings.dataset.drawer)openDrawer(settings.dataset.drawer,settings);
 else if(settings.dataset.removeSegment)removeSegmentById(settings.dataset.removeSegment);
 else if(settings.dataset.segmentEditStart)startSegmentEdit(settings.dataset.segmentEditStart);
 else if(settings.dataset.segmentSave)commitSegmentEdit(settings.dataset.segmentSave);
 else if(settings.dataset.segmentCancel)state.editingSegment=null,renderSettings();
 else if(settings.dataset.removeSeed)removeSeedByIp(settings.dataset.removeSeed);
 else if(settings.dataset.removeExclusion)removeExclusionByKey(settings.dataset.removeExclusion,'exclusionUndo');
 else if(settings.dataset.undo)undoEdit()});
document.addEventListener('keydown',e=>{if(e.key==='Escape'){if(state.drawer)closeDrawer();if(state.editingSegment)state.editingSegment=null,renderSettings();closeDetail()}if((e.key==='Enter'||e.key===' ')&&e.target.matches('[data-node]')){e.preventDefault();showDetail(e.target.dataset.node,e.target)}
 if(e.key==='Enter'&&e.target.matches('[data-segment-edit]')){e.preventDefault();commitSegmentEdit(e.target.dataset.segmentEdit)}});
$('closeToast').addEventListener('click',dismissToast);
$('scanButton').addEventListener('click',()=>{if(state.scopeDirty){navigate('settings');toast('有未保存的设置，请先保存或使用“保存并更新拓扑”。',true);return}launchScan()});
$('cancelScan').addEventListener('click',async()=>{try{await request('/api/cancel',{});await refresh()}catch(e){toast(e.message,true)}});
$('closeDetail').addEventListener('click',closeDetail);$('detailBackdrop').addEventListener('click',closeDetail);
$('topologyIntervalValue').addEventListener('input',changeTopologyScanFrequency);$('topologyIntervalUnit').addEventListener('change',changeTopologyScanFrequency);
$('snmpVersion').addEventListener('change',changeSNMPSettings);$('snmpCommunity').addEventListener('input',changeSNMPSettings);
$('collectionIntervalValue').addEventListener('input',changeCollectionFrequency);$('collectionIntervalUnit').addEventListener('change',changeCollectionFrequency);
$('saveSettings').addEventListener('click',saveSettings);$('saveAndScan').addEventListener('click',saveAndScan);$('settingsRetryScan').addEventListener('click',launchScan);
$('addSegment').addEventListener('click',addSegment);$('addSeed').addEventListener('click',addSeed);$('exclusionAddButton').addEventListener('click',addExclusion);
for(const id of ['segmentInput','seedInput','exclusionAddInput']){$(id).addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();({segmentInput:addSegment,seedInput:addSeed,exclusionAddInput:addExclusion})[id]()}})}
$('closeExclusion').addEventListener('click',closeDrawer);$('drawerBackdrop').addEventListener('click',closeDrawer);
/* 列表页筛选：作用于完整数据，改动后回到第 1 页（合同 §5.3） */
for(const id of ['deviceSearch','vendorFilter','kindFilter','statusFilter'])$(id).addEventListener(id==='deviceSearch'?'input':'change',()=>{state.devicePage=0;renderDevices()});
$('candidateSearch').addEventListener('input',()=>{state.candidatePage=0;renderCandidates()});
$('downloadDevices').addEventListener('click',downloadDevices);
$('focusDevice').addEventListener('change',()=>{state.focus=$('focusDevice').value;if(state.graphMode==='focus')renderMainGraph();mainTopology?.locate(state.focus)});
$('topologySearch').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();locateTopology()}});$('topologyLocate').addEventListener('click',locateTopology);
$('zoomIn').addEventListener('click',()=>mainTopology?.zoom(1.2));$('zoomOut').addEventListener('click',()=>mainTopology?.zoom(1/1.2));$('zoomFit').addEventListener('click',()=>mainTopology?.fit());$('zoomReset').addEventListener('click',()=>mainTopology?.reset());$('zoomFullscreen').addEventListener('click',()=>mainTopology?.fullscreen($('region-topology')));$('expandBranches').addEventListener('click',()=>mainTopology?.expandAll());
$('probeSearch').addEventListener('input',()=>{state.probePage=0;renderProbes()});
$('downloadProbes').addEventListener('click',()=>{const url=URL.createObjectURL(new Blob([JSON.stringify({summary:state.data?.probe_summary,records:state.data?.probe_pool},null,2)],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download='gonet-snmp-probes.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)});
async function initializeSession(){
 if(redirecting)return;
 const main=document.querySelector('main'),sidebar=document.querySelector('aside.sidebar');main.inert=true;sidebar.inert=true;
 try{
  const response=await sessionFetch('/api/v1/auth/me',{cache:'no-store'});if(!response.ok)throw Error('暂时无法检查登录状态，请重试');const session=await response.json();if(redirecting)return;
  state.token=session.csrf_token;$('adminUsername').textContent=session.user.username;sessionReady=true;main.inert=false;sidebar.inert=false;
  const page=new URLSearchParams(location.search).get('page');navigate(pages[page]?page:'overview');await refresh();if(!redirecting)pollTimer=setInterval(refresh,2500);
 }catch(e){if(redirecting)return;main.inert=false;const box=$('connectionError');box.textContent=e.message||'网络不可用，请重试';box.classList.remove('hidden');const retry=document.createElement('button');retry.className='button secondary compact';retry.textContent='重试登录检查';retry.onclick=initializeSession;box.append(' ',retry)}
}
$('logoutButton').addEventListener('click',async()=>{if(redirecting)return;$('logoutButton').disabled=true;try{await request('/api/v1/auth/logout',{});clearSession('/')}catch(e){if(!redirecting){$('logoutButton').disabled=false;toast(e.message,true)}}});
window.addEventListener('popstate',()=>{if(sessionReady&&!redirecting){const page=new URLSearchParams(location.search).get('page');navigate(pages[page]?page:'overview')}});
window.addEventListener('pageshow',event=>{if(event.persisted)location.reload()});
apiManagement=GoNetAPI.create({fetch:sessionFetch,request,notify:toast});
initializeSession();
