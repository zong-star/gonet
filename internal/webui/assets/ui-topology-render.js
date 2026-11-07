/* SVG node/edge rendering and camera interaction; data remains read-only. */
(function(root){'use strict';
 const NS='http://www.w3.org/2000/svg',L=root.GoNetTopologyLayout;
 const el=(tag,attrs={},text)=>{const n=document.createElementNS(NS,tag);for(const[k,v]of Object.entries(attrs))n.setAttribute(k,String(v));if(text!=null)n.textContent=text;return n};
 const label=d=>d.inventory_name||d.sys_name||('设备 #'+d.id),address=d=>d.access_addresses?.[0]||'无已验证地址';
 let measure;
 function truncate(value,units=20){const text=String(value||'');measure=measure||document.createElement('canvas').getContext('2d');measure.font='11px '+getComputedStyle(document.body).fontFamily;const width=units*5.5;if(measure.measureText(text).width<=width)return text;const chars=Array.from(text);let lo=0,hi=chars.length;while(lo<hi){const mid=Math.ceil((lo+hi)/2);if(measure.measureText(chars.slice(0,mid).join('')+'…').width<=width)lo=mid;else hi=mid-1}return chars.slice(0,lo).join('')+'…'}

 function symbol(kind){if(kind==='router')return 'M-10-10 -3-3 M-10-5 -10-10 -5-10 M10-10 3-3 M5-10 10-10 10-5 M-10 10 -3 3 M-10 5 -10 10 -5 10 M10 10 3 3 M5 10 10 10 10 5';if(kind==='wireless_controller')return 'M-12-4 Q0-15 12-4 M-8 0 Q0-8 8 0 M-4 4 Q0 0 4 4 M0 8 0 9';return 'M-12-5 H12 M7-9 12-5 7-1 M12 6 H-12 M-7 2 -12 6 -7 10 M-7-5 V-1 M-1-5 V-1 M5 2 V6'}
 class Viewer{
  constructor(host,options={}){
   this.host=host;this.options=options;this.collapsed=new Set();this.layouts=new Map();this.selected=null;this.view={x:0,y:0,k:1};this.initialized=false;this.autoFit=false;this.frame=0;this.renderCount=0;
   this.svg=el('svg',{role:'group','aria-label':options.mini?'核心连接概览':'纵向分层网络拓扑'});this.world=el('g',{class:'nms-world'});this.svg.append(this.world);host.replaceChildren(this.svg);host.classList.add('nms-canvas');
   if(!options.mini){host.tabIndex=0;host.setAttribute('aria-label','网络拓扑画布，滚轮缩放，拖动平移，方向键移动，0适应画布');this.bind()}
   this.observer=new ResizeObserver(()=>{const w=host.clientWidth,h=host.clientHeight;if(!w||!h)return;this.svg.setAttribute('viewBox',`0 0 ${w} ${h}`);if(this.layout){if(options.mini||this.autoFit)this.fit();else if(!this.initialized)this.reset();else if(this.lastWidth)this.view.x+=(w-this.lastWidth)/2;this.schedule()}this.lastWidth=w});this.observer.observe(host);
  }
  update(input,cacheKey='all'){
   this.input=input;if(this.selected&&!input.nodes.some(n=>String(n.id)===this.selected))this.selected=null;this.cacheKey=cacheKey;const prev=this.layouts.get(cacheKey);this.layout=L.layout(input,{previous:prev,collapsed:this.collapsed});this.layouts.set(cacheKey,this.layout);this.render();
   if(this.options.mini||this.autoFit)this.fit();else if(!this.initialized)this.reset();else this.schedule();return this.layout;
  }
  render(){
   const layout=this.layout;if(!layout)return;const fragment=document.createDocumentFragment(),edgeLayer=el('g',{class:'nms-edges'}),nodeLayer=el('g',{class:'nms-nodes'});
   for(const edge of layout.edges){const a=this.input.nodes.find(n=>String(n.id)===edge.a),b=this.input.nodes.find(n=>String(n.id)===edge.b),count=edge.links?.length||0;
    const g=el('g',{class:'nms-connection'+(edge.pending?' pending':edge.links?.every(l=>!l.fresh)?' historical':''),'data-edge':edge.key,tabindex:this.options.mini?'-1':'0',role:'button','aria-label':`${label(a||{})} 与 ${label(b||{})}，${edge.pending?'LLDP 观察，物理连接未核验':count+' 条物理链路，查看明细'}`});
    g.append(el('title',{},edge.pending?'LLDP观察；不作为已确认物理链路':(edge.links||[]).map(l=>`L${l.id} · ${l.port_a_name||l.port_a_key} ↔ ${l.port_b_name||l.port_b_key} · ${l.confidence==='bidirectional'?'双向确认':'单向证据'} · ${l.fresh?'本轮':'历史'} · 运行 ${l.link_oper_status||'unknown'} · A ${l.source_admin_status||'unknown'}/${l.source_oper_status||'unknown'} ↔ B ${l.target_admin_status||'unknown'}/${l.target_oper_status||'unknown'}`).join('\n')));
    const status=edge.links?.[0]?.link_oper_status||'unknown';g.dataset.operStatus=status;
    if(edge.aggregation){g.classList.add('aggregate');g.dataset.aggregateId=edge.aggregation.aggregate_id;let color=0;for(const c of [edge.aggregation.group_a.group_id,edge.aggregation.group_b.group_id].sort().join('|'))color=(color*31+c.charCodeAt(0))>>>0;g.style.setProperty('--lag-color',`hsl(${color%360} 48% 42%)`);}
    g.append(el('path',{d:edge.path,class:'nms-edge-hit'}),el('path',{d:edge.path,class:'nms-edge'}));
    if(edge.aggregation&&String(edge.aggregation.member_link_ids[0])===String(edge.links[0]?.id))g.append(el('text',{x:edge.label.x,y:edge.label.y,class:'nms-edge-count'},`聚合 · ${edge.aggregation.member_link_ids.length} 条${edge.aggregation.status==='inferred'?' · 对端推断':''}`));
    if(count>1)g.append(el('text',{x:edge.label.x,y:edge.label.y,class:'nms-edge-count'},String(count)));edgeLayer.append(g);
   }
   for(const node of layout.nodes){const d=node.data,kind=d.device_kind||'switch',historical=d.collection_status!=='collected'&&!d.is_pending;
    const g=el('g',{class:`nms-node kind-${kind}${historical?' historical':''}${d.is_pending?' pending':''}${this.selected===node.id?' selected':''}`,'data-node':node.id,transform:`translate(${node.x} ${node.y})`,role:'button',tabindex:'0','aria-label':label(d)+'，'+address(d)+'，查看详情'});
    g.append(el('title',{},[label(d),(d.access_addresses||[]).join(', ')||'无已验证地址',d.model||'',d.is_pending?'LLDP观察，本端身份尚未核验':historical?'历史记录':'本轮已采集',node.collapsed?'已折叠 '+node.descendants+' 个下游设备':''].filter(Boolean).join('\n')));
    g.append(el('circle',{cx:0,cy:20,r:24,class:'nms-selection'}),el('circle',{cx:0,cy:20,r:20,class:'nms-icon'}));
    g.append(el('path',{d:symbol(kind),transform:'translate(0 20)',class:'nms-symbol'}));
    g.append(el('text',{x:0,y:55,class:'nms-name','text-anchor':'middle'},truncate(label(d))),el('text',{x:0,y:70,class:'nms-ip','text-anchor':'middle'},truncate(address(d),20)));nodeLayer.append(g);
    if(node.children&&!this.options.mini){const toggle=el('g',{class:'nms-collapse',transform:`translate(${node.x+29} ${node.y+8})`,'data-collapse':node.id,role:'button',tabindex:'0','aria-expanded':String(!node.collapsed),'aria-label':(node.collapsed?'展开':'折叠')+label(d)+'的下游分支，共'+node.descendants+'台'});toggle.append(el('title',{},(node.collapsed?'展开':'折叠')+'下游分支'),el('rect',{x:-7,y:-7,width:14,height:14,rx:2}),el('path',{d:node.collapsed?'M-4 0 H4 M0-4 V4':'M-4 0 H4'}));if(node.collapsed)toggle.append(el('text',{x:11,y:4,class:'nms-collapse-count'},'+'+node.descendants));nodeLayer.append(toggle)}
   }
   if(!layout.nodes.length)fragment.append(el('text',{x:28,y:55,class:'nms-empty'},'配置起点后更新拓扑，即可查看连接。'));
   const active=document.activeElement,focusNode=active?.closest('[data-node]')?.getAttribute('data-node'),focusCollapse=active?.closest('[data-collapse]')?.getAttribute('data-collapse');const restore=this.host.contains(active);
   fragment.append(edgeLayer,nodeLayer);this.world.replaceChildren(fragment);this.host.dataset.renderCount=String(++this.renderCount);this.host.dataset.visibleNodes=String(layout.nodes.length);this.host.dataset.visibleEdges=String(layout.edges.length);
   if(restore&&(focusNode||focusCollapse)){const attr=focusCollapse?'data-collapse':'data-node',id=focusCollapse||focusNode;[...this.world.querySelectorAll('['+attr+']')].find(n=>n.getAttribute(attr)===id)?.focus({preventScroll:true})}
   this.options.onLayout?.(layout);
  }
  dispose(){this.observer.disconnect();if(this.frame)cancelAnimationFrame(this.frame);this.frame=0;this.input=null;this.layout=null;this.layouts.clear();this.collapsed.clear();this.selected=null;this.drag=null;this.expandedPanel=null;this.options={};this.world.replaceChildren()}
  schedule(){if(this.frame)return;this.frame=requestAnimationFrame(()=>{this.frame=0;this.paint()})}
  paint(){const{host,svg,view}=this,w=host.clientWidth,h=host.clientHeight;if(!w||!h)return;svg.setAttribute('viewBox',`0 0 ${w} ${h}`);this.world.setAttribute('transform',`translate(${view.x} ${view.y}) scale(${view.k})`);host.dataset.detail=view.k<.38?'structure':view.k<.65?'names':'full';this.options.onView?.({...view});}
  zoom(factor,point){if(!this.layout)return;this.autoFit=false;const p=point||{x:this.host.clientWidth/2,y:this.host.clientHeight/2},old=this.view.k,k=Math.min(3,Math.max(.001,old*factor));this.view.x=p.x-(p.x-this.view.x)/old*k;this.view.y=p.y-(p.y-this.view.y)/old*k;this.view.k=k;this.schedule()}
  fit(){if(!this.layout||!this.host.clientWidth||!this.host.clientHeight)return;this.autoFit=!this.options.mini;const b={...this.layout.bounds};for(const e of this.layout.edges)for(const p of e.points){const right=Math.max(b.x+b.width,p.x+12),bottom=Math.max(b.y+b.height,p.y+12);b.x=Math.min(b.x,p.x-12);b.y=Math.min(b.y,p.y-12);b.width=right-b.x;b.height=bottom-b.y}const w=this.host.clientWidth,h=this.host.clientHeight,k=Math.min(this.options.mini?1.1:1.2,Math.max(.001,Math.min((w-36)/b.width,(h-36)/b.height)));this.view={k,x:(w-b.width*k)/2-b.x*k,y:24-b.y*k};this.initialized=true;this.schedule()}
  reset(){if(!this.layout||!this.host.clientWidth)return;this.autoFit=false;const rootId=this.layout.roots.find(id=>this.layout.nodes.some(n=>n.id===id)),p=this.layout.positions[rootId]||{x:200,y:48};this.view={k:1,x:this.host.clientWidth/2-p.x,y:32-p.y};this.initialized=true;this.schedule()}
  select(id){this.selected=String(id);for(const n of this.world.querySelectorAll('[data-node]'))n.classList.toggle('selected',n.getAttribute('data-node')===this.selected)}
  locate(id){id=String(id);if(!this.layout?.positions[id])return false;let ancestor=this.layout.parent[id],changed=false;while(ancestor){changed=this.collapsed.delete(ancestor)||changed;ancestor=this.layout.parent[ancestor]}if(changed)this.update(this.input,this.cacheKey);this.select(id);const p=this.layout.positions[id];this.autoFit=false;this.view.k=Math.max(.75,this.view.k);this.view.x=this.host.clientWidth/2-p.x*this.view.k;this.view.y=this.host.clientHeight/2-(p.y+30)*this.view.k;this.schedule();return true}
  toggle(id){id=String(id);this.collapsed.has(id)?this.collapsed.delete(id):this.collapsed.add(id);this.update(this.input,this.cacheKey)}
  expandAll(){if(!this.collapsed.size)return;this.collapsed.clear();this.update(this.input,this.cacheKey)}
  async fullscreen(panel){const active=panel.classList.contains('nms-expanded');if(active){panel.classList.remove('nms-expanded');if(document.fullscreenElement)await document.exitFullscreen().catch(()=>{});this.options.onFullscreen?.(false);return}panel.classList.add('nms-expanded');this.expandedPanel=panel;this.options.onFullscreen?.(true);try{await document.documentElement.requestFullscreen()}catch{}this.schedule()}
  bind(){const host=this.host;
   host.addEventListener('wheel',e=>{e.preventDefault();const r=host.getBoundingClientRect();this.zoom(Math.exp(-Math.max(-250,Math.min(250,e.deltaY*(e.deltaMode===1?16:1)))*.0015),{x:e.clientX-r.left,y:e.clientY-r.top})},{passive:false});
   host.addEventListener('pointerdown',e=>{if(e.button!==0||e.target.closest('[data-node],[data-collapse],[data-edge]'))return;e.preventDefault();host.focus({preventScroll:true});this.autoFit=false;this.drag={id:e.pointerId,x:e.clientX,y:e.clientY,tx:this.view.x,ty:this.view.y};host.setPointerCapture(e.pointerId);host.classList.add('dragging')});
   host.addEventListener('pointermove',e=>{if(!this.drag||e.pointerId!==this.drag.id)return;this.view.x=this.drag.tx+e.clientX-this.drag.x;this.view.y=this.drag.ty+e.clientY-this.drag.y;this.schedule()});
   const end=()=>{this.drag=null;host.classList.remove('dragging')};for(const type of ['pointerup','pointercancel','lostpointercapture'])host.addEventListener(type,end);
   host.addEventListener('keydown',e=>{const control=e.target.closest('[data-collapse],[data-node],[data-edge]');if(control&&(e.key==='Enter'||e.key===' ')){e.preventDefault();e.stopPropagation();this.activate(control);return}if(control)return;const directions={ArrowLeft:[40,0],ArrowRight:[-40,0],ArrowUp:[0,40],ArrowDown:[0,-40]};if(directions[e.key]){e.preventDefault();this.autoFit=false;this.view.x+=directions[e.key][0];this.view.y+=directions[e.key][1];this.schedule()}else if(e.key==='+'||e.key==='='){e.preventDefault();this.zoom(1.2)}else if(e.key==='-'){e.preventDefault();this.zoom(1/1.2)}else if(e.key==='0'){e.preventDefault();this.fit()}});
   host.addEventListener('click',e=>{const control=e.target.closest('[data-collapse],[data-node],[data-edge]');if(!control)return;e.stopPropagation();this.activate(control)});
   document.addEventListener('fullscreenchange',()=>{if(!document.fullscreenElement&&this.expandedPanel){this.expandedPanel.classList.remove('nms-expanded');this.options.onFullscreen?.(false);this.schedule()}});
   document.addEventListener('keydown',e=>{if(e.key==='Escape'&&this.expandedPanel?.classList.contains('nms-expanded')&&!document.querySelector('[role=dialog]:not(.hidden)'))this.fullscreen(this.expandedPanel)});
  }
  activate(control){if(control.hasAttribute('data-collapse')){this.toggle(control.getAttribute('data-collapse'));return}if(control.hasAttribute('data-node')){const id=control.getAttribute('data-node');this.select(id);this.options.onNode?.(id,control);return}const edge=this.layout.edges.find(e=>e.key===control.getAttribute('data-edge'));if(edge)this.options.onEdge?.(edge,control)}
 }
 root.GoNetTopology={create:(host,options)=>new Viewer(host,options),truncate};
})(typeof self!=='undefined'?self:this);
