/* Pure deterministic display layout. No discovery, identity or link mutation. */
(function(root,factory){const api=factory();if(typeof module==='object'&&module.exports)module.exports=api;else root.GoNetTopologyLayout=api})(typeof self!=='undefined'?self:this,function(){
 'use strict';
 const DEFAULTS=Object.freeze({icon:40,nodeWidth:116,nodeHeight:80,siblingGap:28,subtreeGap:28,componentGap:100,levelGap:76,trackGap:6,padding:48});
 const cmp=(a,b)=>String(a).localeCompare(String(b),'en',{numeric:true});
 const path=points=>points.map((p,i)=>(i?'L':'M')+p.x+' '+p.y).join(' ');
 function descendants(id,children){const found=[],queue=[...(children[id]||[])];for(let i=0;i<queue.length;i++){found.push(queue[i]);queue.push(...(children[queue[i]]||[]))}return found}
 function bounds(nodes,cfg=DEFAULTS){if(!nodes.length)return{x:0,y:0,width:400,height:240};const xs=nodes.map(p=>p.x),ys=nodes.map(p=>p.y);const x=Math.min(...xs)-cfg.nodeWidth/2-24,y=Math.min(...ys)-32;return{x,y,width:Math.max(...xs)-x+cfg.nodeWidth/2+24,height:Math.max(...ys)-y+cfg.nodeHeight+24}}
 function physicalEdges(links,aggregations=[]){
  const groups=new Map();for(const group of aggregations.filter(g=>['confirmed','inferred'].includes(g.status)))for(const id of group.member_link_ids||[])groups.set(String(id),group);
  return (links||[]).map(link=>({key:'link:'+String(link.id),a:String(link.device_a_id),b:String(link.device_b_id),links:[link],aggregation:groups.get(String(link.id))||null}));
 }
 function layout(input,options={}){
  const cfg={...DEFAULTS,...options.config},previous=options.previous||{},old=previous.positions||{},byId=new Map((input.nodes||[]).map(n=>[String(n.id),n]));
  const ids=[...byId.keys()].sort(cmp),edges=(input.edges||[]).filter(e=>byId.has(String(e.a))&&byId.has(String(e.b))).map(e=>({...e,a:String(e.a),b:String(e.b),key:e.key||[String(e.a),String(e.b)].sort(cmp).join('|')})).sort((a,b)=>cmp(a.key,b.key));
  const adj=new Map(ids.map(id=>[id,[]]));for(const e of edges){if(e.a!==e.b){adj.get(e.a).push(e.b);adj.get(e.b).push(e.a)}}for(const list of adj.values())list.sort(cmp);
  const rank=Object.create(null),parent=Object.create(null),children=Object.create(null),positions=Object.create(null),roots=[];
  const preferred=[...new Set((input.roots||[]).map(String))].filter(id=>byId.has(id));
  function visit(seedList){const queue=[];for(const id of seedList)if(rank[id]===undefined){rank[id]=0;roots.push(id);queue.push(id)}for(let i=0;i<queue.length;i++){const id=queue[i];for(const peer of adj.get(id)){if(byId.get(peer).is_pending)continue;if(rank[peer]===undefined){rank[peer]=rank[id]+1;queue.push(peer)}}}}
  visit(preferred.length?preferred:ids.filter(id=>!byId.get(id).is_pending).slice(0,1));for(const id of ids)if(rank[id]===undefined&&!byId.get(id).is_pending)visit([id]);for(const id of ids)if(rank[id]===undefined){const owners=adj.get(id).filter(p=>rank[p]!==undefined&&!byId.get(p).is_pending);rank[id]=owners.length?Math.min(...owners.map(p=>rank[p]))+1:0;if(!owners.length)roots.push(id)}
  for(const id of ids){children[id]=[];parent[id]=null;if(rank[id]>0){const candidates=adj.get(id).filter(p=>rank[p]===rank[id]-1&&!byId.get(p).is_pending);const saved=previous.parent?.[id];parent[id]=candidates.includes(saved)?saved:candidates.sort((a,b)=>(old[a]?.x??Infinity)-(old[b]?.x??Infinity)||cmp(a,b))[0]}}
  for(const id of ids)if(parent[id]!=null)children[parent[id]].push(id);
  const ordered=(a,b)=>{if(old[a]&&old[b])return old[a].x-old[b].x||cmp(a,b);if(old[a])return -1;if(old[b])return 1;return cmp(a,b)};
  roots.sort((a,b)=>preferred.indexOf(a)>=0&&preferred.indexOf(b)<0?-1:preferred.indexOf(b)>=0&&preferred.indexOf(a)<0?1:ordered(a,b));for(const list of Object.values(children))list.sort(ordered);
  const spans=Object.create(null),ideal=Object.create(null),deepest=ids.reduce((v,id)=>Math.max(v,rank[id]),0);
  for(const id of ids.slice().sort((a,b)=>rank[b]-rank[a]||cmp(a,b))){const cs=children[id];spans[id]=Math.max(cfg.nodeWidth,cs.reduce((n,c)=>n+spans[c],0)+Math.max(0,cs.length-1)*cfg.subtreeGap)}
  let left=cfg.padding;const stack=[];for(const id of roots){stack.push({id,left});left+=spans[id]+cfg.componentGap}
  while(stack.length){const n=stack.pop(),cs=children[n.id];ideal[n.id]=n.left+spans[n.id]/2;let x=n.left+(spans[n.id]-(cs.reduce((v,c)=>v+spans[c],0)+Math.max(0,cs.length-1)*cfg.subtreeGap))/2;for(const id of cs){stack.push({id,left:x});x+=spans[id]+cfg.subtreeGap}}
  // Existing row positions are anchors. New devices take the nearest free slot;
  // a full scan with unchanged identities never shuffles the existing forest.
  const pitch=cfg.nodeWidth+cfg.siblingGap,levels=Array.from({length:deepest+1},()=>[]);
  for(const id of ids)levels[rank[id]].push(id);
  for(const list of levels){const used=[];for(const id of list)if(old[id]&&old[id].level===rank[id]){positions[id]={x:old[id].x,level:rank[id]};used.push(old[id].x)}
   for(const id of list.filter(id=>!positions[id]).sort((a,b)=>ideal[a]-ideal[b]||cmp(a,b))){const desired=old[id]?.x??(previous.positions&&parent[id]?positions[parent[id]]?.x??ideal[id]:ideal[id]);const free=x=>x>=cfg.padding+cfg.nodeWidth/2&&used.every(v=>Math.abs(x-v)>=pitch-0.01);let x=desired;if(!free(x)){const candidates=[cfg.padding+cfg.nodeWidth/2,...used.flatMap(v=>[v-pitch,v+pitch])].filter(free).sort((a,b)=>Math.abs(a-desired)-Math.abs(b-desired)||a-b);x=candidates[0]??Math.max(0,...used)+pitch}positions[id]={x,level:rank[id]};used.push(x)}
  }
  const same=Array(deepest+1).fill(0),cross=Array(deepest+1).fill(0);
  const isTree=e=>parent[e.b]===e.a||parent[e.a]===e.b;
  for(const e of edges){if(rank[e.a]===rank[e.b])same[rank[e.a]]++;else if(!isTree(e))cross[Math.min(rank[e.a],rank[e.b])]++}
  const rowY=[Math.max(cfg.padding+same[0]*cfg.trackGap,previous.rowY?.[0]||0)];
  for(let i=1;i<=deepest;i++){const gap=Math.max(cfg.levelGap,56+(same[i]+cross[i-1])*cfg.trackGap);rowY[i]=rowY[i-1]+Math.max(cfg.nodeHeight+gap,(previous.rowY?.[i]||0)-(previous.rowY?.[i-1]||0))}
  for(const id of ids)Object.assign(positions[id],{id,y:rowY[rank[id]],width:cfg.nodeWidth,height:cfg.nodeHeight});
  let width=Math.max(400,...ids.map(id=>positions[id].x+cfg.nodeWidth/2+cfg.padding)),height=Math.max(240,...rowY.map(y=>y+cfg.nodeHeight+cfg.padding));
  const sameLane=Array(deepest+1).fill(0),crossLane=Array(deepest+1).fill(0),routed=[];let outer=0;
  const parallel=new Map(),pairKey=e=>[e.a,e.b].sort(cmp).join('|');for(const e of edges){const k=pairKey(e);if(!parallel.has(k))parallel.set(k,[]);parallel.get(k).push(e.key)}
  for(const e of edges){let a=positions[e.a],b=positions[e.b];if(a.level>b.level||a.level===b.level&&a.x>b.x)[a,b]=[b,a];const tree=isTree(e)&&a.level!==b.level,side=tree?1:b.x<a.x?-1:1,sx=a.x+side*(cfg.nodeWidth/2+8);let points,label;
   if(a.level===b.level){const bus=a.y-18-sameLane[a.level]++*cfg.trackGap;points=[{x:a.x,y:a.y+cfg.icon},{x:a.x,y:a.y+44},{x:sx,y:a.y+44},{x:sx,y:bus},{x:b.x,y:bus},{x:b.x,y:b.y}];label={x:(sx+b.x)/2,y:bus-4}}
   else if(b.level===a.level+1){const bus=tree?a.y+cfg.nodeHeight+14:b.y-18-(same[b.level]+crossLane[a.level]++)*cfg.trackGap;points=[{x:a.x,y:a.y+cfg.icon},{x:a.x,y:a.y+44},{x:sx,y:a.y+44},{x:sx,y:bus},{x:b.x,y:bus},{x:b.x,y:b.y}];label={x:b.x+8,y:b.y-9}}
   else{const lane=width+24+outer++*10;points=[{x:a.x,y:a.y+cfg.icon},{x:a.x,y:a.y+44},{x:sx,y:a.y+44},{x:sx,y:a.y+cfg.nodeHeight+14},{x:lane,y:a.y+cfg.nodeHeight+14},{x:lane,y:b.y-18},{x:b.x,y:b.y-18},{x:b.x,y:b.y}];label={x:lane+5,y:(a.y+b.y)/2};width=Math.max(width,lane+36)}
   const siblings=parallel.get(pairKey(e)),lane=siblings.indexOf(e.key),offset=siblings.length>1?Math.max(-16,Math.min(16,(lane-(siblings.length-1)/2)*8)):0;
   if(siblings.length>1){
    const sourceX=a.x+offset,targetX=b.x+offset;
    points=points.map(p=>({...p}));points[0].x=sourceX;points[1].x=sourceX;
    points[points.length-1].x=targetX;points[points.length-2].x=targetX;
    if(tree){points[2].x+=lane*cfg.trackGap;points[3].x+=lane*cfg.trackGap;points[3].y+=lane*cfg.trackGap;points[4].y+=lane*cfg.trackGap;label={x:points[3].x+8,y:points[3].y-4};}
   }
   routed.push({...e,tree,source:a.id,target:b.id,points,path:path(points),label});
  }
  const hidden=new Set(),collapsed=new Set([...options.collapsed||[]].map(String));for(const id of collapsed)for(const child of descendants(id,children))hidden.add(child);
  const nodes=ids.filter(id=>!hidden.has(id)).map(id=>({id,data:byId.get(id),...positions[id],root:roots.includes(id),children:children[id].length,descendants:descendants(id,children).length,collapsed:collapsed.has(id)}));
  const visibleEdges=routed.filter(e=>!hidden.has(e.a)&&!hidden.has(e.b));
  return{config:cfg,nodes,edges:visibleEdges,allEdges:routed,positions,parent,children,roots,rowY,width,height,hiddenCount:hidden.size,hiddenLinks:routed.length-visibleEdges.length,unplacedEdges:(input.edges||[]).length-edges.length,bounds:bounds(nodes,cfg)};
 }
 return{DEFAULTS,layout,physicalEdges,descendants,bounds,path};
});
