(function (global) {
  'use strict';

  const roles = {source: '查询设备', transit: '中间设备', core: '核心', source_core: '查询设备 · 核心'};
  const verification = {confirmed: '已确认', unverified: '待核验', conflict: '证据冲突', unknown: '核验未知'};
  const operations = {up: '观测为 up', down: '观测为 down', degraded: '观测为 degraded', unknown: '运行状态未知'};
  const portName = endpoint => endpoint.interface_name || endpoint.display_name || '接口名未知';

  function validEndpoint(endpoint) {
    if (!endpoint || typeof endpoint.device_id !== 'string') return false;
    if (endpoint.interface_name !== null && typeof endpoint.interface_name !== 'string') return false;
    if (endpoint.interface_description !== null && typeof endpoint.interface_description !== 'string') return false;
    if (endpoint.interface_name && !['inventory', 'if_name', 'lldp_interface_name'].includes(endpoint.interface_name_source)) return false;
    if (!endpoint.interface_name && endpoint.interface_name_source !== null) return false;
    return endpoint.if_index_status === 'known'
      ? Number.isInteger(endpoint.if_index) && endpoint.if_index > 0
      : endpoint.if_index === null && ['not_collected', 'unmatched', 'ambiguous', 'unknown'].includes(endpoint.if_index_status);
  }

  function validStatus(edge) {
    return Object.hasOwn(verification, edge.verification_status) && ['active', 'inactive', 'unknown'].includes(edge.topology_status)
      && Object.hasOwn(operations, edge.oper_status)
      && (edge.oper_status === 'unknown' || Number.isFinite(Date.parse(edge.oper_observed_at)));
  }

  function validatePath(data) {
    if (!data || ![2, 3, 4].includes(data.schema_version) || data.target !== 'core') return false;
    if (data.path_status !== 'found') return ['not_found', 'no_core_configured'].includes(data.path_status) && data.path === null;
    const path = data.path;
    if (!path || !Array.isArray(path.nodes) || !Array.isArray(path.edges) || !path.nodes.length
      || !path.nodes.every(node => node && typeof node.device_id === 'string' && Object.hasOwn(roles, node.role))
      || path.hop_count !== path.edges.length || path.nodes.length !== path.edges.length + 1
      || path.nodes[0].device_id !== data.source_device_id || path.nodes.at(-1).device_id !== path.target_core_device_id
      || new Set(path.nodes.map(node => node.device_id)).size !== path.nodes.length) return false;
    if (path.edges.length === 0 ? path.nodes[0].role !== 'source_core'
      : path.nodes[0].role !== 'source' || path.nodes.at(-1).role !== 'core' || path.nodes.slice(1, -1).some(node => node.role !== 'transit')) return false;
    const edgeIDs = new Set();
    return path.edges.every((edge, index) => {
      if (!edge || !edge.edge_id || edgeIDs.has(edge.edge_id) || edge.hop !== index + 1 || !validEndpoint(edge.from) || !validEndpoint(edge.to)
        || edge.from.device_id !== path.nodes[index].device_id || edge.to.device_id !== path.nodes[index + 1].device_id
        || !validStatus(edge) || edge.verification_status !== 'confirmed' || edge.topology_status !== 'active') return false;
      edgeIDs.add(edge.edge_id);
      if (data.schema_version === 4) return ['peer-lag-v1','peer-lag-v2'].includes(data.inference_policy_version) && validateAggregateV3(edge, true);
      if (data.schema_version === 3) return validateAggregateV3(edge);
      if (edge.kind === 'physical') return typeof edge.link_id === 'string' && edge.link_id.length > 0 && edge.aggregation === null;
      const aggregate = edge.aggregation;
      if (edge.kind !== 'aggregate' || !aggregate || !aggregate.aggregate_id || !['complete', 'partial', 'unknown'].includes(aggregate.member_data_status)) return false;
      if (aggregate.member_links === null) return aggregate.member_data_status === 'unknown';
      if (!Array.isArray(aggregate.member_links) || aggregate.member_data_status === 'unknown') return false;
      const seen = new Set();
      return aggregate.member_links.every(member => {
        if (!member || !member.link_id || seen.has(member.link_id) || !validEndpoint(member.from) || !validEndpoint(member.to) || !validStatus(member)
          || member.from.device_id !== edge.from.device_id || member.to.device_id !== edge.to.device_id) return false;
        seen.add(member.link_id);
        return true;
      });
    });
  }

  function validGroupV4(group){
    if(!group||typeof group.group_id!=='string'||!group.group_id||typeof group.device_id!=='string'||!['direct','peer_inferred'].includes(group.evidence_type))return false;
    if(group.evidence_type==='peer_inferred')return group.aggregate_if_index===null&&group.interface_name===null&&group.mode==='unknown'&&typeof group.display_name==='string'&&group.inferred_from&&typeof group.inferred_from.device_id==='string'&&typeof group.inferred_from.group_id==='string'&&typeof group.inferred_from.scan_id==='string';
    return Number.isInteger(group.aggregate_if_index)&&group.aggregate_if_index>0&&(group.interface_name===null||typeof group.interface_name==='string');
  }
  function validateAggregateV3(edge, v4=false) {
    const a = edge.aggregation;
    if (!a || !(v4?['confirmed','inferred','partial','unknown','none','conflict']:['confirmed','partial','unknown','none','conflict']).includes(a.status)
      || !['lacp','static','unknown'].includes(a.mode) || edge.aggregation_status !== a.status || !['complete','partial','unknown'].includes(a.member_data_status)) return false;
    if (a.status === 'confirmed' || v4 && a.status === 'inferred') {
      if (edge.kind !== 'aggregate' || edge.link_id !== null || typeof a.aggregate_id !== 'string' || !a.aggregate_id) return false;
    } else if (edge.kind !== 'physical' || typeof edge.link_id !== 'string' || !edge.link_id || a.aggregate_id !== null) return false;
    for (const group of [a.local_group,a.remote_group]) if (group !== null && !(v4?validGroupV4(group):validEndpoint(group))) return false;
    if(v4&&['confirmed','inferred'].includes(a.status)&&(!a.local_group||!a.remote_group||a.local_group.device_id!==edge.from.device_id||a.remote_group.device_id!==edge.to.device_id))return false;
    if(v4&&a.status==='inferred'&&(a.mode!=='unknown'||a.member_data_status!=='partial'||[a.local_group,a.remote_group].filter(g=>g.evidence_type==='peer_inferred').length!==1))return false;
    if (!Array.isArray(a.unpaired_members) || a.member_data_status === 'complete' && a.unpaired_members.length) return false;
    if (a.member_links === null) return ['unknown','partial','conflict'].includes(a.status) && a.member_data_status === 'unknown';
    if (!Array.isArray(a.member_links) || a.member_data_status === 'unknown'
      || a.known_member_link_count !== a.member_links.length || a.returned_member_link_count !== a.member_links.length) return false;
    const seen = new Set();
    return a.member_links.every(m => {
      if (!m || !m.link_id || seen.has(m.link_id) || !validEndpoint(m.from) || !validEndpoint(m.to) || !validStatus(m)
        || m.from.device_id !== edge.from.device_id || m.to.device_id !== edge.to.device_id
        || !(v4?['confirmed','inferred','local_only','remote_only','conflict']:['confirmed','local_only','remote_only','conflict']).includes(m.membership_status)
        || a.status === 'confirmed' && m.membership_status !== 'confirmed'
        || a.status === 'inferred' && m.membership_status !== 'inferred') return false;
      seen.add(m.link_id); return true;
    });
  }

  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function table(headers, rows) {
    const wrapper = element('div', undefined, 'uplink-table-wrap');
    wrapper.tabIndex = 0;
    wrapper.setAttribute('aria-label', headers.join('、'));
    const result = element('table');
    const head = element('tr');
    for (const label of headers) {
      const cell = element('th', label);
      cell.scope = 'col';
      head.append(cell);
    }
    const thead = element('thead');
    thead.append(head);
    result.append(thead);
    const body = element('tbody');
    for (const row of rows) {
      const line = element('tr');
      for (const value of row) line.append(element('td', value));
      body.append(line);
    }
    result.append(body);
    wrapper.append(result);
    return wrapper;
  }

  function statusText(edge) {
    const observed = edge.oper_status !== 'unknown' && edge.oper_observed_at ? ' · ' + edge.oper_observed_at : '';
    const precise={admin_down:'管理关闭',stale:'接口状态过期'}[edge.link_oper_status];
    return verification[edge.verification_status] + ' · ' + (precise||operations[edge.oper_status]) + observed;
  }

  function aggregateText(aggregate, state) {
    state = aggregate?.status || state;
    if (state === 'inferred') return `聚合 · 对端推断 · 已观察成员 ${aggregate?.member_links?.length ?? aggregate?.known_member_link_count ?? 0} 条`;
    if (state === 'partial') return '聚合信息不完整';
    if (state === 'unknown' || !aggregate && !state) return '聚合状态未知';
    if (state === 'none') return '已确认未聚合';
    if (state === 'conflict') return '聚合证据冲突';
    if (!aggregate) return '聚合状态未知';
    if (aggregate.member_links === null) return '聚合 · 成员未知';
    const suffix = aggregate.member_data_status === 'complete' ? '列表完整' : '列表不完整';
    const title = {lacp:'LACP 聚合',static:'静态聚合',unknown:'模式未知聚合'}[aggregate.mode] || '聚合';
    return `${title} · 已知成员 ${aggregate.member_links?.length ?? aggregate.known_member_link_count ?? 0} 条，${suffix}`;
  }

  function showQuality(root, quality) {
    if (!quality) return;
    const parts = [`快照 ${quality.snapshot_id ?? '未知'}`, `快照时间 ${quality.snapshot_at ?? '未知'}`];
    if (quality.latest_scan) parts.push(`最新扫描 ${quality.latest_scan.scan_id} / ${quality.latest_scan.status}`);
    if (Number.isInteger(quality.data_age_seconds)) {
      const age = quality.data_age_seconds;
      parts.push(`数据年龄 ${Math.floor(age / 86400)} 天 ${Math.floor(age % 86400 / 3600)} 时 ${Math.floor(age % 3600 / 60)} 分 ${age % 60} 秒`);
    }
    if (quality.stale === true) parts.push('数据可能过期');
    for (const coverage of quality.coverage || []) {
      const scope = {network: '全网', device_neighbors: '设备邻居', device_to_core_query: '到核心查询'}[coverage.scope] || coverage.scope;
      parts.push(scope + {covered: '覆盖充分', gap: '采集有缺口', unknown: '覆盖未知'}[coverage.status]);
    }
    root.append(element('p', parts.join(' · '), 'uplink-quality'));
  }

  function endpointDetail(endpoint) {
    if (endpoint.group_id) return `${endpoint.device_id} · ${endpoint.display_name || endpoint.interface_name || '聚合接口未知'} · ifIndex ${endpoint.aggregate_if_index ?? '未知'}${endpoint.evidence_type === 'peer_inferred' ? ' · 对端推断' : ''}`;
    const description = endpoint.interface_description === null ? '描述未知' : endpoint.interface_description || '未配置描述';
    return `${endpoint.device_id} · ${portName(endpoint)} · ${description} · ifIndex ${endpoint.if_index ?? '未知'}`;
  }

  function edgeDetail(edge) {
    const detail = element('details', undefined, 'uplink-edge-detail');
    if(edge.kind==='aggregate')detail.open=true;
    detail.dataset.hop = String(edge.hop);
    detail.append(element('summary', `第 ${edge.hop} 跳 · ${statusText(edge)}`));
    detail.append(element('p', endpointDetail(edge.from)), element('p', endpointDetail(edge.to)));
    detail.append(element('p', `链路 ${edge.link_id ?? edge.edge_id} · ${aggregateText(edge.aggregation, edge.aggregation_status)}`));
    const aggregateDetails = edge.aggregation || edge.aggregation_diagnostics;
    if(aggregateDetails?.status==='inferred')detail.append(element('p','信锐真实聚合口名称与完整成员表未采集，当前依据对端映射建立关系。'));
    if (aggregateDetails?.local_group) detail.append(element('p', '本端聚合 · ' + endpointDetail(aggregateDetails.local_group)));
    if (aggregateDetails?.remote_group) detail.append(element('p', '对端聚合 · ' + endpointDetail(aggregateDetails.remote_group)));
    if (aggregateDetails?.unpaired_members?.length) detail.append(element('p', `未配对成员 ${aggregateDetails.unpaired_members.length} 个，成员数据不完整`));
    if (aggregateDetails?.member_links) {
      detail.append(table(['成员链路', '源端口及描述', '对端端口及描述', '状态'], aggregateDetails.member_links.map(member => [
        member.link_id, endpointDetail(member.from), endpointDetail(member.to), `${statusText(member)} · ${member.membership_status || '已知物理配对'}`
      ])));
    }
    return detail;
  }

  function renderGraph(root, path) {
    const ns = 'http://www.w3.org/2000/svg';
    const vertical = global.matchMedia('(max-width: 760px)').matches;
    const step = vertical ? 190 : 250;
    const width = vertical ? 300 : Math.max(300, path.nodes.length * step);
    const height = vertical ? Math.max(160, path.nodes.length * step) : 230;
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
    svg.setAttribute('width', width);
    svg.setAttribute('height', height);
    svg.setAttribute('role', 'group');
    svg.setAttribute('aria-label', '从查询设备到核心的一条确认路径，逐跳表格位于下方');
    function shape(tag, attrs, text) {
      const node = document.createElementNS(ns, tag);
      for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
      if (text !== undefined) node.textContent = text;
      return node;
    }
    const point = index => vertical ? {x: 150, y: 65 + index * step} : {x: 125 + index * step, y: 90};
    for (const edge of path.edges) {
      const a = point(edge.hop - 1), b = point(edge.hop);
      const group = shape('g', {tabindex: 0, role: 'button', 'aria-label': `第 ${edge.hop} 跳详情，${portName(edge.from)} 到 ${portName(edge.to)}，${statusText(edge)}`});
      group.append(shape('line', {x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: 'uplink-line'}));
      const labels = vertical
        ? [{x: a.x + 12, y: a.y + 47}, {x: b.x + 12, y: b.y - 42}]
        : [{x: a.x + 56, y: a.y - 46}, {x: b.x - 56, y: b.y + 56}];
      [edge.from, edge.to].forEach((endpoint, index) => {
        const full = portName(endpoint), short = full.length > 21 ? full.slice(0, 20) + '…' : full;
        const label = shape('text', {...labels[index], 'text-anchor': vertical ? 'start' : 'middle', class: 'uplink-port'}, short);
        label.append(shape('title', {}, full));
        group.append(label);
      });
      const status = vertical ? {x: 22, y: (a.y + b.y) / 2} : {x: (a.x + b.x) / 2, y: a.y + 16};
      group.append(shape('text', {...status, 'text-anchor': vertical ? 'start' : 'middle', class: 'uplink-status'}, verification[edge.verification_status] + ' · ' + operations[edge.oper_status]));
      const open = () => {
        const detail = root.parentElement.querySelector(`[data-hop="${edge.hop}"]`);
        if (detail) { detail.open = true; detail.querySelector('summary').focus(); }
      };
      group.addEventListener('click', open);
      group.addEventListener('keydown', event => {
        if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); open(); }
      });
      svg.append(group);
    }
    path.nodes.forEach((node, index) => {
      const p = point(index), group = shape('g', {});
      group.append(shape('rect', {x: p.x - 49, y: p.y - 30, width: 98, height: 60, rx: 9, class: 'uplink-node'}));
      const full = node.display_name || node.device_id;
      const short = full.length > 11 ? full.slice(0, 10) + '…' : full;
      const label = shape('text', {x: p.x, y: p.y - 2, 'text-anchor': 'middle', class: 'uplink-node-name'}, node.device_id + ' · ' + short);
      label.append(shape('title', {}, full));
      group.append(label, shape('text', {x: p.x, y: p.y + 17, 'text-anchor': 'middle', class: 'uplink-role'}, roles[node.role]));
      svg.append(group);
    });
    root.replaceChildren(svg);
  }

  function render(root, data) {
    root.replaceChildren(element('h3', '到核心的确认路径'));
    if (!validatePath(data)) { root.append(element('p', '路径数据校验失败，请检查后端返回。', 'uplink-error')); return; }
    showQuality(root, data.data_quality);
    if (data.path_status !== 'found') {
      const message = data.path_status === 'no_core_configured' ? '未配置核心设备。' : '在当前可用的确认数据中未找到路径。';
      root.append(element('p', message + (data.reason ? `（${data.reason}）` : '')));
      return;
    }
    const path = data.path;
    if (!path.hop_count) { root.append(element('p', '该设备已是核心。')); return; }
    const graph = element('div', undefined, 'uplink-graph');
    root.append(graph);
    const deviceName = id => path.nodes.find(node => node.device_id === id)?.display_name || id;
    root.append(table(['跳序', '源设备', '源端口', '对端设备', '对端端口', '核验', '运行状态', '聚合'], path.edges.map(edge => [
      edge.hop, deviceName(edge.from.device_id), portName(edge.from), deviceName(edge.to.device_id), portName(edge.to),
      verification[edge.verification_status], operations[edge.oper_status], aggregateText(edge.aggregation, edge.aggregation_status)
    ])));
    for (const edge of path.edges) root.append(edgeDetail(edge));
    try { renderGraph(graph, path); } catch { graph.replaceChildren(element('p', '图形不可用，请查看逐跳表格。')); }
  }

  function renderLegacy(root, data) {
    if (data?.path_found === false && Array.isArray(data.paths) && data.paths.length === 0) {
      root.replaceChildren(element('h3', '到核心的确认路径'), element('p', '在当前可用的确认数据中未找到路径。'));
      return;
    }
    const path = data?.paths?.[0];
    if (!path || !Array.isArray(path.nodes) || !Array.isArray(path.links) || path.nodes.length !== path.links.length + 1
      || !path.nodes.every(node => node && typeof node.device_id === 'string')
      || path.hop_count !== path.links.length || new Set(path.nodes.map(node => node.device_id)).size !== path.nodes.length
      || !path.links.every((edge, i) => edge && edge.verification_status === 'confirmed' && edge.endpoint_a?.device_id === path.nodes[i].device_id && edge.endpoint_b?.device_id === path.nodes[i + 1].device_id)) {
      root.replaceChildren(element('p', '旧版路径缺少可验证的逐跳数据。'));
      return;
    }
    root.replaceChildren(element('h3', '到核心的确认路径'), element('p', '当前使用旧版逐跳数据，接口名未知。'));
    root.append(table(['跳序', '源设备', '源端口', '对端设备', '对端端口', '核验', '运行状态'], path.links.map((edge, i) => [
      i + 1, path.nodes[i].name || path.nodes[i].device_id, '接口名未知', path.nodes[i + 1].name || path.nodes[i + 1].device_id, '接口名未知', '已确认', '运行状态未知'
    ])));
    for (const [index, edge] of path.links.entries()) {
      const a = edge.endpoint_a.interface?.name || edge.endpoint_a.logical_interface?.name || '未知';
      const b = edge.endpoint_b.interface?.name || edge.endpoint_b.logical_interface?.name || '未知';
      root.append(element('p', `第 ${index + 1} 跳旧端口文本 · ${a} ↔ ${b}`, 'uplink-quality'));
    }
    if (!path.hop_count) root.append(element('p', '该设备已是核心。'));
  }

  function mount(root, deviceID, request) {
    root.classList.add('uplink-view');
    const pathRoot = element('section'), neighborsRoot = element('section');
    root.replaceChildren(pathRoot, neighborsRoot);
    pathRoot.append(element('p', '正在查询上联路径…'));
    neighborsRoot.append(element('p', '正在查询直接邻居…'));
    let disposed = false, current = null;
    async function read(url) {
      const response = await request(url);
      const payload = await response.json();
      if (!response.ok) { const error = Error(payload.error?.message || '查询失败'); error.status = response.status; throw error; }
      return payload;
    }
    const prefix = '/api/v1/devices/' + encodeURIComponent(deviceID);
    async function loadPath() {
      try {
        let payload;
        try {
          try {
            try {payload=await read(prefix+'/uplink-path?schema_version=4');}
            catch(error){if(error.status!==400)throw error;payload=await read(prefix+'/uplink-path?schema_version=3');}
          }
          catch (error) { if (error.status !== 400) throw error; payload = await read(prefix + '/uplink-path?schema_version=2'); }
        }
        catch (error) {
          if (error.status !== 400) throw error;
          payload = await read(prefix + '/uplink-path?max_paths=1');
          if (!disposed) {
            renderLegacy(pathRoot, payload.data);
            const meta = payload.meta;
            if (meta) showQuality(pathRoot, {snapshot_id: meta.latest_scan_id, snapshot_at: meta.latest_scan_finished_at,
              data_age_seconds: meta.data_age_seconds, coverage: [{scope: 'network', status: meta.coverage_gap ? 'gap' : 'unknown'}]});
          }
          return;
        }
        if (!disposed) { current = payload.data; render(pathRoot, current); }
      } catch (error) {
        if (!disposed && error.status !== 401) pathRoot.replaceChildren(element('h3', '到核心的确认路径'), element('p', `查询失败 · ${error.message}`, 'uplink-error'));
      }
    }
    async function loadNeighbors() {
      try {
        let version = 4, payload;
        try {
          try {payload=await read(prefix+'/neighbors?schema_version=4');}
          catch(error){if(error.status!==400)throw error;version=3;payload=await read(prefix+'/neighbors?schema_version=3');}
        }
        catch (error) { if (error.status !== 400) throw error; version = 2; payload = await read(prefix + '/neighbors?schema_version=2'); }
        const data = payload.data, all = [], seen = new Set(), cursors = new Set();
        for (let page = 0; ; page++) {
          if (disposed) return;
          const current = payload.data;
          if (current.schema_version !== version || !Array.isArray(current.items)
            || !current.items.every(item => validEndpoint(item.local) && validEndpoint(item.remote) && validStatus(item))) throw Error('邻居数据校验失败');
          if (current.data_quality?.snapshot_id !== data.data_quality?.snapshot_id) throw Error('拓扑快照已变化，请重新查询');
          for (const item of current.items) { if (seen.has(item.link_id)) throw Error('邻居分页出现重复链路'); seen.add(item.link_id); all.push(item); }
          if (!current.has_more) { data.truncated = current.response_truncated || all.length < data.matching_link_count; break; }
          if (!current.next_cursor || cursors.has(current.next_cursor) || page >= 500) throw Error('邻居分页无法完成');
          cursors.add(current.next_cursor);
          payload = await read(prefix + '/neighbors?schema_version=' + version + '&cursor=' + encodeURIComponent(current.next_cursor));
        }
        data.items = all; data.returned_link_count = all.length;
        neighborsRoot.replaceChildren(element('h3', '直接邻居'));
        showQuality(neighborsRoot, data.data_quality);
        neighborsRoot.append(element('p', `匹配 ${data.matching_link_count ?? '未知'} 条，返回 ${data.returned_link_count} 条${data.truncated ? '，结果已截断' : ''}`));
        neighborsRoot.append(table(['链路', '本设备端口', '邻居设备', '邻居端口', '状态', '聚合'], data.items.map(item => [item.link_id, portName(item.local), item.remote.device_id, portName(item.remote), statusText(item), item.aggregation ? aggregateText(item.aggregation,item.aggregation.status) : '聚合状态未知'])));
        for (const item of data.items) neighborsRoot.append(element('p', `${item.link_id} · ${endpointDetail(item.local)} ↔ ${endpointDetail(item.remote)}`, 'uplink-quality'));
      } catch (error) {
        if (!disposed && error.status !== 401) neighborsRoot.replaceChildren(element('h3', '直接邻居'), element('p', `查询失败 · ${error.message}`, 'uplink-error'));
      }
    }
    const resize = () => { if (!disposed && current) render(pathRoot, current); };
    global.addEventListener('resize', resize);
    loadPath();
    loadNeighbors();
    return () => { disposed = true; global.removeEventListener('resize', resize); };
  }

  const api = {validatePath, render, renderLegacy, mount};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else global.GoNetUplink = api;
})(typeof window === 'undefined' ? globalThis : window);
