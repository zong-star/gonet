/* GoNet 区域变化判据与稳定行更新（P9）。
 *
 * 对应合同 `docs/ui-contract-2026-11-01.md` §8：
 *   - 每个区域独立判据、独立状态、独立 DOM 根；
 *   - 判据必须覆盖**实际展示字段**，不能只比 ID 与条数（A7：改名、IP 修正、错误原因变化都要能发现）；
 *   - 未变化不写 DOM、不重建行；
 *   - 隐藏页面保留最新数据并标记待渲染，进入时再更新。
 *
 * 本文件只放纯函数，可在 Node 中 require；DOM 应用留在 app.js。
 * 字段清单直接抄自合同 §8 的判据表：改这里必须同步改合同。 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.GoNetRegion = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  // 合同 §8 判据字段（对象内用点号取嵌套值）
  const FIELDS = {
    summary: ['device_counts', 'probe_summary', 'coverage_gap', 'latest_scan_id', 'latest_scan_status', 'latest_scan_finished_at', 'pending_links'],
    devices: ['id', 'inventory_name', 'sys_name', 'area', 'vendor', 'model', 'device_kind', 'access_addresses', 'chassis_mac', 'collection_status', 'discovery_depth', 'link_count', 'identity_state', 'last_seen_at'],
    candidates: ['key', 'system_name', 'model', 'device_kind', 'chassis_subtype', 'chassis_hex', 'observed_by', 'observed_by_ids', 'observed_at', 'status', 'reported_management_addresses', 'verification.verification_status', 'verification.selected_snmp_ip', 'verification.failure_code', 'verification.failure_reason', 'verification.last_verification_at'],
    probes: ['probe_ip', 'response_ip', 'source', 'probe_status', 'identity_conflict', 'failure_code', 'failure_reason', 'cache_status', 'scope_status', 'topology_status', 'first_seen_at', 'last_attempt_at', 'last_success_at', 'last_successful_facts.sys_name', 'last_successful_facts.sys_object_id', 'last_successful_facts.sys_description', 'last_successful_facts.chassis', 'normalized_identity', 'model', 'device_kind_hint', 'classification_rule', 'profile_name', 'matched_device_id'],
    links: ['id', 'device_a_id', 'device_b_id', 'port_a_key', 'port_b_key', 'port_a_name', 'port_b_name', 'confidence', 'fresh', 'discovery_state', 'missed_complete_scans', 'source_admin_status', 'source_oper_status', 'target_admin_status', 'target_oper_status', 'link_oper_status', 'status_collected_at', 'source_collection_state', 'target_collection_state'],
    pendingLinks: ['local_device_id', 'local_port_num', 'remote_key', 'remote_device_id', 'remote_port', 'original_port', 'status', 'reason', 'observed_at'],
    pendingNodes: ['key', 'system_name', 'system_description', 'status', 'chassis', 'reported_management_addresses', 'verification'],
    topologyPending: ['key', 'system_name', 'system_description', 'status', 'chassis', 'reported_management_addresses', 'verification'],
    topologyDevices: ['id', 'device_kind', 'name', 'access_addresses', 'area', 'model', 'collection_status'],
    settings: ['topology_scan_interval','collection_interval', 'seeds', 'allowed_cidrs', 'excluded_cidrs', 'bootstrap_cidrs', 'read_management_addresses'],
    job: ['running', 'id', 'state', 'message', 'scan_id', 'progress.stage', 'progress.depth', 'progress.completed', 'progress.scheduled', 'progress.target', 'progress.probe.range_hosts', 'progress.probe.identified'],
  };

  // 区域 → 承载它的页面（隐藏页面只标记待渲染）
  const REGION_PAGE = {
    devices: 'devices', candidates: 'candidates', probes: 'probes',
    topology: 'topology', settings: 'settings',
    summary: null, job: null,
  };

  const MISSING = '\u0000';

  function path(object, dotted) {
    let cur = object;
    for (const part of String(dotted).split('.')) {
      if (cur === null || cur === undefined) return undefined;
      cur = cur[part];
    }
    return cur;
  }

  function pick(object, fields) {
    return fields.map(f => path(object, f));
  }

  // FNV-1a：只用于判断"这一行的 HTML 是否变过"，不参与业务
  function hash(input) {
    let h = 0x811c9dc5;
    const text = String(input);
    for (let i = 0; i < text.length; i++) {
      h ^= text.charCodeAt(i);
      h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
    }
    return h.toString(16).padStart(8, '0');
  }

  // 列表区域：逐条按字段序列化；数组与对象都用 JSON 规范化，保证顺序敏感、空值可区分
  function listSignature(list, fields) {
    const items = Array.isArray(list) ? list : [];
    let out = items.length + '\u0002';
    for (const item of items) {
      for (const value of pick(item, fields)) {
        out += (value === undefined ? MISSING : JSON.stringify(value)) + '\u0001';
      }
      out += '\u0003';
    }
    return out;
  }

  function deviceName(d) {
    if (!d) return '';
    return d.inventory_name || d.sys_name || ('设备 #' + (d.id === undefined ? '' : d.id));
  }

  /** 各区域签名：只有签名变化才允许写 DOM */
  function signatures(payload) {
    const p = payload || {};
    const t = p.topology || {};
    const coreIDs = Array.isArray(t.core_ids) ? t.core_ids.join(',') : '';
    const topologyDevices = (t.devices || []).map(d => ({
      id: d.id, device_kind: d.device_kind, name: deviceName(d), access_addresses: d.access_addresses, area: d.area, model: d.model, collection_status: d.collection_status,
    }));
    return {
      summary: hash(listSignature([p.summary || {}], FIELDS.summary) + '|' + String(p.error || '')),
      devices: hash(listSignature(t.devices, FIELDS.devices)),
      candidates: hash(listSignature(t.neighbor_candidates, FIELDS.candidates)),
      probes: hash(listSignature(t.probe_pool, FIELDS.probes)),
      topology: hash(JSON.stringify(t.graph || null) + '\u0004' + listSignature(t.graph ? t.graph.links : t.links, FIELDS.links)
        + '\u0004' + listSignature(t.pending_links, FIELDS.pendingLinks)
        + '\u0004' + listSignature(t.pending_nodes, FIELDS.topologyPending)
        + '\u0004' + listSignature(t.neighbor_candidates, FIELDS.pendingNodes)
        + '\u0004' + listSignature(topologyDevices, FIELDS.topologyDevices)
        + '\u0004' + coreIDs
        + '\u0004' + JSON.stringify(t.aggregate_connections || [])
        + '\u0004' + String(t.inference_policy_version || '')),
      settings: hash(JSON.stringify(pick(p.settings || {}, FIELDS.settings))),
      job: hash(JSON.stringify(pick(p.job || {}, FIELDS.job))),
    };
  }

  /** 与上次签名比较，返回发生变化的区域名（首次全部算变化） */
  function changed(prev, next) {
    const before = prev || {};
    const after = next || {};
    const out = [];
    for (const key of Object.keys(after)) if (before[key] !== after[key]) out.push(key);
    return out;
  }

  /** 区域是否需要在进入页面时补渲染 */
  function pendingFor(page, pending) {
    const flags = pending || {};
    return Object.keys(REGION_PAGE).filter(region => REGION_PAGE[region] === page && flags[region]);
  }

  /**
   * 行级更新计划（纯函数）。
   * existing/target 都是 [{key, hash}]，顺序即 DOM 顺序。
   * 返回 ops（按目标顺序的操作）+ 统计，供 app.js 落地到 DOM。
   */
  function planRows(existing, target) {
    const before = new Map();
    for (const row of existing || []) if (!before.has(String(row.key))) before.set(String(row.key), String(row.hash));
    const wanted = new Set((target || []).map(r => String(r.key)));
    const ops = [];
    const stats = { reuse: 0, create: 0, replace: 0, remove: 0 };
    for (const row of target || []) {
      const key = String(row.key);
      const hash = String(row.hash);
      if (!before.has(key)) { ops.push({ key, action: 'create' }); stats.create++; continue; }
      if (before.get(key) === hash) { ops.push({ key, action: 'reuse' }); stats.reuse++; continue; }
      ops.push({ key, action: 'replace' }); stats.replace++;
    }
    for (const key of before.keys()) if (!wanted.has(key)) { ops.push({ key, action: 'remove' }); stats.remove++; }
    return { ops, stats };
  }

  return { FIELDS, REGION_PAGE, path, pick, hash, listSignature, signatures, changed, pendingFor, planRows };
});
