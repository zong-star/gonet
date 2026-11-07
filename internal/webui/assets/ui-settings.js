/* GoNet 设置页转换与归属（P4）。
 *
 * 只做三件事，且都是纯函数：
 *   1. 现有 Settings ↔ 网段编辑模型 的往返转换（不改变有效访问集合和起点；LLDP管理地址读取固定开启）；
 *   2. 排除项归属、历史排除保留、重复与重叠检测；
 *   3. 区间级等价性检查，供测试与验收使用。
 *
 * 边界：地址解析只覆盖 IPv4（拨号四段 + 可选前缀长度），因为浏览器端不重复实现
 * 复杂的 IPv6 解析器；任何非 IPv4 的输入一律原样保留并标记 deferred，交由既有后端
 * （net/netip + Settings.Validate + SavePolicy）做权威校验与两文件保存。
 *
 * 可被浏览器直接加载（window.GoNetSettings），也可被 Node 原生测试 require。
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module && module.exports) module.exports = api;
  if (root && !root.GoNetSettings) root.GoNetSettings = api;
})(typeof globalThis !== 'undefined' ? globalThis : null, function () {
  'use strict';

  const V4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const V4_CIDR = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/;
  const MAX32 = 4294967295;

  const str = v => (v === null || v === undefined ? '' : String(v).trim());
  const list = v => (Array.isArray(v) ? v.map(str).filter(Boolean) : []);

  function octets(text) {
    const m = V4.exec(text);
    if (!m) return null;
    const parts = [m[1], m[2], m[3], m[4]].map(Number);
    if (parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return null;
    return parts;
  }

  function toInt(parts) {
    return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
  }

  function fromInt(value) {
    const n = Number(value);
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }

  /* ---- IPv4 前缀运算（唯一被实现的地址数学） ---- */

  // 解析成 {bits, addr, net, start, end, text}；非 IPv4 或无斜杠的单地址返回 null
  function v4Prefix(raw) {
    const text = str(raw);
    const m = V4_CIDR.exec(text);
    if (!m) return null;
    const parts = octets(m[1] + '.' + m[2] + '.' + m[3] + '.' + m[4]);
    if (!parts) return null;
    const bits = m[5] === undefined ? 32 : Number(m[5]);
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null;
    const addr = toInt(parts);
    const size = bits === 0 ? 4294967296 : Math.pow(2, 32 - bits);
    const start = size * Math.floor(addr / size);
    const end = start + size - 1;
    return { bits, addr, net: fromInt(start), start, end, text: fromInt(start) + '/' + bits };
  }

  function v4Addr(raw) {
    const text = str(raw);
    if (text.indexOf('/') >= 0) return null;
    const parts = octets(text);
    return parts ? { addr: toInt(parts), text: fromInt(toInt(parts)) } : null;
  }

  // 仅 IPv4 时给出规范键；其他一切（IPv6、异常写法）按小写原值保留
  function normalizeKey(raw) {
    const p = v4Prefix(raw);
    if (p) return p.text;
    const a = v4Addr(raw);
    if (a) return a.text + '/32';
    return str(raw).toLowerCase();
  }

  // 单个主机地址：'10.0.0.9' 与 '10.0.0.9/32' 是同一个地址
  // 形态检查：不解析 IPv6，只拒绝不可能是地址的输入（多余字符、多个斜杠、缺段的 IPv4）。
  // 通过形态检查但本地看不懂的值一律标记 deferred，交由后端权威校验（规则 11）。
  const ADDRESS_SHAPE = /^[0-9a-fA-F:.]+(\/[0-9]{1,3})?$/;
  const V4_SHAPE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,3}))?$/;
  function shapeOk(raw) {
    const value = str(raw);
    if (!ADDRESS_SHAPE.test(value)) return false;
    if (value.indexOf(':') >= 0) return true; // IPv6 及混合写法：只做形态检查
    const match = V4_SHAPE.exec(value);
    if (!match) return false;
    for (let i = 1; i <= 4; i++) if (Number(match[i]) > 255) return false;
    return match[5] === undefined || Number(match[5]) <= 32;
  }

  function hostAddrOf(raw) {
    const p = v4Prefix(raw);
    return p && p.bits === 32 ? p.addr : null;
  }

  function kindOf(raw) {
    const p = v4Prefix(raw);
    if (p) return p.bits === 32 ? 'ip' : 'range';
    if (v4Addr(raw)) return 'ip';
    if (str(raw).indexOf('/') >= 0) return 'opaque-prefix';
    return 'opaque-address';
  }

  const isSingle = raw => kindOf(raw) === 'ip';
  const isV4 = raw => v4Prefix(raw) !== null;

  // 长前缀优先；同前缀按原顺序（规则 2）
  function attribute(raw, segments) {
    const addr = hostAddrOf(raw);
    if (addr === null) return -1;
    let best = -1;
    let bestBits = -1;
    for (let i = 0; i < segments.length; i++) {
      const p = v4Prefix(segments[i].cidr);
      if (!p || addr < p.start || addr > p.end) continue;
      if (p.bits > bestBits) { bestBits = p.bits; best = i; }
    }
    return best;
  }

  /* ---- 区间集合运算：用于"有效访问集合保持不变"的等价性检查（规则 10） ---- */

  function mergeIntervals(intervals) {
    const sorted = intervals.slice().sort((x, y) => x.start - y.start || x.end - y.end);
    const out = [];
    for (const cur of sorted) {
      const last = out[out.length - 1];
      if (last && cur.start <= last.end + 1) last.end = Math.max(last.end, cur.end);
      else out.push({ start: cur.start, end: cur.end });
    }
    return out;
  }

  function subtractIntervals(allowed, excluded) {
    const out = [];
    for (const a of mergeIntervals(allowed)) {
      let pieces = [{ start: a.start, end: a.end }];
      for (const x of mergeIntervals(excluded)) {
        const next = [];
        for (const p of pieces) {
          if (x.end < p.start || x.start > p.end) { next.push(p); continue; }
          if (x.start > p.start) next.push({ start: p.start, end: x.start - 1 });
          if (x.end < p.end) next.push({ start: x.end + 1, end: p.end });
        }
        pieces = next;
      }
      out.push(...pieces);
    }
    return out;
  }

  function intervalText(intervals) {
    return intervals.map(i => (i.start === i.end ? fromInt(i.start) + '/32' : fromInt(i.start) + '-' + fromInt(i.end))).join(',') || '(空)';
  }

  function intervalHosts(intervals) {
    let total = 0n;
    for (const i of intervals) total += BigInt(i.end - i.start + 1);
    return total;
  }

  // 只统计能由 IPv4 表达的条目；其余进入 deferred 列表并原样保留
  function effectiveRanges(settings) {
    const s = settings || {};
    const allowed = [];
    const excluded = [];
    const deferred = { allowed: [], excluded: [] };
    for (const raw of list(s.allowed_cidrs)) (isV4(raw) ? allowed : deferred.allowed).push(raw);
    for (const raw of list(s.excluded_cidrs)) (isV4(raw) ? excluded : deferred.excluded).push(raw);
    const allowedInts = mergeIntervals(allowed.map(v4Prefix).filter(Boolean).map(p => ({ start: p.start, end: p.end })));
    const excludedInts = mergeIntervals(excluded.map(v4Prefix).filter(Boolean).map(p => ({ start: p.start, end: p.end })));
    const effective = subtractIntervals(allowedInts, excludedInts);
    return {
      allowed: allowedInts,
      excluded: excludedInts,
      effective: effective,
      effectiveText: intervalText(effective),
      effectiveHosts: intervalHosts(effective),
      deferred: deferred,
    };
  }

  /* ---- 转换：Settings -> 编辑模型 ---- */

  function fromSettings(settings) {
    const s = settings || {};
    const allowed = Array.isArray(s.allowed_cidrs) ? s.allowed_cidrs.map(str) : [];
    const excluded = Array.isArray(s.excluded_cidrs) ? s.excluded_cidrs.map(str) : [];
    const segments = [];
    allowed.forEach((cidr, i) => {
      if (!cidr) return;
      segments.push({ uiId: 'seg-' + (i + 1), cidr: str(cidr), excludedIPs: [], sourceOrder: i });
    });
    const history = [];
    excluded.forEach((value, order) => {
      if (!value) return;
      const entry = { value: str(value), key: normalizeKey(value), sourceOrder: order };
      const target = isSingle(value) ? attribute(value, segments) : -1;
      if (target >= 0) segments[target].excludedIPs.push(entry);
      else history.push(Object.assign({ kind: kindOf(value) }, entry));
    });
    const seedIPs = [];
    (Array.isArray(s.seeds) ? s.seeds.map(str) : []).forEach((ip, order) => {
      if (ip) seedIPs.push({ ip: ip, key: normalizeKey(ip), sourceOrder: order });
    });
    const draft = {
	  snmp: s.snmp ? {version:s.snmp.version,community:'',communityConfigured:!!s.snmp.community_configured} : null,
      collectionInterval: s.collection_interval ? {...s.collection_interval} : null,
      topologyScanInterval:s.topology_scan_interval?{...s.topology_scan_interval}:null,
      segments: segments,
      seedIPs: seedIPs,
      preservedLegacyExclusions: history,
      explicitlyRemovedExclusionKeys: [],
      advanced: {
        readManagement: true,
        bootstrapCIDRs: Array.isArray(s.bootstrap_cidrs) ? s.bootstrap_cidrs.map(str).filter(Boolean) : [],
      },
    };
    draft.segmentWarnings = segmentWarnings(draft);
    return draft;
  }

  // 旧配置里已有的重复/重叠只提示，不合并、不拆段、不扩大范围（规则 3）
  function segmentWarnings(draft) {
    const segs = (draft && draft.segments) || [];
    const out = [];
    for (let i = 0; i < segs.length; i++) {
      for (let j = i + 1; j < segs.length; j++) {
        const a = v4Prefix(segs[i].cidr);
        const b = v4Prefix(segs[j].cidr);
        if (!a || !b) continue;
        const same = a.bits === b.bits && a.start === b.start;
        const overlap = a.start <= b.end && b.start <= a.end;
        if (same) out.push({ kind: 'duplicate', uiIds: [segs[i].uiId, segs[j].uiId], message: '两条管理 IP 段完全相同：' + a.text });
        else if (overlap) out.push({ kind: 'overlap', uiIds: [segs[i].uiId, segs[j].uiId], message: '管理 IP 段重叠：' + a.text + ' 与 ' + b.text });
      }
    }
    return out;
  }

  /* ---- 转换：编辑模型 -> Settings ---- */

  function collectExclusions(draft) {
    const removed = new Set(draft.explicitlyRemovedExclusionKeys || []);
    const entries = [];
    for (const seg of draft.segments || []) {
      for (const item of seg.excludedIPs || []) entries.push(item);
    }
    for (const item of draft.preservedLegacyExclusions || []) entries.push(item);
    const seen = new Set();
    const kept = [];
    for (const item of entries) {
      if (!item || !str(item.value)) continue;
      const key = item.key || normalizeKey(item.value);
      if (removed.has(key) || seen.has(key)) continue;
      seen.add(key);
      kept.push({ key: key, value: str(item.value), sourceOrder: Number.isFinite(item.sourceOrder) ? item.sourceOrder : Number.MAX_SAFE_INTEGER });
    }
    kept.sort((a, b) => a.sourceOrder - b.sourceOrder);
    return kept.map(k => k.value);
  }

  function toSettings(draft) {
    const d = draft || {};
    const segments = (d.segments || []).filter(s => s && str(s.cidr));
    const seeds = [];
    const seenSeed = new Set();
    for (const item of d.seedIPs || []) {
      const ip = str(item && item.ip !== undefined ? item.ip : item);
      if (!ip || seenSeed.has(ip)) continue;
      seenSeed.add(ip);
      seeds.push(ip);
    }
    return {
      ...(d.topologyScanInterval?{topology_scan_interval:{value:Number(d.topologyScanInterval.value),unit:d.topologyScanInterval.unit}}:{}),
	  ...(d.snmp?{snmp:{version:d.snmp.version,...(d.snmp.community?{community:d.snmp.community}:{})}}:{}),
      ...(d.collectionInterval ? {collection_interval:{value:Number(d.collectionInterval.value),unit:d.collectionInterval.unit}} : {}),
      seeds: seeds,
      allowed_cidrs: segments.map(s => str(s.cidr)),
      excluded_cidrs: collectExclusions(d),
      // 地址补全已退役：控制台规范化入口把该字段置空，原值只留在 advanced 里做记录
      bootstrap_cidrs: [],
      read_management_addresses: true,
    };
  }

  function retiredBootstrap(settings) {
    return list((settings || {}).bootstrap_cidrs);
  }

  /* ---- 编辑操作（P5/P6 使用；都不修改入参） ---- */

  const clone = draft => JSON.parse(JSON.stringify(draft));

  function addSegment(draft, cidr) {
    const next = clone(draft);
    const value = str(cidr);
    if (!value) return { ok: false, code: 'empty', message: '请输入管理 IP 段' };
    if (!shapeOk(value)) return { ok: false, code: 'garbage', message: '无法识别的地址格式，请检查是否有多余字符' };
    const key = normalizeKey(value);
    for (const seg of next.segments) {
      if (normalizeKey(seg.cidr) === key) return { ok: false, code: 'duplicate', message: '该网段已存在', with: seg.uiId };
    }
    const p = v4Prefix(value);
    let deferred = false;
    if (p) {
      for (const seg of next.segments) {
        const q = v4Prefix(seg.cidr);
        if (!q) continue;
        if (p.start <= q.end && q.start <= p.end) return { ok: false, code: 'overlap', message: '与现有网段 ' + seg.cidr + ' 重叠', with: seg.uiId };
      }
    } else {
      deferred = true;
    }
    const uiId = 'seg-new-' + (next.segments.length + 1) + '-' + key.replace(/[^0-9a-z]+/gi, '');
    next.segments.push({ uiId: uiId, cidr: value, excludedIPs: [], sourceOrder: next.segments.length, deferred: deferred });
    next.segmentWarnings = segmentWarnings(next);
    return { ok: true, draft: next, uiId: uiId, deferred: deferred };
  }

  // 修改已有网段：只改 CIDR，保留原有排除项，再统一重新归属（规则 3、6）
  function editSegment(draft, uiId, cidr) {
    const next = clone(draft);
    const value = str(cidr);
    const target = next.segments.find(s => s.uiId === uiId);
    if (!target) return { ok: false, code: 'missing' };
    if (!value) return { ok: false, code: 'empty', message: '请输入管理 IP 段' };
    if (!shapeOk(value)) return { ok: false, code: 'garbage', message: '无法识别的地址格式，请检查是否有多余字符' };
    if (normalizeKey(value) === normalizeKey(target.cidr)) return { ok: true, draft: next, unchanged: true };
    for (const seg of next.segments) {
      if (seg.uiId === uiId) continue;
      if (normalizeKey(seg.cidr) === normalizeKey(value)) return { ok: false, code: 'duplicate', message: '该网段已存在', with: seg.uiId };
    }
    const p = v4Prefix(value);
    if (p) {
      for (const seg of next.segments) {
        if (seg.uiId === uiId) continue;
        const q = v4Prefix(seg.cidr);
        if (q && p.start <= q.end && q.start <= p.end) return { ok: false, code: 'overlap', message: '与现有网段 ' + seg.cidr + ' 重叠', with: seg.uiId };
      }
    }
    target.cidr = value;
    target.deferred = !p;
    const revalidated = revalidateExclusions(next);
    const out = revalidated.draft;
    out.segmentWarnings = segmentWarnings(out);
    return { ok: true, draft: out, movedToHistory: revalidated.movedToHistory, deferred: !p };
  }

  // 删除网段不等于删除其排除记录：仍被覆盖的重新归属，其余保留为历史排除（规则 6）
  function removeSegment(draft, uiId) {
    const next = clone(draft);
    const target = next.segments.find(s => s.uiId === uiId);
    if (!target) return { ok: false, code: 'missing' };
    next.segments = next.segments.filter(s => s.uiId !== uiId);
    const orphans = [];
    for (const item of target.excludedIPs || []) {
      const index = attribute(item.value, next.segments);
      if (index >= 0) next.segments[index].excludedIPs.push(item);
      else orphans.push(Object.assign({ kind: kindOf(item.value) }, item));
    }
    next.preservedLegacyExclusions = (next.preservedLegacyExclusions || []).concat(orphans);
    next.segmentWarnings = segmentWarnings(next);
    return { ok: true, draft: next, movedToHistory: orphans.length };
  }

  function addExclusion(draft, uiId, ip) {
    const next = clone(draft);
    const value = str(ip);
    if (!value) return { ok: false, code: 'empty', message: '请输入要排除的 IP' };
    if (!shapeOk(value)) return { ok: false, code: 'garbage', message: '无法识别的地址格式，请检查是否有多余字符' };
    const seg = next.segments.find(s => s.uiId === uiId);
    if (!seg) return { ok: false, code: 'missing' };
    const key = normalizeKey(value);
    for (const item of seg.excludedIPs) if (normalizeKey(item.value) === key) return { ok: false, code: 'duplicate', message: '已存在' };
    for (const item of next.preservedLegacyExclusions) if (normalizeKey(item.value) === key) return { ok: false, code: 'duplicate', message: '已存在' };
    const prefix = v4Prefix(value);
    if (prefix === null) {
      // 本地看不懂的写法的（含 IPv6）：无前缀或 /128 视为单个地址，交后端校验（规则 11）
      const slash = value.indexOf('/');
      if (slash >= 0 && Number(value.slice(slash + 1)) !== 128) return { ok: false, code: 'not_single', message: '新增排除项只支持单个 IP' };
      seg.excludedIPs.push({ value: value, key: key, sourceOrder: Number.MAX_SAFE_INTEGER, deferred: true });
      return { ok: true, draft: next, deferred: true };
    }
    if (prefix.bits !== 32) return { ok: false, code: 'not_single', message: '新增排除项只支持单个 IP' };
    const scope = v4Prefix(seg.cidr);
    if (scope && (prefix.addr < scope.start || prefix.addr > scope.end)) return { ok: false, code: 'outside', message: '该 IP 不在 ' + seg.cidr + ' 内' };
    seg.excludedIPs.push({ value: value, key: key, sourceOrder: Number.MAX_SAFE_INTEGER });
    return { ok: true, draft: next };
  }

  function removeExclusion(draft, key) {
    const next = clone(draft);
    const wanted = normalizeKey(key);
    const removed = new Set(next.explicitlyRemovedExclusionKeys || []);
    removed.add(wanted);
    next.explicitlyRemovedExclusionKeys = Array.from(removed);
    const strip = arr => (arr || []).filter(item => normalizeKey(item.value || item) !== wanted);
    next.segments = next.segments.map(seg => Object.assign({}, seg, { excludedIPs: strip(seg.excludedIPs) }));
    next.preservedLegacyExclusions = strip(next.preservedLegacyExclusions);
    return { ok: true, draft: next };
  }

  // 网段变化后重新校验已有排除项：能归属的保留，不能归属的转入历史，不删除（规则 6/7）
  function revalidateExclusions(draft) {
    const next = clone(draft);
    const moved = [];
    const still = [];
    const all = [];
    for (const seg of next.segments) {
      for (const item of seg.excludedIPs || []) all.push(item);
      seg.excludedIPs = [];
    }
    for (const item of all) {
      const index = attribute(item.value, next.segments);
      if (index >= 0) {
        next.segments[index].excludedIPs.push(item);
        still.push(item.value);
      } else {
        next.preservedLegacyExclusions.push(Object.assign({ kind: kindOf(item.value) }, item));
        moved.push(item.value);
      }
    }
    next.segmentWarnings = segmentWarnings(next);
    return { ok: true, draft: next, movedToHistory: moved, stillValid: still };
  }

  function addSeed(draft, ip) {
    const next = clone(draft);
    const value = str(ip);
    if (!value) return { ok: false, code: 'empty', message: '请输入发现起点' };
    if (!shapeOk(value)) return { ok: false, code: 'garbage', message: '无法识别的地址格式，请检查是否有多余字符' };
    if (next.seedIPs.some(s => s.ip === value)) return { ok: false, code: 'duplicate', message: '该起点已在列表中' };
    const check = seedStatus(next, value);
    if (!check.ok) return { ok: false, code: check.code, message: check.message };
    next.seedIPs.push({ ip: value, key: normalizeKey(value), sourceOrder: Number.MAX_SAFE_INTEGER });
    return { ok: true, draft: next, deferred: check.deferred === true };
  }

  function seedStatus(draft, raw) {
    const value = str(raw);
    if (!value) return { ok: false, code: 'empty', message: '请输入发现起点' };
    const a = v4Addr(value);
    if (!a) {
      if (!isV4(value) && value.indexOf('/') < 0) return { ok: true, deferred: true };
      return { ok: false, code: 'not_single', message: '起点只能是单个 IP' };
    }
    let inside = false;
    for (const seg of draft.segments || []) {
      const p = v4Prefix(seg.cidr);
      if (p && a.addr >= p.start && a.addr <= p.end) { inside = true; break; }
    }
    if (!inside) return { ok: false, code: 'outside', message: '起点不在任何管理 IP 段内' };
    const key = a.text + '/32';
    for (const seg of draft.segments || []) {
      for (const item of seg.excludedIPs || []) if (normalizeKey(item.value) === key) return { ok: false, code: 'excluded', message: '该地址已被排除' };
    }
    for (const item of draft.preservedLegacyExclusions || []) {
      const p = v4Prefix(item.value);
      if (p && a.addr >= p.start && a.addr <= p.end) return { ok: false, code: 'excluded', message: '该地址命中历史排除范围 ' + p.text };
    }
    return { ok: true };
  }

  function removeSeed(draft, ip) {
    const next = clone(draft);
    if ((next.seedIPs || []).length <= 1) return { ok: false, code: 'last_seed', message: '至少保留一个有效起点' };
    next.seedIPs = next.seedIPs.filter(s => s.ip !== str(ip));
    return { ok: true, draft: next };
  }

  // 保存前的统一预检；后端 Validate/SavePolicy 仍是权威校验
  function validateDraft(draft) {
    const errors = [];
    const warnings = [];
	if(draft?.snmp){
	 const s=draft.snmp,v=s.community||'';
	 if(s.version!=='2c')errors.push({code:'snmp',message:'SNMP 版本请选择 v2c'});
	 if(new TextEncoder().encode(v).length>255||/[\r\n\0]/.test(v))errors.push({code:'snmp',message:'团体名不能超过 255 字节或包含换行、NUL'});
	 if(!v&&!s.communityConfigured)errors.push({code:'snmp',message:'请填写 SNMP 团体名'});
	}
    if(draft?.topologyScanInterval&&!validTopologyScanInterval(draft.topologyScanInterval))errors.push({code:"topology_interval",message:"拓扑扫描频率请输入 0 或正整数，并选择分、时或日"});
    if(draft?.collectionInterval&&!validCollectionInterval(draft.collectionInterval))errors.push({code:"collection_interval",message:"采集频率请输入有效的正整数，并选择分、时或日"});
    const segments = (draft && draft.segments) || [];
    if (segments.length === 0) errors.push({ code: 'no_segments', message: '至少需要一个管理 IP 段' });
    if (!draft || (draft.seedIPs || []).length === 0) errors.push({ code: 'no_seeds', message: '至少需要一个发现起点' });
    for (const seg of segments) {
      const p = v4Prefix(seg.cidr);
      if (!p) warnings.push({ code: 'deferred_segment', uiId: seg.uiId, message: '网段 ' + seg.cidr + ' 的地址格式交由后端校验' });
      for (const item of seg.excludedIPs || []) {
        if (item.deferred) { warnings.push({ code: 'deferred_exclusion', uiId: seg.uiId, message: '排除项 ' + item.value + ' 交由后端校验' }); continue; }
        const a = hostAddrOf(item.value);
        if (p && a !== null && (a < p.start || a > p.end)) warnings.push({ code: 'outside', uiId: seg.uiId, message: '排除项 ' + item.value + ' 已不在 ' + seg.cidr + ' 内，将保留为历史排除' });
      }
    }
    for (const w of segmentWarnings(draft)) warnings.push(Object.assign({ code: w.kind }, w));
    const hasV4Segment = segments.some(seg => v4Prefix(seg.cidr));
    for (const seed of (draft && draft.seedIPs) || []) {
      const status = seedStatus(draft, seed.ip);
      if (status.ok) continue;
      if (status.code === 'outside' && !hasV4Segment) continue; // 全 IPv6 配置交由后端判定
      errors.push({ code: 'seed_' + status.code, message: '起点 ' + seed.ip + '：' + status.message });
    }
    for (const item of (draft && draft.preservedLegacyExclusions) || []) {
      if (item.kind === 'range' || item.kind === 'opaque-prefix') warnings.push({ code: 'legacy_range', message: '历史范围排除 ' + item.value + ' 保持原样，不展开为单个 IP' });
    }
    return { ok: errors.length === 0, errors: errors, warnings: warnings };
  }

  const collectionUnits={minute:60,hour:3600,day:86400};
  function validCollectionInterval(interval){return !!interval&&Object.hasOwn(collectionUnits,interval.unit)&&/^[1-9]\d*$/.test(String(interval.value))&&Number.isSafeInteger(Number(interval.value))&&Number(interval.value)<=Math.floor(3074457345/collectionUnits[interval.unit])}
  function collectionFrequency(interval){const labels={minute:'分钟',hour:'小时',day:'天'};return validCollectionInterval(interval)?'每 '+interval.value+' '+labels[interval.unit]+'采集一次':'未配置'}
  function validTopologyScanInterval(interval){return !!interval&&Object.hasOwn(collectionUnits,interval.unit)&&String(interval.value)==='0'||validCollectionInterval(interval)}
  function topologyScanFrequency(interval){if(!interval||validTopologyScanInterval(interval)&&Number(interval.value)===0)return '已关闭自动更新（数值为 0）';return validTopologyScanInterval(interval)?collectionFrequency(interval).replace('采集一次','更新一次'):'未配置'}
  return {
    validCollectionInterval,collectionFrequency,validTopologyScanInterval,topologyScanFrequency,
    fromSettings, toSettings, retiredBootstrap, normalizeKey, kindOf, isSingle, isV4, shapeOk,
    v4Prefix, v4Addr, hostAddrOf, attribute, segmentWarnings, effectiveRanges, intervalText, intervalHosts,
    mergeIntervals, subtractIntervals,
    addSegment, editSegment, removeSegment, addExclusion, removeExclusion, revalidateExclusions,
    addSeed, removeSeed, seedStatus, validateDraft,
  };
});
