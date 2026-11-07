// P9 区域判据与行级更新：纯函数 Node 测试（合同 §8）
const test = require('node:test');
const assert = require('node:assert/strict');
const R = require('./assets/ui-region.js');

test('聚合关系和推断规则变化单独触发拓扑刷新',()=>{
 const first={topology:{links:[{id:240},{id:253}],aggregate_connections:[]}};
 const next=structuredClone(first);next.topology.aggregate_connections=[{aggregate_id:'lag:1:pair',status:'inferred',member_link_ids:['240','253']}];
 assert.notEqual(R.signatures(first).topology,R.signatures(next).topology);
 const policy=structuredClone(next);policy.topology.inference_policy_version='peer-lag-v2';
 assert.notEqual(R.signatures(next).topology,R.signatures(policy).topology);
 assert.equal(R.signatures(first).devices,R.signatures(next).devices);
});

const base = () => ({
  summary: { device_counts: { confirmed: 96 }, probe_summary: { range_hosts: 700 }, coverage_gap: true, latest_scan_id: 30, latest_scan_status: 'partial', latest_scan_finished_at: '2026-11-01T10:00:00Z', pending_links: [{ id: 1 }] },
  error: '',
  settings: { seeds: ['10.201.1.1'], allowed_cidrs: ['10.201.1.1/32'], excluded_cidrs: [], bootstrap_cidrs: [], read_management_addresses: true },
  job: { running: false, id: 'j1', state: 'completed', message: '完成', scan_id: 30, progress: { stage: 'finished', depth: 0, completed: 5, scheduled: 5, target: '', probe: { range_hosts: 700, identified: 12 } } },
  topology: {
    core_ids: [1],
    devices: [{ id: 1, inventory_name: '核心交换机', area: '机房A', vendor: 'H3C', model: 'S5560', device_kind: 'switch', access_addresses: ['10.201.1.1'], chassis_mac: 'aabbccddeeff', collection_status: 'collected', discovery_depth: 0, link_count: 12, identity_state: 'verified', last_seen_at: '2026-11-01T10:00:00Z' }],
    links: [{ id: 5, device_a_id: 1, device_b_id: 2, port_a_key: 'lldp:5:01', port_b_key: 'lldp:5:02', port_a_name: 'GE1/0/1', port_b_name: 'GE1/0/2', confidence: 'bidirectional', fresh: true, discovery_state: 'confirmed', missed_complete_scans: 0 }],
    pending_links: [{ local_device_id: 1, local_port_num: 3, remote_key: 'k1', remote_device_id: null, remote_port: 4, original_port: 'GE1/0/3', status: 'unverified', reason: 'no_address', observed_at: '2026-11-01T09:00:00Z' }],
    neighbor_candidates: [{ key: 'k1', system_name: 'AP', system_description: 'H3C WA', status: 'unverified', chassis: 'aabb', reported_management_addresses: ['10.20.0.9'], verification: { verification_status: 'failed', selected_snmp_ip: '10.20.0.9', failure_code: 'timeout', failure_reason: '无响应', last_verification_at: '2026-11-01T09:05:00Z' }, model: 'WA6320', device_kind: 'wireless_controller', observed_by: ['核心交换机'], observed_by_ids: [1], observed_at: '2026-11-01T09:00:00Z' }],
    probe_pool: [{ probe_ip: '10.201.1.1', response_ip: '10.201.1.1', source: 'seed', probe_status: 'identified', identity_conflict: false, failure_code: '', failure_reason: '', cache_status: 'fresh', scope_status: 'allowed', topology_status: 'linked', first_seen_at: '2026-11-01T08:00:00Z', last_attempt_at: '2026-11-01T10:00:00Z', last_success_at: '2026-11-01T10:00:00Z', last_successful_facts: { sys_name: 'core', sys_object_id: '1.3.6', sys_description: 'H3C S5560', chassis: { subtype: 4, raw_hex: 'aabb' } }, normalized_identity: 'chassis:aabb', model: 'S5560', device_kind_hint: 'switch', classification_rule: 'chassis', profile_name: 'h3c', matched_device_id: 1 }],
  },
});

test('signatures：未变化时签名完全一致', () => {
  const a = R.signatures(base());
  const b = R.signatures(base());
  assert.deepEqual(a, b);
  assert.deepEqual(R.changed(a, b), []);
});

test('signatures：每个展示字段变化都必须被发现（A7）', () => {
  const cases = [
    ['devices', t => { t.devices[0].inventory_name = '改名后的核心'; }],
    ['devices', t => { t.devices[0].access_addresses = ['10.201.1.9']; }],
    ['devices', t => { t.devices[0].link_count = 13; }],
    ['devices', t => { t.devices[0].identity_state = 'pending'; }],
    ['candidates', t => { t.neighbor_candidates[0].verification.failure_reason = '认证失败'; }],
    ['candidates', t => { t.neighbor_candidates[0].status = 'identity_conflict'; }],
    ['probes', t => { t.probe_pool[0].failure_code = 'timeout'; }],
    ['probes', t => { t.probe_pool[0].cache_status = 'stale'; }],
    ['probes', t => { t.probe_pool[0].last_successful_facts.sys_name = '改名'; }],
    ['probes', t => { t.probe_pool[0].matched_device_id = 7; }],
    ['topology', t => { t.links[0].confidence = 'unidirectional'; }],
    ['topology', t => { t.pending_links[0].reason = 'port_missing'; }],
    ['topology', t => { t.neighbor_candidates[0].system_name = 'AP-2'; }],
    ['topology', t => { t.core_ids = [2]; }],
    ['topology', t => { t.devices[0].inventory_name = '改名'; }],
    ['topology', t => { t.devices[0].area = '机房B'; }],
    ['topology', t => { t.devices[0].model = '新型号'; }],
    ['topology', t => { t.devices[0].collection_status = 'historical'; }],
    ['topology', t => { t.pending_nodes = [{ key: 'k9', status: 'unverified' }]; }],
  ];
  for (const [region, mutate] of cases) {
    const before = R.signatures(base());
    const payload = base();
    mutate(payload.topology);
    const after = R.signatures(payload);
    assert.ok(R.changed(before, after).includes(region), `${region} 应被发现变化：${JSON.stringify(mutate)}`);
  }
  // 未展示字段不该触发重绘
  const before = R.signatures(base());
  const payload = base();
  payload.topology.devices[0].created_at = '2020-01-01T00:00:00Z';
  payload.topology.devices[0].internal_note = 'x';
  assert.deepEqual(R.changed(before, R.signatures(payload)), [], '未展示字段不应触发区域更新');
});

test('signatures：summary/job/settings 各自独立', () => {
  const cases = [
    ['summary', p => { p.summary.device_counts = { confirmed: 97 }; }],
    ['summary', p => { p.error = 'PostgreSQL 暂不可用'; }],
    ['job', p => { p.job.progress.completed = 4; }],
    ['job', p => { p.job.message = '正在停止并保存结果'; }],
    ['settings', p => { p.settings.excluded_cidrs = ['10.201.1.2/32']; }],
    ['settings', p => { p.settings.read_management_addresses = false; }],
  ];
  for (const [region, mutate] of cases) {
    const before = R.signatures(base());
    const payload = base();
    mutate(payload);
    const diff = R.changed(before, R.signatures(payload));
    assert.ok(diff.includes(region), `${region} 应被发现：${JSON.stringify(diff)}`);
    assert.deepEqual(diff.filter(x => x !== region), [], `只应影响 ${region}`);
  }
});

test('changed：首次（无上次签名）时全部区域都算变化', () => {
  const diff = R.changed(null, R.signatures(base()));
  assert.deepEqual(diff.sort(), ['candidates', 'devices', 'job', 'probes', 'settings', 'summary', 'topology']);
});

test('pendingFor：只有当前页面的区域会被补渲染', () => {
  const pending = { devices: true, probes: true, topology: true };
  assert.deepEqual(R.pendingFor('devices', pending), ['devices']);
  assert.deepEqual(R.pendingFor('probes', pending), ['probes']);
  assert.deepEqual(R.pendingFor('candidates', pending), []);
});

test('planRows：未变化时全部复用，不重建行', () => {
  const existing = [{ key: '1', hash: 'aaa' }, { key: '2', hash: 'bbb' }];
  const plan = R.planRows(existing, existing);
  assert.deepEqual(plan.stats, { reuse: 2, create: 0, replace: 0, remove: 0 });
  assert.deepEqual(plan.ops.map(o => o.action), ['reuse', 'reuse']);
});

test('planRows：只有内容变化的那一行被替换，其余复用', () => {
  const existing = [{ key: '1', hash: 'aaa' }, { key: '2', hash: 'bbb' }, { key: '3', hash: 'ccc' }];
  const target = [{ key: '1', hash: 'aaa' }, { key: '2', hash: 'zzz' }, { key: '3', hash: 'ccc' }];
  const plan = R.planRows(existing, target);
  assert.deepEqual(plan.stats, { reuse: 2, create: 0, replace: 1, remove: 0 });
  assert.equal(plan.ops[1].action, 'replace');
});

test('planRows：新增、删除与翻页顺序变化', () => {
  const existing = [{ key: '1', hash: 'a' }, { key: '2', hash: 'b' }];
  assert.deepEqual(R.planRows(existing, [{ key: '1', hash: 'a' }, { key: '2', hash: 'b' }, { key: '3', hash: 'c' }]).stats, { reuse: 2, create: 1, replace: 0, remove: 0 });
  assert.deepEqual(R.planRows(existing, [{ key: '1', hash: 'a' }]).stats, { reuse: 1, create: 0, replace: 0, remove: 1 });
  // 整页翻到下一页：2 条全换，但复用了 key 不变的第 1 条
  const plan = R.planRows(existing, [{ key: '2', hash: 'b' }, { key: '1', hash: 'a' }]);
  assert.deepEqual(plan.stats, { reuse: 2, create: 0, replace: 0, remove: 0 });
  assert.deepEqual(plan.ops.map(o => o.key), ['2', '1']);
});

test('hash：同输入同结果，不同输入不同结果', () => {
  assert.equal(R.hash('abc'), R.hash('abc'));
  assert.notEqual(R.hash('abc'), R.hash('abd'));
  assert.equal(R.hash('').length, 8);
});

test('path/pick：点号取嵌套字段，缺失值可区分', () => {
  assert.equal(R.path({ a: { b: [1] } }, 'a.b.0'), 1);
  assert.equal(R.path({ a: 1 }, 'a.b.c'), undefined);
  assert.deepEqual(R.pick({ a: 1, b: { c: 2 } }, ['a', 'b.c', 'z']), [1, 2, undefined]);
});


test('graph 批次、最近尝试、当前成员变化独立刷新拓扑',()=>{
 const first={topology:{graph:{snapshot_id:32,device_ids:[1,42],links:[{id:249}],aggregate_connections:[],latest_attempt:{scan_id:32,status:'partial'}}}};
 for(const mutate of [g=>g.snapshot_id++,g=>g.latest_attempt={scan_id:33,status:'running'},g=>g.links=[],g=>g.device_ids=[1],g=>g.aggregate_connections=[{aggregate_id:'a',member_link_ids:['249']}],g=>g.snapshot_finished_at='2026-11-06T10:00:00Z']){
  const next=structuredClone(first);mutate(next.topology.graph);assert.notEqual(R.signatures(first).topology,R.signatures(next).topology);assert.equal(R.signatures(first).devices,R.signatures(next).devices);
 }
});
