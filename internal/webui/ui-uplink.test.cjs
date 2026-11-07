const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {validatePath} = require('./assets/ui-uplink.js');
const samples = JSON.parse(fs.readFileSync(path.join(__dirname, '../../docs/acceptance/gonet-uplink-optimization/P3-http.json'), 'utf8'));
const sample = () => structuredClone(samples.find(item => item.name === 'uplink_v2').body.data);

test('schema 4 接受真实 handler 的对端推断组、空真实接口及两条物理成员',()=>{
 const captures=JSON.parse(fs.readFileSync(path.join(__dirname,'../../docs/acceptance/gonet-peer-lag/http-samples.json'),'utf8'));
 const data=captures.find(s=>s.path.includes('/uplink-path')).body.data;
 assert.equal(validatePath(data),true);const edge=data.path.edges.at(-1);
 assert.equal(edge.aggregation.status,'inferred');assert.equal(edge.aggregation.member_links.length,2);assert.equal(edge.aggregation.remote_group.aggregate_if_index,null);
 for(const mutate of [d=>{d.path.edges.at(-1).aggregation.remote_group.aggregate_if_index=639},d=>{d.path.edges.at(-1).aggregation.member_links.pop()},d=>{d.path.edges.at(-1).aggregation.member_data_status='complete'},d=>{d.schema_version=3}]){const invalid=structuredClone(data);mutate(invalid);assert.equal(validatePath(invalid),false)}
});

test('schema 3 使用实际 handler 样本，保留未知、单端成员和冲突边界', () => {
  const cases = JSON.parse(fs.readFileSync(path.join(__dirname, '../../docs/acceptance/gonet-lag-adaptation/http-samples.json'), 'utf8'));
  const data = structuredClone(cases.find(s => s.path.includes('/uplink-path?schema_version=3')).body.data);
  assert.equal(validatePath(data), true);
  assert.equal(data.path.edges[0].aggregation.status, 'unknown');
  assert.equal(data.path.edges[2].aggregation.status, 'partial');
  assert.equal(data.path.edges[2].aggregation.member_links.length, 2);
  const invalid = structuredClone(data);
  invalid.path.edges[2].aggregation.status = 'confirmed';
  assert.equal(validatePath(invalid), false);
  const adOnly = structuredClone(data);
  adOnly.path.edges[0].aggregation_status = adOnly.path.edges[0].aggregation.status = 'partial';
  assert.equal(validatePath(adOnly), true);
});

test('上联校验接受确认聚合、零跳与无路径响应', () => {
  for (const item of samples.filter(item => item.name.startsWith('uplink_'))) assert.equal(validatePath(item.body.data), true, item.name);
});

test('断裂、成环、错向或未确认图不能绘成完整路径', () => {
  for (const mutate of [
    data => { data.path.hop_count++; },
	data => { data.path.nodes[0] = null; },
	data => { data.path.edges[0] = null; },
	data => { data.path.edges[0].aggregation.member_links[0] = null; },
    data => { data.path.edges[0].to.device_id = 'wrong'; },
    data => { data.path.nodes[2].device_id = data.path.nodes[0].device_id; },
    data => { data.path.edges[0].verification_status = 'unverified'; },
    data => { data.path.edges[0].aggregation.member_links[0].from.device_id = 'wrong'; },
    data => { data.path.edges[0].aggregation.member_links.push(data.path.edges[0].aggregation.member_links[0]); },
    data => { data.path.edges[0].oper_status = 'down'; },
    data => { data.path.edges[0].from.if_index = 0; }
  ]) {
    const data = sample();
    mutate(data);
    assert.equal(validatePath(data), false);
  }
});

test('端口描述按文本保留，运行观测必须有时间，成员未知与部分独立', () => {
  const data = sample();
  const edge = data.path.edges[0];
  edge.from.interface_description = '<img src=x onerror=alert(1)>';
  edge.oper_status = 'down';
  edge.oper_observed_at = '2026-11-05T00:00:00Z';
  assert.equal(validatePath(data), true);
  edge.aggregation.member_data_status = 'partial';
  assert.equal(validatePath(data), true);
  edge.aggregation.member_data_status = 'unknown';
  edge.aggregation.member_links = null;
  assert.equal(validatePath(data), true);
});
