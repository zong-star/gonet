/* P4 设置转换与归属测试：node --test internal/webui/ui-settings.test.cjs
 *
 * 只测纯函数：不碰数据库、不碰 SNMP、不启动服务、不修改任何配置。
 * 基线取自 P0 记录的只读快照（示例地址仅用于测试）。
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const S = require('./assets/ui-settings.js');

test('SNMP 草稿不导入返回值中的秘密，留空保留已保存团体名',()=>{
 const d=S.fromSettings({...baseline(),snmp:{version:'2c',community_configured:true,community:'must-not-copy'}});
 assert.equal(d.snmp.community,'');
 assert.deepEqual(S.toSettings(d).snmp,{version:'2c'});
 d.snmp.community='new fixture value';
 assert.deepEqual(S.toSettings(d).snmp,{version:'2c',community:'new fixture value'});
 assert.equal(S.validateDraft(d).ok,true);
});

test('SNMP 校验按字节限制团体名且不误改旧客户端设置',()=>{
 const d=S.fromSettings({...baseline(),snmp:{version:'2c',community_configured:false}});
 assert.ok(S.validateDraft(d).errors.some(e=>e.code==='snmp'));
 d.snmp.community='团'.repeat(86);
 assert.ok(S.validateDraft(d).errors.some(e=>e.code==='snmp'));
 d.snmp.community='valid-fixture';d.snmp.version='3';
 assert.ok(S.validateDraft(d).errors.some(e=>e.code==='snmp'));
 assert.equal(S.toSettings(S.fromSettings(baseline())).snmp,undefined);
});

// P0 基线：5 个管理段、1 条无效排除、4 条旧 bootstrap
const baseline = () => ({
  seeds: ['10.201.1.1'],
  allowed_cidrs: ['10.201.1.1/32', '10.201.109.0/24', '10.201.212.0/24', '10.202.99.0/24', '10.203.150.2/32'],
  excluded_cidrs: ['10.201.1.2/32'],
  bootstrap_cidrs: ['10.203.150.2/32', '10.202.99.3/32', '10.202.99.19/32', '10.202.99.2/32'],
  read_management_addresses: true,
});

test('往返转换不改变有效访问集合（区间相等，不只是数量相等）', () => {
  const before = baseline();
  const after = S.toSettings(S.fromSettings(before));
  const a = S.effectiveRanges(before);
  const b = S.effectiveRanges(after);
  assert.deepStrictEqual(b.allowed, a.allowed, '管理区间必须逐段相等');
  assert.deepStrictEqual(b.excluded, a.excluded, '排除区间必须逐段相等');
  assert.deepStrictEqual(b.effective, a.effective, '有效访问区间必须逐段相等');
  assert.strictEqual(b.effectiveText, a.effectiveText);
  assert.strictEqual(b.effectiveHosts, a.effectiveHosts);
  assert.strictEqual(b.effectiveHosts, 770n, '/32 + 3 个 /24 + /32 = 770 个地址；10.201.1.2/32 不在任何管理段内，所以排除无效');
});

test('往返转换保持起点、排除顺序和高级值', () => {
  const before = baseline();
  const after = S.toSettings(S.fromSettings(before));
  assert.deepStrictEqual(after.seeds, before.seeds);
  assert.deepStrictEqual(after.allowed_cidrs, before.allowed_cidrs);
  assert.deepStrictEqual(after.excluded_cidrs, before.excluded_cidrs);
  assert.strictEqual(after.read_management_addresses, before.read_management_addresses);
});

test('往返转换退役 bootstrap 但保留原值供记录', () => {
  const before = baseline();
  const draft = S.fromSettings(before);
  const after = S.toSettings(draft);
  assert.deepStrictEqual(after.bootstrap_cidrs, [], '新控制台提交的 settings 里该字段必须为空');
  assert.deepStrictEqual(draft.advanced.bootstrapCIDRs, before.bootstrap_cidrs);
  assert.deepStrictEqual(S.retiredBootstrap(before), before.bootstrap_cidrs);
  // 退役不影响有效访问集合，也不影响保留项
  assert.strictEqual(S.effectiveRanges(after).effectiveHosts, S.effectiveRanges(before).effectiveHosts);
});

test('排除项归属：长前缀优先，同前缀按原顺序', () => {
  const draft = S.fromSettings({
    seeds: ['10.0.0.1'],
    allowed_cidrs: ['10.0.0.0/16', '10.0.5.0/24'],
    excluded_cidrs: ['10.0.5.9/32'],
    bootstrap_cidrs: [],
    read_management_addresses: false,
  });
  assert.strictEqual(draft.segments[1].excludedIPs.length, 1, '应归属到更长的 /24');
  assert.strictEqual(draft.segments[0].excludedIPs.length, 0);
  const same = S.fromSettings({
    seeds: ['10.0.0.1'],
    allowed_cidrs: ['10.0.0.0/24', '10.0.0.0/24'],
    excluded_cidrs: ['10.0.0.9/32'],
    bootstrap_cidrs: [],
    read_management_addresses: false,
  });
  assert.strictEqual(same.segments[0].excludedIPs.length, 1, '同前缀时归到先声明的那条');
  assert.strictEqual(same.segments[1].excludedIPs.length, 0);
});

test('不属于任何网段的排除项保留为历史排除（规则 4）', () => {
  const draft = S.fromSettings({
    seeds: ['10.201.109.2'],
    allowed_cidrs: ['10.201.109.0/24'],
    excluded_cidrs: ['10.201.1.2/32'],
    bootstrap_cidrs: [],
    read_management_addresses: true,
  });
  assert.strictEqual(draft.segments[0].excludedIPs.length, 0);
  assert.strictEqual(draft.preservedLegacyExclusions.length, 1);
  assert.strictEqual(draft.preservedLegacyExclusions[0].kind, 'ip');
  assert.deepStrictEqual(S.toSettings(draft).excluded_cidrs, ['10.201.1.2/32']);
});

test('范围排除保留为"历史范围排除"，不展开为大量 IP（规则 5）', () => {
  const draft = S.fromSettings({
    seeds: ['10.201.109.2'],
    allowed_cidrs: ['10.201.0.0/16'],
    excluded_cidrs: ['10.201.9.0/24'],
    bootstrap_cidrs: [],
    read_management_addresses: false,
  });
  assert.strictEqual(draft.preservedLegacyExclusions.length, 1, '只能有一条记录，不能展开成 254 个 IP');
  assert.strictEqual(draft.preservedLegacyExclusions[0].kind, 'range');
  assert.deepStrictEqual(S.toSettings(draft).excluded_cidrs, ['10.201.9.0/24']);
});

test('删除网段：可归属的重归属，其余转历史，都不删除（规则 6）', () => {
  const draft = S.fromSettings({
    seeds: ['10.0.0.1'],
    allowed_cidrs: ['10.0.0.0/16', '10.0.5.0/24'],
    excluded_cidrs: ['10.0.5.9/32', '10.0.5.10/32'],
    bootstrap_cidrs: [],
    read_management_addresses: false,
  });
  const result = S.removeSegment(draft, draft.segments[1].uiId);
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.draft.segments.length, 1);
  assert.strictEqual(result.draft.segments[0].excludedIPs.length, 2, '两条都被 /16 重新接住');
  const orphaned = S.removeSegment(result.draft, result.draft.segments[0].uiId);
  assert.strictEqual(orphaned.draft.segments.length, 0);
  assert.strictEqual(orphaned.movedToHistory, 2, '失去归属的排除项转入历史而不是被删除');
  assert.deepStrictEqual(S.toSettings(orphaned.draft).excluded_cidrs, ['10.0.5.9/32', '10.0.5.10/32']);
});

test('新增网段：拒绝重复与重叠，旧重叠只提示不自动处理（规则 3）', () => {
  let draft = S.fromSettings({ seeds: ['10.0.0.1'], allowed_cidrs: ['10.0.0.0/24'], excluded_cidrs: [], bootstrap_cidrs: [], read_management_addresses: false });
  assert.strictEqual(S.addSegment(draft, '10.0.0.0/24').code, 'duplicate');
  assert.strictEqual(S.addSegment(draft, '10.0.0.128/25').code, 'overlap');
  assert.strictEqual(S.addSegment(draft, '10.0.0.0/16').code, 'overlap');
  assert.strictEqual(S.addSegment(draft, '').code, 'empty');
  const added = S.addSegment(draft, '10.0.1.0/24');
  assert.strictEqual(added.ok, true);
  assert.strictEqual(added.draft.segments.length, 2);
  draft = S.fromSettings({ seeds: ['10.0.0.1'], allowed_cidrs: ['10.0.0.0/16', '10.0.0.0/24'], excluded_cidrs: [], bootstrap_cidrs: [], read_management_addresses: false });
  assert.strictEqual(draft.segmentWarnings.length, 1, '旧重叠读取时提示');
  assert.strictEqual(draft.segmentWarnings[0].kind, 'overlap');
  assert.deepStrictEqual(S.toSettings(draft).allowed_cidrs, ['10.0.0.0/16', '10.0.0.0/24'], '不合并、不拆分、不扩大范围');
});

test('IPv6 或其他写法不自行解析，标记 deferred 后原样保留（规则 11）', () => {
  const input = { seeds: ['2001:db8::1'], allowed_cidrs: ['2001:db8::/32'], excluded_cidrs: ['2001:db8::5/128'], bootstrap_cidrs: [], read_management_addresses: false };
  const draft = S.fromSettings(input);
  const out = S.toSettings(draft);
  assert.deepStrictEqual(out.allowed_cidrs, input.allowed_cidrs);
  assert.deepStrictEqual(out.excluded_cidrs, input.excluded_cidrs);
  assert.deepStrictEqual(out.seeds, input.seeds);
  assert.strictEqual(draft.preservedLegacyExclusions[0].kind, 'opaque-prefix');
  const ranges = S.effectiveRanges(input);
  assert.deepStrictEqual(ranges.deferred.allowed, ['2001:db8::/32'], '非 IPv4 交给后端校验');
  assert.deepStrictEqual(ranges.deferred.excluded, ['2001:db8::5/128']);
  const added = S.addSegment(S.fromSettings({ seeds: ['10.0.0.1'], allowed_cidrs: ['10.0.0.0/24'], excluded_cidrs: [], bootstrap_cidrs: [], read_management_addresses: false }), '2001:db8:1::/48');
  assert.strictEqual(added.ok, true);
  assert.strictEqual(added.deferred, true, '无法本地校验的重叠交由后端');
  assert.strictEqual(S.validateDraft(added.draft).warnings.some(w => w.code === 'deferred_segment'), true);
});

test('新增排除项必须位于所编辑网段内，重复提示"已存在"（规则 7）', () => {
  const draft = S.fromSettings({ seeds: ['10.0.0.1'], allowed_cidrs: ['10.0.0.0/24'], excluded_cidrs: ['10.0.0.9/32'], bootstrap_cidrs: [], read_management_addresses: false });
  const uiId = draft.segments[0].uiId;
  assert.deepStrictEqual(S.addExclusion(draft, uiId, '10.0.0.9'), { ok: false, code: 'duplicate', message: '已存在' });
  assert.strictEqual(S.addExclusion(draft, uiId, '10.0.1.9').code, 'outside');
  assert.strictEqual(S.addExclusion(draft, uiId, '10.0.0.9/24').code, 'not_single');
  assert.strictEqual(S.addExclusion(draft, uiId, '').code, 'empty');
  const ok = S.addExclusion(draft, uiId, '10.0.0.10');
  assert.strictEqual(ok.ok, true);
  assert.strictEqual(ok.draft.segments[0].excludedIPs.length, 2);
  assert.deepStrictEqual(S.toSettings(ok.draft).excluded_cidrs, ['10.0.0.9/32', '10.0.0.10'], '顺序稳定；新录入的值按用户输入保存，规范化由后端完成');
});

test('删除排除项才从集合移除，且记录被显式移除的键（规则 6）', () => {
  const draft = S.fromSettings({ seeds: ['10.0.0.1'], allowed_cidrs: ['10.0.0.0/24'], excluded_cidrs: ['10.0.0.9/32', '10.0.0.10/32', '10.0.0.9/32'], bootstrap_cidrs: [], read_management_addresses: false });
  const removed = S.removeExclusion(draft, '10.0.0.009');
  assert.deepStrictEqual(removed.draft.explicitlyRemovedExclusionKeys, ['10.0.0.9/32']);
  assert.deepStrictEqual(S.toSettings(removed.draft).excluded_cidrs, ['10.0.0.10/32'], '同一地址的重复项一起移除');
});

test('起点：必须在管理范围内且未被排除，至少保留一个（规则 8）', () => {
  const draft = S.fromSettings({ seeds: ['10.0.0.1'], allowed_cidrs: ['10.0.0.0/24'], excluded_cidrs: ['10.0.0.9/32'], bootstrap_cidrs: [], read_management_addresses: false });
  assert.strictEqual(S.addSeed(draft, '10.0.0.2').ok, true);
  assert.strictEqual(S.addSeed(draft, '10.0.0.1').code, 'duplicate');
  assert.strictEqual(S.addSeed(draft, '10.0.9.9').code, 'outside');
  assert.strictEqual(S.addSeed(draft, '10.0.0.9').code, 'excluded');
  assert.strictEqual(S.addSeed(draft, '10.0.0.0/24').code, 'not_single');
  assert.deepStrictEqual(S.seedStatus(draft, '10.0.0.2'), { ok: true });
  const historyExcluded = S.toSettings(S.removeSegment(draft, 'seg-1').draft).excluded_cidrs;
  assert.deepStrictEqual(historyExcluded, ['10.0.0.9/32']);
  const noSegments = S.fromSettings({ seeds: [], allowed_cidrs: [], excluded_cidrs: [], bootstrap_cidrs: [], read_management_addresses: false });
  assert.strictEqual(S.addSeed(noSegments, '10.0.0.2').code, 'outside');
  assert.strictEqual(S.removeSeed(draft, '10.0.0.1').code, 'last_seed');
  const two = S.addSeed(draft, '10.0.0.2').draft;
  assert.strictEqual(S.removeSeed(two, '10.0.0.1').ok, true);
  assert.deepStrictEqual(S.toSettings(S.removeSeed(two, '10.0.0.1').draft).seeds, ['10.0.0.2']);
});

test('网段收窄后重新校验：不能归属的排除项转历史且有效集合不变（规则 6/7）', () => {
  const draft = S.fromSettings({ seeds: ['10.0.0.1'], allowed_cidrs: ['10.0.0.0/24'], excluded_cidrs: ['10.0.0.9/32'], bootstrap_cidrs: [], read_management_addresses: false });
  const narrowed = JSON.parse(JSON.stringify(draft));
  narrowed.segments[0].cidr = '10.0.0.128/25';
  assert.deepStrictEqual(S.effectiveRanges(S.toSettings(narrowed)).excluded, S.effectiveRanges(S.toSettings(draft)).excluded, '排除区间本来就不受网段收窄影响');
  const revalidated = S.revalidateExclusions(narrowed);
  assert.deepStrictEqual(revalidated.movedToHistory, ['10.0.0.9/32']);
  assert.strictEqual(revalidated.draft.preservedLegacyExclusions.length, 1);
  assert.deepStrictEqual(S.toSettings(revalidated.draft).excluded_cidrs, ['10.0.0.9/32'], '不因收窄而删除排除项');
});

test('修改网段：保留自身排除项、超出范围的转历史、重复与重叠被拒绝（规则 3/6）', () => {
  const draft = S.fromSettings({ seeds: ['10.0.0.1'], allowed_cidrs: ['10.0.0.0/24', '10.1.0.0/24'], excluded_cidrs: ['10.0.0.9/32'], bootstrap_cidrs: [], read_management_addresses: false });
  const uiId = draft.segments[0].uiId;
  const unchanged = S.editSegment(draft, uiId, '10.0.0.0/24');
  assert.strictEqual(unchanged.unchanged, true, '同样的值不算修改');
  assert.strictEqual(S.editSegment(draft, uiId, '10.1.0.0/24').code, 'duplicate');
  assert.strictEqual(S.editSegment(draft, uiId, '10.0.0.0/8').code, 'overlap', '覆盖到 10.1 段');
  assert.strictEqual(S.editSegment(draft, 'seg-missing', '10.2.0.0/24').code, 'missing');
  const widened = S.editSegment(draft, uiId, '10.0.0.0/8');
  assert.strictEqual(widened.ok, false, '与另一段重叠时必须拒绝，不自动拆段');
  const narrowed = S.editSegment(draft, uiId, '10.0.0.128/25');
  assert.deepStrictEqual(narrowed.movedToHistory, ['10.0.0.9/32'], '排除项落到段外');
  assert.deepStrictEqual(S.toSettings(narrowed.draft).excluded_cidrs, ['10.0.0.9/32'], '只是转历史，不删除');
  assert.deepStrictEqual(S.effectiveRanges(S.toSettings(narrowed.draft)).excluded, S.effectiveRanges(S.toSettings(draft)).excluded);
  const sameScope = S.editSegment(draft, uiId, '10.0.0.0/25');
  assert.strictEqual(sameScope.ok, true);
  assert.deepStrictEqual(sameScope.movedToHistory, [], '10.0.0.9/32 仍在 10.0.0.0/25 内');
  assert.strictEqual(sameScope.draft.segments[0].excludedIPs.length, 1, '排除项留在原段内');
});

test('形态检查：拒绝多余字符与多个斜杠，但不解析 IPv6（规则 11）', () => {
  const draft = S.fromSettings({ seeds: ['10.0.0.1'], allowed_cidrs: ['10.0.0.0/24'], excluded_cidrs: [], bootstrap_cidrs: [], read_management_addresses: false });
  const uiId = draft.segments[0].uiId;
  assert.strictEqual(S.addSegment(draft, '10.0.1.0/2410.0.2.0/16').code, 'garbage', '两个斜杠必须被拒绝');
  assert.strictEqual(S.addSegment(draft, '10.0.1.0/24 10.0.2.0/24').code, 'garbage', '空格分隔的多值必须被拒绝');
  assert.strictEqual(S.addExclusion(draft, uiId, '10.0.0.1/3210.0.0.2/32').code, 'garbage');
  assert.strictEqual(S.addSeed(draft, '10.0.0.110.0.0.2').code, 'garbage', '五段 IPv4 是输入错误');
  assert.strictEqual(S.addSeed(draft, 'core-sw-01').code, 'garbage', '起点必须是 IP，不接受主机名');
  assert.strictEqual(S.editSegment(draft, uiId, '10.0.0.0/24x').code, 'garbage');
  const v6 = S.addSegment(draft, '2001:db8::/64');
  assert.strictEqual(v6.ok, true, 'IPv6 形态合法，交后端校验');
  assert.strictEqual(v6.deferred, true);
  assert.strictEqual(S.addExclusion(S.fromSettings({ seeds: [], allowed_cidrs: ['2001:db8::/64'], excluded_cidrs: [], bootstrap_cidrs: [], read_management_addresses: false }), 'seg-1', '2001:db8::9').ok, true, 'IPv6 排除项不本地解析');
});

test('validateDraft：排除掉起点本身必须报错，全 IPv6 配置仍交后端（规则 8/11）', () => {
  const draft = S.fromSettings({ seeds: ['10.0.0.1'], allowed_cidrs: ['10.0.0.0/24'], excluded_cidrs: [], bootstrap_cidrs: [], read_management_addresses: false });
  assert.strictEqual(S.validateDraft(draft).ok, true);
  const drawn = S.addExclusion(draft, draft.segments[0].uiId, '10.0.0.1');
  assert.strictEqual(drawn.ok, true, '先允许录入，再由预检拦截');
  const bad = S.validateDraft(drawn.draft);
  assert.strictEqual(bad.ok, false);
  assert.ok(bad.errors.some(e => e.message.includes('10.0.0.1')), JSON.stringify(bad.errors));
  const v6 = S.fromSettings({ seeds: ['2001:db8::1'], allowed_cidrs: ['2001:db8::/64'], excluded_cidrs: [], bootstrap_cidrs: [], read_management_addresses: false });
  assert.strictEqual(S.validateDraft(v6).ok, true, 'IPv6 起点不在本地判定范围内');
});

test('validateDraft：缺网段或缺起点是错误，待后端校验是提示', () => {
  const empty = S.fromSettings({ seeds: [], allowed_cidrs: [], excluded_cidrs: [], bootstrap_cidrs: [], read_management_addresses: false });
  const bad = S.validateDraft(empty);
  assert.strictEqual(bad.ok, false);
  assert.deepStrictEqual(bad.errors.map(e => e.code), ['no_segments', 'no_seeds']);
  const good = S.validateDraft(S.fromSettings(baseline()));
  assert.strictEqual(good.ok, true);
  assert.strictEqual(good.errors.length, 0);
  assert.deepStrictEqual(good.warnings, []);
});

test('纯函数不修改入参', () => {
  const before = JSON.stringify(baseline());
  const draft = S.fromSettings(baseline());
  S.toSettings(draft);
  S.addSegment(draft, '10.0.1.0/24');
  S.addExclusion(draft, draft.segments[0].uiId, '10.201.1.3');
  S.removeExclusion(draft, '10.201.1.2/32');
  S.removeSegment(draft, draft.segments[0].uiId);
  S.revalidateExclusions(draft);
  S.addSeed(draft, '10.201.1.1');
  S.validateDraft(draft);
  assert.strictEqual(JSON.stringify(baseline()), before);
  assert.notStrictEqual(S.fromSettings(baseline()).segments[0].uiId, '1');
});

test('IPv4 前缀与区间运算的边界', () => {
  assert.deepStrictEqual(S.v4Prefix('10.0.0.5').text, '10.0.0.5/32');
  assert.strictEqual(S.v4Prefix('10.0.0.256'), null);
  assert.strictEqual(S.v4Prefix('10.0.0.0/33'), null);
  assert.strictEqual(S.v4Prefix('abc'), null);
  assert.strictEqual(S.v4Prefix('10.0.0.1/24').net, '10.0.0.0');
  assert.strictEqual(S.normalizeKey('010.000.000.001'), '10.0.0.1/32', '前导零按同一地址归一');
  assert.strictEqual(S.normalizeKey('2001:DB8::1'), '2001:db8::1', '非 IPv4 只做去空白与小写');
  assert.deepStrictEqual(S.mergeIntervals([{ start: 1, end: 5 }, { start: 6, end: 9 }]), [{ start: 1, end: 9 }]);
  assert.deepStrictEqual(S.subtractIntervals([{ start: 0, end: 9 }], [{ start: 3, end: 4 }]), [{ start: 0, end: 2 }, { start: 5, end: 9 }]);
  assert.deepStrictEqual(S.subtractIntervals([{ start: 0, end: 9 }], [{ start: 0, end: 9 }]), []);
  assert.strictEqual(S.intervalHosts([{ start: 0, end: 4294967295 }]), 4294967296n, '整段 IPv4 也不会溢出');
  assert.strictEqual(S.intervalText([]), '(空)');
  assert.strictEqual(S.effectiveRanges({ allowed_cidrs: ['10.0.0.0/24'], excluded_cidrs: ['10.0.0.0/24'] }).effectiveHosts, 0n);
});


test('移除开关后旧false配置也始终启用LLDP地址读取，保留允许范围与排除', () => {
 const before = baseline(); before.read_management_addresses = false;
 const draft = S.fromSettings(before);
 const after = S.toSettings(draft);
 assert.strictEqual(after.read_management_addresses,true);
 assert.deepStrictEqual(after.allowed_cidrs,before.allowed_cidrs);
 assert.deepStrictEqual(after.excluded_cidrs,before.excluded_cidrs);
 assert.deepStrictEqual(after.seeds,before.seeds);
});
test('采集频率：分/时/日往返、保留手选单位及显示当前频率', () => {
 for(const [value,unit,label] of [[7,'minute','每 7 分钟采集一次'],[2,'hour','每 2 小时采集一次'],[3,'day','每 3 天采集一次'],[120,'minute','每 120 分钟采集一次']]){
  const input={...baseline(),collection_interval:{value,unit}};
  const output=S.toSettings(S.fromSettings(input));assert.deepStrictEqual(output.collection_interval,input.collection_interval);
  assert.strictEqual(S.collectionFrequency(output.collection_interval),label);assert.strictEqual(S.validateDraft(S.fromSettings(input)).ok,true);
 }
 for(const interval of [{value:0,unit:'minute'},{value:-1,unit:'hour'},{value:1.5,unit:'day'},{value:'',unit:'minute'},{value:1,unit:'second'},{value:1e15,unit:'day'}]){
  assert.strictEqual(S.validCollectionInterval(interval),false);
  const draft=S.fromSettings({...baseline(),collection_interval:interval});assert.strictEqual(S.validateDraft(draft).ok,false);
 }
 assert.strictEqual('collection_interval' in S.toSettings(S.fromSettings(baseline())),false,'旧设置不新增未提交的频率');
});
test('拓扑扫描频率：0关闭，分/时/日独立保存且不影响接口采集',()=>{
 for(const [value,unit] of [[0,'minute'],[5,'minute'],[2,'hour'],[3,'day'],[0,'day']]){
  const settings={...baseline(),collection_interval:{value:4,unit:'minute'},topology_scan_interval:{value,unit}};
  const draft=S.fromSettings(settings),saved=S.toSettings(draft);assert.deepStrictEqual(saved.topology_scan_interval,settings.topology_scan_interval);assert.deepStrictEqual(saved.collection_interval,settings.collection_interval);assert.strictEqual(S.validateDraft(draft).ok,true);
 }
 assert.match(S.topologyScanFrequency({value:0,unit:'hour'}),/已关闭自动更新/);
 assert.strictEqual(S.topologyScanFrequency({value:2,unit:'hour'}),'每 2 小时更新一次');
 for(const interval of [{value:-1,unit:'minute'},{value:1.5,unit:'day'},{value:'',unit:'minute'},{value:0,unit:'second'}])assert.strictEqual(S.validTopologyScanInterval(interval),false);
});
