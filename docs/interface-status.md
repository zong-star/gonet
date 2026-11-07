# 接口运行状态与信锐聚合反向确认

2026-11-06，版本 `0.18.0-interface-status-dev`，数据库 schema 12。

## 实现与兼容性

扩展现有 `model.Interface`，复用现有 SNMP 会话、GETBULK/WALK、重试和 PDU 预算。没有新建接口资产表：`scan_interface_facts` 继续保存不可变的扫描证据，`devices.interface_status` 只缓存当前接口运行状态，内容使用同一个接口模型。接口匹配优先使用设备内唯一且精确的 ifName，ifIndex 只表示当前 SNMP 索引；旧扫描索引不会被运行状态任务改写。缺少唯一、可信接口映射时返回 unknown，不按旧 ifIndex 或可编辑展示名称猜测。

后台采集随 `serve` 启动，首次立即执行，默认每 4 分钟采集一次。它只访问已有可见、已核验交换机及其 verified 管理地址，不扫描新地址，不请求 LLDP，也不修改发现、端口、链路生命周期或上联路径选择。物理以太接口（ifType 6）、逻辑聚合（161）和已有原生成员证据识别的聚合接口均保留；华为 ifType 53 聚合不被强行改成 161。其他逻辑接口不加入运行状态缓存。本次没有新增 VLAN、MAC、ARP、光功率或 STP 配置采集。

配置示例：

```yaml
interface_status:
  disabled: false
  interval: 4m
  stale_after: 12m
  workers: 4
  inference_stale_after: 72h
```

网络 timeout、retries、device_timeout、max_repetitions、max_pdus_per_device 沿用 `snmp` 配置。整个采集周期和单设备请求均有 deadline；不会重叠启动周期。多服务实例通过专用 advisory lock `(207026,2)` 选出采集执行者。状态缓存使用短行锁事务、阻止较旧任务覆盖较新记录；发现扫描仍使用原锁 `(207026,1)`。网络采集期间不持有数据库事务。

一次设备采集的列不完整、行解析失败、超时或 uptime 不稳定时，拒绝整次样本，不拼接不完整状态。失败保留最后成功的 admin/oper/last_change 和采样时间，记录新的 attempted_at、failed 状态及经过过滤的错误码。下一次成功快照中消失的接口保留为 missing，不继续当成 UP。读取时实时判定 stale，不等待下一次采集。

## TimeTicks

读取 ifIndex、ifDescr、ifType、ifName、ifAlias、ifAdminStatus、ifOperStatus、ifLastChange，采集前后读取 sysUpTime。`last_change` 为原始 uint32 TimeTicks；非零且位于当前 uptime 周期时，估算 `last_change_at = 采样时间 - (sysUpTime - ifLastChange) × 10ms`。0 表示变化早于代理初始化，日期留空。无法定位当前 uptime 周期时保留 ticks、日期留空；采集中重启或回绕则样本失败。日期明确标记 `estimated_current_uptime_cycle`，不将 ticks 当 Unix 时间。定义依据：[RFC 2863](https://www.rfc-editor.org/rfc/rfc2863.html)。

## 状态与 API

新增 `GET /api/v1/devices/{id}/interfaces`，采用原设备可见范围及 Session / Bearer 权限，topology_read 和 topology_compact 均可查询。响应为现有 `{data, meta}` 信封，`data.interfaces` 返回接口列表，包含 if_index、name、description、alias、type、admin_status、oper_status、last_change、last_change_at、sys_up_time、status_collected_at、status_attempted_at、status_collection_state。管理状态支持 up/down/testing；运行状态保留标准 1–7 对应的 up/down/testing/unknown/dormant/not_present/lower_layer_down。新增接口响应上限 8 MiB，超出返回 422。

```json
{
  "data": {
    "device_id": "1",
    "status_collection_state": "success",
    "status_attempted_at": "2026-11-06T09:55:00Z",
    "interfaces": [{
      "if_index": 78,
      "name": "ge1_1_29",
      "type": 6,
      "admin_status": "up",
      "oper_status": "up",
      "last_change": 0,
      "last_change_at": null,
      "last_change_state": "before_agent_initialization",
      "status_collected_at": "2026-11-06T09:55:00Z",
      "status_collection_state": "success"
    }]
  },
  "meta": {"request_id": "示例，实际响应还包含原有元数据"}
}
```

以上为节选示例，完整真实 handler 样本见[验收样本](acceptance/interface-status-2026-11-06/http-samples.json)，两个 OpenAPI 文档包含完整契约。

`GET /api/v1/topology` 的物理 link 增加 source_admin_status、source_oper_status、target_admin_status、target_oper_status、link_oper_status、status_collected_at、source/target_status_collected_at、source/target_collection_state 及 aggregation。source/target 分别对应 device_a/device_b；新版物理邻居响应的 source/target 对应 local/remote。两端成功采样时间不同时，公共时间取较早值；缺一端时公共时间为空。

| link_oper_status | 判定 |
| --- | --- |
| up | 两端采样有效且均 oper up |
| degraded | 两端采样有效，一端 up、另一端明确非 up |
| down | 两端采样有效，均明确非 up |
| admin_down | 两端采样有效，至少一端管理关闭 |
| unknown | 无样本、采集失败、接口映射歧义、testing/dormant/unknown 等不能确定运行状态 |
| stale | 已有两端采样，但至少一端超过阈值或采样时间在未来 |

优先级为缺失→过期→采集失败→管理关闭→未知/测试→UP/DOWN。一端有明确关闭但另一端无可靠采样时，整体仍 unknown，端点字段保留各自事实。拓扑 active 不代表运行 up。

原有 `/topology`、`/topology/summary`、`/devices/{id}`、`/devices/{id}/neighbors` 路由、原字段及身份/拓扑语义保留。旧 `oper_status` 枚举仍为 up/down/degraded/unknown：管理关闭映射为 down，过期映射为 unknown；精确区分使用新增 `link_oper_status`。原上联路径精简容量保持，聚合整体运行状态根据所有已返回物理成员计算，不继承首成员。新增物理邻居字段可能使单页可容纳的条目减少，既有 next_cursor/has_more 分页机制继续生效。

## 聚合反向确认

沿用现有原生成员证据及已确认物理 LLDP links，策略版本为 `peer-lag-v2`。只从 native 直接采集关系推断，不用推断结果继续推断。

按信锐设备、对端设备和对端原生聚合组分组；至少两条不同、已确认的物理链路映射到对端不同成员，且对端组数据完整、映射无冲突且未过期时，建立有效 inferred 连接。单成员返回 `inference_status=peer_inferred_member`，不会生成有效逻辑聚合 ID。对端不完整时返回 partial，冲突返回 conflict；过期推断保留诊断并标记 stale，不作为有效逻辑聚合展示。接口 DOWN 不影响成员归属判断。新扫描提交成员变化后，查询基于新扫描重新计算，不跨扫描继承旧成员。

关系包含 aggregation_source（native / peer_inferred）、local_device_id、remote_device_id、remote_aggregation_id、member_interfaces、evidence_link_ids、inference_status、inferred_at。member_interfaces 为设备内接口索引列表，evidence_link_ids 引用原物理 link。inferred_at 使用证据快照提交时间，确保多次查询一致。推断关系只在查询层派生，真实本端 interface_name 与 aggregate_if_index 均为空；display_name 仅为明确标注的展示标签。

当前自动推断的信锐型号边界沿用已有已验证 TS7914 指纹；不根据名字、IP 或厂商展示字段猜测，不扩展未经验证型号。H3C/华为原生来源、标准/私有 MIB 适配边界保持原实现。

## 迁移与回退

```powershell
.\gonet.exe migrate up --config config.yaml
```

`000012_interface_status.up.sql` 为 devices 增加 interface_status、status_attempted_at、status_collection_state、status_error，以及按 device_id/scan_id 读取接口事实的索引。旧数据默认 unknown，原设备/端口/link_id 与扫描证据不变。只读导出对旧 schema 10/11 仍兼容。迁移使用原全局迁移锁并可重复执行。

回退应用可恢复备份的旧二进制，schema 12 的附加字段无需立即撤销。需要删除新缓存时才在停止新服务后审阅执行配套 down.sql；不要对业务库运行集成测试的 resetDB。此次已自动执行迁移和服务切换，详见验收记录。


## 2026-11-06：扫描设置中的采集频率

扫描设置新增“接口状态采集频率”卡片，可输入正整数并手动选择“分 / 时 / 日”。“当前采集频率”只显示服务端已保存的有效设置，编辑草稿不会改变当前值。点击原“保存设置”按钮后，后台重新计算下次采集时间，无需再次重启服务；正在进行的一轮正常完成，不创建重叠采集。该选项控制 IF-MIB 接口状态采集，原手动拓扑更新入口保持。

原 `PUT /api/settings` 请求和 `/api/state` 的 settings 响应新增可选字段：

```json
{"collection_interval": {"value": 2, "unit": "hour"}}
```

unit 支持 minute、hour、day。数字与所选单位一并保存在 scope，实际时长写入 config.yaml 的 interface_status.interval。旧客户端不提交此字段时保留原周期；无效值不会写入文件。修改周期时将接口状态过期阈值同步调整为三个周期，避免日级采集时刚采集的数据提前过期。访问控制、会话及 CSRF 要求沿用原设置接口。


## 2026-11-06：独立的完整拓扑扫描周期

扫描设置的两个频率卡片并排显示：左侧继续控制 IF-MIB 接口状态；右侧控制完整“更新拓扑”流程。右侧数值为 0 时关闭自动更新，默认 0，不影响手动更新。设置请求新增可选 topology_scan_interval 字段，详见 [自动扫描说明](automatic-scan.md)。
