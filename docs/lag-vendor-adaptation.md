# 链路聚合采集与查询

0.16.0-peer-lag-dev 增加基于对端成员映射的信锐聚合推断。H3C/华为一端直接确认聚合成员，且成员通过本扫描物理 LLDP 链路连接到同一台已核验 TS7914 时，v4 返回一个 `inferred` 聚合连接；信锐真实聚合接口名称和 ifIndex 保持 null。两个物理成员保留两个 link_id，主拓扑分别画线并可独立点击。逻辑组只关联成员，不压缩物理数据。

新版界面优先请求 v4，明确不支持时回退 v3/v2。`GET /api/v1/devices/{id}/uplink-path?schema_version=4` 返回一跳及全部已观察成员；`neighbors?schema_version=4` 仍每个物理 link 一条结果并支持分页；拥有完整拓扑权限的客户端可使用 `/api/v1/topology?schema_version=4`。规则版本为 `peer-lag-v1`，组 ID 绑定扫描快照。

推断只使用直接采集来源，不能用推断组继续反推其他组。同一直接组指向多个独立设备、成员争用或可信映射冲突时不成组，全部物理链路继续保留。信锐真实成员全集未知时 `member_data_status=partial`；这不影响 `status=inferred` 作为可用的逻辑聚合结果，也不表示接口 Up 或 LACP 已协商。

该功能复用 schema 11 的已提交接口、成员和 LLDP 证据，不新增推断表或数据库迁移。旧批次有足够证据时可只读重放；本轮不能拼接旧轮成员事实。型号判断使用设备身份和 TS7914 分类依据，不使用设备名称、IP 或可编辑厂商标签。验证和发布记录见本次验收。

以下为 0.15 采集来源及 v1/v2/v3 的兼容合同。原有厂商采集证据仍需要数据库 schema 11。

| 适配开关 | 范围 | 取得的事实 |
| --- | --- | --- |
| `huawei_s5735_qa2_v200r023_lag` | S5735-L8T4S-QA2、V200R023C00SPC500、sysObjectID 2011.2.23.967 | 私有组到真实 ifIndex、配置成员；兼容真实 ifType=53 |
| `h3c_s5560_6628p47_lag` | S5560X-30C-EI、Release 6628P47、sysObjectID 25506.1.1460 | 私有静态/动态模式和 selected bitmap，与标准成员集合对照 |
| `lldp_dot3_lag` | 标准 LLDP-EXT-DOT3，仅保留经过行索引/稳定性检查的通告 | 本端/远端聚合能力、状态和原始聚合标识 |

在原 `snmp.adapters` 列表中追加需要的开关，保留已有 TS/RS 编码适配项。默认不启用厂商来源，也不扩大到未经验证的固件。`snmp.lag_timeout` 默认 3s、`snmp.lag_max_pdus` 默认 32；都受设备总预算约束。根据来源耗时、PDU 数和预算耗尽诊断决定是否调整，不通过 `view_verified=true` 绕过覆盖验证。

```yaml
snmp:
  adapters:
    - sundray_ts7914_chassis38_20251010
    - huawei_s5735_qa2_v200r023_lag
    - h3c_s5560_6628p47_lag
    - lldp_dot3_lag
  lag_timeout: 3s
  lag_max_pdus: 32
```

以上仅为合并配置的片段，不能作为完整 config.yaml 使用。本次源码实施没有改动本机生产配置。

华为通过同一设备内的私有组索引关联接口，不将组号或接口名称中的数字当 ifIndex。现场组索引 0 对应接口 19，而不是接口名称 Eth-Trunk0。H3C 根据经过验证的成员位图集合匹配标准聚合关系，不按聚合组号猜测。DebugRxState=5 不再单独证明静态模式。

信锐 TS7914 可保存 IF-MIB 的聚合角色和从邻居收到的聚合通告，当前没有经过验证的核心本端直接成员来源。其远端标识 27 不被当作核心 ifIndex；v1/v2/v3 保留 partial/unknown。v4 按上文规则创建推断组，无需等待本端直接成员来源。

**查询版本与状态**

- 省略版本仍使用原有 API；v1 保持 endpoint_a/endpoint_b 结构。
- `schema_version=2` 保持原有 kind / aggregation 合同，增加 `aggregation_status` 和单端证据的 `aggregation_diagnostics`。客户端不能仅凭 aggregation=null 得出无聚合。
- 路径与邻居支持 `schema_version=3`。设备详情、摘要仍选择 v2，搜索仍使用原合同。
- v3 的路径边始终有 aggregation 对象；status 为 confirmed、partial、unknown、none 或 conflict。member_data_status 独立为 complete、partial、unknown。
- v3 的成员继续使用 `from/to`，每条含 link_id 和 membership_status。只有 confirmed 的双端关系参与逻辑折叠；local_only / remote_only 成员仅用于展示单端事实。
- 聚合通告没有映射到本端组时，可为 status=partial、member_data_status=unknown、member_links=null；原始通告保留其 observer_device_id 和编号语义。
- 未匹配到物理链路的配置成员通过 unpaired_members 展示，整体列表标为 partial。接口运行状态缺证据时仍为 unknown。

例：`GET /api/v1/devices/77/uplink-path?schema_version=3`。如果新批次成功取得 77 的成员，77↔74 可展示 Eth-Trunk1 ↔ Bridge-Aggregation2，成员 link 65/66。v3 中 74↔核心保留单端结果；同一数据用 v4 可返回已知 BA1 ↔ 信锐推断聚合，成员 link 240/253，状态为 inferred。

**邻居分页**

`GET /api/v1/devices/1/neighbors?schema_version=3&limit=20&neighbor_device_id=74` 可定点查全部并行物理链路。省略 neighbor_device_id 可查看所有邻居。响应 has_more=true 时，用 next_cursor 原样发起下一页，保留 limit/state/neighbor_device_id。

cursor 绑定查询、快照和可见端点事实。签名无效返回 400 INVALID_CURSOR；快照/范围变化返回 409 CURSOR_STALE，需要从第一页重新查询。服务重启后旧 cursor 失效。界面会逐页取得邻居，不再把核心前 20 条当全部结果。

matching_link_count 是过滤后分页前的物理条数，returned_link_count 是当前页数量，returned_unique_neighbor_count 是当前页唯一对端数。v3 的 truncated / response_truncated 表示字节预算裁剪，正常分页用 has_more；v2 保留原有 truncated 口径，并增加 has_more / next_cursor / response_truncated。发生字节裁剪后游标从实际已返回位置继续，不跳过被裁剪条目。

路径成员不静默裁剪；单条必要路径超出 12 KiB 时返回 RESULT_TOO_LARGE。查询读取已提交批次，不实时触发 SNMP、扫描或 CLI。

**迁移与回退**

迁移 11 扩展成员来源和选择状态，并增加 scan_lag_groups / scan_lag_evidence；设备、端口和物理链路主键保持不变。旧批次没有新证据时返回未知。新程序可读取 schema 10 用于预览，但启用新采集前必须完成迁移 11。

退回旧程序前应停止新来源写入，验证旧程序读取新增枚举的行为。关闭厂商适配只影响后续采集，不删除历史证据。迁移 11 的 down SQL 明确拒绝破坏性删除；正常应用回退不执行 down migration。

可在源码工作区中显式运行 `pwsh -File scripts/test-lag-isolated.ps1` 建立独立回环测试实例，完成迁移和所有数据库测试后停止实例。该脚本使用工作区临时目录和临时口令，不使用业务 GONET_DATABASE_URL。PostgreSQL 安装位置和测试端口可通过参数指定。普通单元测试不自动启动第二个实例。

实现和验证记录见验收记录。Dify 工作流没有修改；后续联调需显式选择版本并按新状态解释。


## 2026-11-06 状态采集阶段规则更新

当前 `peer-lag-v2` 覆盖此前 v1 的单成员成组规则：单成员只产生 peer_inferred_member 诊断，至少两条不同成员物理链路、对端组完整且证据未过期才可输出有效 inferred 连接。conflict、partial 和 stale 不作为有效逻辑聚合展示；物理链路继续逐条显示。`aggregation_source` 明确区分 native 和 peer_inferred；推断名称仅为展示标签，真实本端接口名称和 ifIndex 保持 null。详见 [接口状态开发说明](interface-status.md)。
