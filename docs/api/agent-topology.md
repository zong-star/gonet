# GoNet 只读拓扑 API

0.16 新增 `schema_version=4`：路径与邻居可识别 H3C/华为直接成员映射支持的信锐对端推断聚合。`aggregation.status=inferred` 表示可用的逻辑聚合，`confirmed` 保留两端直接确认语义；真实信锐组名和 `aggregate_if_index` 未取得时为 null。组中每条物理成员保留独立 link_id、from/to、LLDP observations，邻居分页按物理链路计数。完整拓扑 v4 的 `links` 与 `aggregate_connections` 分开返回，完整拓扑权限要求不变。

调用路径示例：`GET /api/v1/devices/74/uplink-path?schema_version=4`；读取全部物理成员：`GET /api/v1/devices/1/neighbors?schema_version=4&neighbor_device_id=74`，然后沿 next_cursor 翻页。v4 的规则版本为 `peer-lag-v2`。v1/v2/v3 合同保持，明确不支持 v4 时才回退旧版本。详细状态与限制见[聚合说明](../lag-vendor-adaptation.md)和验收记录。

登录控制台后访问 `/?page=api`，为每个客户端新增独立 Key 并填写 IP 白名单。完整 Key 只在创建成功时显示一次。名称、描述、权限和白名单可随时编辑，保存后立即生效。在编辑弹窗中确认删除后，该 Key 立即失效。精简查询契约可从 `/docs/agent-openapi.yaml` 下载，通用契约仍从 `/docs/openapi.yaml` 下载。 [精简 OpenAPI](agent-openapi.yaml) · [通用 OpenAPI](openapi.yaml)

## 接口与认证

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET / HEAD | `/api/v1/topology` | 完整拓扑 |
| GET / HEAD | `/api/v1/topology/summary` | 拓扑摘要 |
| GET | `/api/v1/devices?query={ip_or_name}` | 按已核验管理 IP、显示名或 sysName 搜索内部设备 ID |
| GET / HEAD | `/api/v1/devices/{device_id}` | 设备详情 |
| GET / HEAD | `/api/v1/devices/{device_id}/neighbors` | 设备邻居 |
| GET / HEAD | `/api/v1/devices/{device_id}/interfaces` | 接口运行状态与采集时间 |
| GET | `/api/v1/devices/{device_id}/uplink-path` | 最新已提交批次内到可见核心的已确认路径 |
| GET / HEAD | `/api/v1/topology/collection` | 采集缺口、设备结果及失败原因 |
| GET / HEAD | `/api/v1/admin/api-keys` | 脱敏列表，按创建时间倒序 |
| POST | `/api/v1/admin/api-keys` | 创建 Key，201 响应的 `key` 字段包含完整值 |
| PATCH | `/api/v1/admin/api-keys/{id}` | 更新名称、描述、权限或白名单 |
| DELETE | `/api/v1/admin/api-keys/{id}` | 删除 Key，成功返回 204 |

查询接口使用管理员会话或 `Authorization: Bearer <API_KEY>`。显式 Authorization 必须通过 Bearer 校验。无效 Key 返回 401，来源 IP 不在白名单返回 403。所有管理接口要求管理员会话，写操作还要求当前会话的 `X-GoNet-Token`。创建必须提供 `name`、`allowed_ips`，`description` 和 `profile` 选填。原管理员 OpenAPI 下载地址 `/api/v1/admin/agent-api/openapi.yaml` 继续提供通用契约。

### 精简查询权限

选择「精简拓扑查询」或在 Key 管理 API 提交 `"profile": "topology_compact"`。此权限允许专用契约中的七个 GET：设备搜索、详情、邻居、接口状态、到核心路径、拓扑摘要、采集诊断，与 Dify 工具一一对应。通用文档另有完整拓扑查询，共八个拓扑查询路径；完整拓扑未加入精简工具契约，精简 Key 请求它返回 `403 API_ROUTE_NOT_ALLOWED`。旧 Key 和省略权限字段创建的 Key 使用 `topology_read`。

- 设备搜索默认返回最多 5 条。遇到 `ambiguous=true` 时，按候选设备确认目标 ID。
- 邻居查询对精简 Key 默认返回最多 20 条当前活跃物理链路。会话或旧 Key 显式传 `limit` 也可使用紧凑响应。
- 到核心默认最多 3 条路径，每条最多 16 跳。双端确认的 LAG 占一跳，物理链路 ID 及端口配对见 `member_links`。路径依据同一扫描批次。带 `coverage_gap=true` 的结果表示采集覆盖有缺口。
- 精简响应预算为 12 KiB。可选候选或靠后的完整结果可能省略，`meta.response_truncated` 标示字节裁剪。单条必需结果超限返回 422。

## 升级与应急

1. 使用 GoNet 的既有数据库配置运行 `gonet migrate up --config config.yaml`。迁移 008 保存按批次的接口与 LAG 证据，迁移 009 添加 Key 权限类型，迁移 010 区分接口别名已采到空值与缺采。先完成迁移再启动新版。已有扫描仍可查询，其接口证据随下一轮采集补齐。
2. 首次启动读取 `--scope` 同目录的 `agent-api.json`，也可用已有的 `--agent-api-config` 指向原文件。原文件不存在时，读取旧环境变量 `GONET_AGENT_API_ENABLED` 和 `GONET_AGENT_READ_TOKEN_SHA256`。只导入旧配置中已启用的摘要，并保留已记录时间。
3. 旧实现没有应用层白名单。旧 Key 以 `0.0.0.0/0` 和 `::/0` 导入以维持原有访问范围，仍受既有 Nginx 网段限制。管理员可在管理页将其收窄至实际客户端出口地址。新建 Key 至少需要一个地址或网段。
4. 若密钥泄露，可在编辑弹窗中删除该 Key。需要通过 PostgreSQL 应急处理时，管理员可核对记录 ID 后删除对应记录，并保留导入记录，以免重启时再次导入旧 Key。

数据库保存 SHA-256 摘要和脱敏值。原始 Key 放在客户端的安全配置中。GoNet 为拓扑请求记录请求 ID、调用主体、路由、目标设备、状态码、结果条数和耗时。回退到早于迁移 009 的程序前，撤销精简 Key 或在入口保留对应路由限制。

## 显式选择新版端点与单路径

详情、邻居、上联、摘要四个 GET 可传 `schema_version=2`。搜索仍按现有契约查询内部 ID。Dify 上联工具的 OpenAPI `operationId` 为 `get_device_path_to_core`，实例若使用自定义名称，应在联调时核对其路由。

```text
GET /api/v1/devices?query=<IP或名称>
GET /api/v1/devices/<内部ID>?schema_version=2
GET /api/v1/devices/<内部ID>/neighbors?schema_version=2
GET /api/v1/devices/<内部ID>/uplink-path?schema_version=2&target=core
GET /api/v1/topology/summary?schema_version=2
```

- 新版 `data.schema_version` 为整数 `2`。邻居的 `local` / `remote`、路径边的 `from` / `to` 及聚合成员均使用共享端点。真实接口名来自 `interface_name`，管理员描述来自 `interface_description`。未知值为 `null`，真实采到空别名为 `""`。旧行的空别名保留未知。端口名有证据而索引未知时仍可展示端口名。缺可信厂商证据时，保守保留未知。
- 上联 `path_status` 为 `found`、`not_found` 或 `no_core_configured`。找到时 `path` 是一条从查询设备到核心的路径，源设备为核心时零跳。正常路径满足 `hop_count = edges.length = nodes.length - 1`。新版 `max_paths` 仅可省略或传 `1`，`max_hops` 为 `1–16`，默认 `16`。`SEARCH_BUDGET_EXCEEDED` 和 `RESULT_TOO_LARGE` 为不同的 422 错误。确认路径只说明拓扑证据，实时业务转发须依赖相应运行观测。
- `data_quality.snapshot_*` 描述实际读取的已提交批次。`latest_scan` 独立描述最近扫描，进行中或失败的扫描可与使用的旧快照并存。覆盖分别使用 `network`、`device_neighbors`、`device_to_core_query`。全网覆盖限定于 GoNet 当前配置下的预期可发现范围。缺乏查询范围覆盖证据时返回 `unknown`。邻居的匹配数、返回数和字节裁剪另行表达。摘要的 `count_definitions` 记录各项范围、单位、去重键和过滤状态，历史设备计入设备总量，物理链路按正式记录计数，逻辑聚合不另加到物理链路数，待核验项按条目键计数。
- 过期提示配置为服务进程环境变量 `GONET_TOPOLOGY_STALE_AFTER`，格式为正的 Go duration，必须为整秒，默认 `72h`。年龄达到阈值时 `stale=true`，时间不可信时为 `null`，`diagnostic_codes` 说明缺快照、缺时间或时间倒挂。`verification_status`、`topology_status` 与 `oper_status` 分别读取，运行状态缺观测时显示未知。
- 候选数据只在显式 `include_unverified=true` 时查询，观察者限定为源设备和已选路径节点，详见 `candidate_observer_device_ids`。省略、空数组和带原因的 `null` 分别表示未请求、可查且空、无法提供。候选裁剪不改变已选路径。
- 控制台设备详情自动请求新版并提供 SVG、逐跳表格和成员详情。外部客户端须确认实际发送版本参数并收到完整端点。回退时移除版本参数。旧响应端口文本语义未核实时，应显示“接口名未知”，独立列出旧端口文本。应用程序回退可保留向前兼容的迁移 010 列，数据库回退 SQL 仅在停用新版并完成相应备份及验证后执行。

开发和回归证据见 阶段验收目录。Dify 的真实工具参数及字段透传需在实例中完成独立验收。

## Nginx

使用随项目提供的代理模板。设置 `GONET_TRUSTED_PROXY_CIDRS=127.0.0.1/32`，与模板中的本机代理地址对应。GoNet 只接受来自显式信任代理且由代理覆写的单个 `X-Forwarded-For` 地址。直接访问时使用 TCP 对端地址。只读路由接收 Bearer，控制台继续通过登录会话认证。代理模板保留原有 TLS、客户端网段和 Host/Origin 检查。 [Nginx 模板](../../deploy/linux/nginx-gonet.conf.example)


## 聚合厂商扩展与分页（0.15.0-lag-dev）

路径与邻居可显式传 schema_version=3；详情和摘要仍使用 v2，搜索保持原合同。v3 路径的 aggregation.status 区分 confirmed/partial/unknown/none/conflict；member_data_status 单独说明 complete/partial/unknown。成员端点为 from/to，只有 confirmed 的双端成员形成逻辑聚合边。单端或仅通告证据不参与逻辑折叠。v2 兼容原结构并增加 aggregation_status / aggregation_diagnostics；aggregation=null 不再被解释为已确认无聚合。

邻居 v2/v3 支持 neighbor_device_id 和 cursor。has_more=true 时保留过滤和 limit，通过 next_cursor 继续；409 CURSOR_STALE 后从第一页重查。matching_link_count 是过滤后分页前的物理总数，returned_link_count 是当前页数量。v3 用 response_truncated 表示字节裁剪，用 has_more 表示分页；v2 保留旧 truncated 口径。

华为需要启用经过固件指纹约束的私有成员来源；信锐核心本端成员来源尚待取证，必须保留 partial/unknown。完整说明与配置见 [聚合适配说明](../lag-vendor-adaptation.md)。外部工作流本次没有自动修改。


## 2026-11-06：接口运行状态与聚合规则 v2

新增 `GET /api/v1/devices/{device_id}/interfaces`，沿用设备可见范围、Session / Bearer 认证以及 topology_read / topology_compact 权限。该接口只读取独立 IF-MIB 缓存，不触发扫描，响应上限 8 MiB。完整契约见同目录 OpenAPI。

接口字段包括 `if_index`、`name`（ifName）、`description`（ifDescr）、`type`（ifType）、`alias`（ifAlias）、`admin_status`、`oper_status`、`last_change`、`last_change_at`、`sys_up_time`、`status_collected_at`、`status_attempted_at`、`status_collection_state`。采集失败保留成功值并标记 failed；过期样本不代表当前状态。

完整拓扑的每条物理 link 增加两端状态、`link_oper_status`、采样时间和 `aggregation`。source 对应 device_a，target 对应 device_b；新版物理邻居返回中 source 对应 local，target 对应 remote。两端采样时间不同时，`status_collected_at` 取较早值。拓扑 active 与运行 up 独立。既有路径精简响应容量不变，`oper_status` 使用采样派生状态，未采到时仍为 unknown。

`aggregation_source=native` 表示自身采集关系，`peer_inferred` 表示对端反推。`inference_status=peer_inferred_member` 的单成员只有诊断关系，不生成有效逻辑聚合 ID；对端数据不完整或推断过期时状态为 partial，冲突为 conflict。仅至少两条不同成员的已确认 LLDP 物理链路且对端组完整时，连接才为 inferred。原始物理链路始终保留。默认推断过期阈值 72h，可用 interface_status.inference_stale_after 配置。

使用示例（凭据从调用方安全环境提供）：

```http
GET /api/v1/devices/1/interfaces
Authorization: Bearer <现有只读 Key>

GET /api/v1/topology?schema_version=4
Authorization: Bearer <topology_read Key>
```

完整状态矩阵、配置和迁移见 [本次开发说明](../interface-status.md)。

### 采集完整性诊断（0.20）

`schema_version=2/3/4` 的邻居和路径、v2 的摘要与设备详情增加
`data_quality.snapshot_status` 和 `data_quality.collection`。`snapshot_status`
描述正在读取的已提交快照；`latest_scan` 可以是之后启动的另一轮。
`collection.device_counts` 保留扫描器原始口径，计数可能重叠，不能相加；
`recorded_outcomes` 按可见正式设备的本轮记录分组，`not_recorded` 表示缺少记录，
可能是历史设备，不等于已知采集失败。`reason_counts` 为问题出现次数，不是设备数。

用现有只读 Key 调用 `get_collection_diagnostics`：

```http
GET /api/v1/topology/collection?schema_version=2&snapshot_id=35&limit=10
GET /api/v1/topology/collection?schema_version=2&snapshot_id=35&device_id=68
```

优先沿 `collection.details_url` 查询。`snapshot_id` 仅检查当前快照是否一致，
不是历史查询；快照变化返回 409。分页跟随 `next_cursor`，保留所有筛选条件。
游标绑定快照、筛选和明细；签名错误返回 400，数据变化返回 409。
`items.kind` 区分正式设备、未解析邻居、无正式设备关联的目标尝试。
`incomplete_components` 同时包含可选组件，不能单凭该列表推断邻居覆盖失败。
旧快照不补造过去没有记录的失败目标；新扫描会保存失败、未扫描的正式设备
和未成功的目标地址尝试。不返回原始错误文本、SNMP 密钥或配置内容。

邻居覆盖：已知采集失败、未扫描、部分采集、快照不稳定或未解析观测为 `gap`；
完整性所需验证缺失为 `unknown`，且始终提供原因。常见原因：

| 原因码 | 含义 |
| --- | --- |
| `device_collection_failed` / `device_unscanned` | 本轮有明确失败 / 未扫描记录 |
| `device_not_recorded_in_snapshot` | 本轮没有设备记录，无法断言是否尝试 |
| `collection_incomplete` / `lldp_rem_incomplete` | 必要采集不完整 / LLDP 邻居表不完整 |
| `snapshot_stability_unverified` | 不能确认采集期间快照稳定 |
| `snmp_view_unverified` | 本轮配置未声明 SNMP 读取视图已核验 |
| `lldp_receive_incomplete` | 未能验证相关端口的 LLDP 接收状态（新扫描记录） |
| `absence_evidence_unverified` | 正面采集成功，但不能用未观察到的内容证明不存在 |
| `unresolved_observations` | 仍有未解析邻居或端口 |
| `branch_link_not_observed_in_snapshot` | 查询分支使用了未在本轮观察到的历史链路 |

路径覆盖定义为：当前可见范围内，从源设备沿 active 链路到 `max_hops` 的分支，
遇到核心停止扩展；检查沿途设备覆盖和链路观察轮次。相关 `gap` 优先于
`unknown`，全部具备完整性证据才为 `covered`。不受无关分支的全网缺口直接降级。
返回 `evaluated_device_count`、`max_hops`、`definition` 和最多 10 个
`affected_device_ids`；`affected_devices_truncated` 说明是否还有更多受影响设备。
它不证明配置范围外或 LLDP 不可见的网络不存在，也不表示已枚举所有路径。
`found/confirmed`、覆盖状态、数据年龄和过期状态继续独立表达。

Dify 已导入旧规格时，从 `/docs/agent-openapi.yaml` 更新工具定义以添加
`get_collection_diagnostics`。原有工具 URL 和 Key 继续可用；摘要、邻居、路径
仍需使用对应的 v2/v3/v4 参数才能取得这些诊断字段。
