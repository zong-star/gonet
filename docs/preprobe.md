# 网段预探测与身份索引

## 0.21：一次更新完整探测管理范围

`scan` 和控制台“更新拓扑”现在会在同一任务内实际探测全部有效管理 IPv4 地址，每个地址一次；已有新鲜缓存也会刷新。范围仍来自扫描设置中的管理 IP 段减去排除项，重叠地址去重，普通子网跳过网络/广播地址，/31、/32 保留有效主机。IPv6 不进行地址枚举。

不再因为旧的 `max_hosts_per_run: 256`、60 秒阶段预算或递归 `max_targets` 结束预探测。这些旧批次字段仍可读取，低层批次回放接口保留兼容；产品的更新流程使用全范围模式。预探测使用独立的有界并发，`max_targets` 只限制随后完整 LLDP 递归采集；不会将探测响应或历史设备作为额外拓扑种子。

整轮 `discovery.run_timeout` 和“停止扫描”仍有效。完成时 `preprobe.full_range=true`、`termination_reason=range_complete`、`probe_completed=range_hosts`、`deferred=0`；停止/超时则明确返回 `canceled` / `run_deadline` 及剩余未尝试数。全范围完成说明全部地址已尝试，不代表全部地址在线、SNMP 成功或拓扑已完全核验。`admitted_candidates` 为完整递归采集的去重目标数，预探测数量单独查看 `preprobe`。

以下段落记录 0.11～0.20 的分批机制，供历史证据和低层回放参考。

从 0.11.0-dev 开始，普通控制台“更新拓扑”、CLI scan、计划任务的 scan 共用同一个协调器：
先在允许范围减排除范围内分批执行只读 SNMP 预探测，再从原核心种子沿 LLDP 递归。
探测池不是额外种子。名称、访问 IP、远端 Port ID 都不能代替本机 Chassis 建立设备关系。

## 配置与预算

```yaml
discovery:
  preprobe:
    enabled: true
    workers: 8
    timeout: 1s
    retries: 0
    host_timeout: 3s
    max_hosts_per_run: 256
    known_hosts_per_run: 64
    phase_timeout: 60s
    refresh_interval: 15m
```

省略整个 preprobe 配置时默认关闭，以兼容旧配置。随附示例与本机配置显式开启。
`known_hosts_per_run` 是需要刷新地址的配额上限，最多占本轮批次的一半；其余配额用于
持久化游标轮询。新鲜的成功身份跳过重复请求，失败地址在后续轮询中重试。

IPv4 以合并、扣除后的区间表示，不先展开整段地址。普通子网跳过网络/广播地址，
/31 和 /32 保留合法主机；IPv6 不枚举，原种子与 LLDP IPv6 递归仍按原策略运行。
排除项优先；范围变化重算摘要并复位游标，缓存每次使用都重新检查当前范围与新鲜度。

预探测新增 IP 最多使用全轮唯一目标预算扣除核心采集预留后的容量，核心采集预留至少
半轮预算（包含原种子）。同一 IP 先 probe 后 collect 只占一个唯一目标，但两个阶段的
队列、完成、失败、PDU 计数各自独立。预探测期限还受全轮期限三分之一约束。
阶段到期会保留已尝试结果，未发出的请求 deferred；核心采集继续。取消时游标只越过
连续、确已尝试或已有新鲜成功事实的地址，后完成的正面结果也保存，不跳过中间空洞。

只计算范围，不读凭据、不连接数据库、不请求设备：

```text
gonet scan --config config.yaml --plan
```

单地址基础诊断，不写数据库、不读取 LLDP 表或接口表：

```text
gonet probe --config config.yaml --target <允许范围内的IPv4地址>
```

第一组 GET 读取 sysObjectID、sysName、sysDescr、sysUpTime，第二组读取本机 Chassis
subtype/raw。每地址采用现有 profile 选择规则，每次独立会话；最多 10 个请求 PDU，
受 host_timeout 与阶段 context 双重限制。只有原有可隔离标量错误类别允许单 OID 兜底；
认证、超时、取消、PDU 上限不触发该兜底。不使用 ICMP 作为准入条件。

## 持久化与显示

升级先执行 `gonet migrate up --config config.yaml`。迁移 6 添加：

- `snmp_probe_results`：每个访问 IP 一行，`record` JSONB 保存 typed Chassis、规范化身份、
  系统事实、规则、profile 名、最近尝试状态、最近成功及身份成功时间、冲突前事实。
  `last_scan_id` 和 `matched_device_id` 为独立外键列，历史清理时 SET NULL；读取时以外键列为准。
- `snmp_probe_progress`：独立于扫描明细的范围摘要、轮询游标、刷新游标及阶段覆盖摘要。
- 地址来源约束扩展为接受 `snmp_preprobe`、`probe_cache`、`manual_supplement`，不伪装人工覆盖。

Chassis 没有唯一约束：多个访问地址可归于一个逻辑设备。只有直接完整采集验证成功，
才经本轮 ref → PostgreSQL ID 映射关联正式设备；没有 LLDP 路径的设备只留在探测池。
失败不清除成功事实、不刷新成功时间，也不产生链路缺失证据。系统成功但 Chassis 缺失
时保留“SNMP 可达，身份待核验”；不会刷新旧身份的新鲜度。

IP 返回不同 Chassis，或者两个阶段身份发生变化，保留旧证据并显示身份冲突，停止该地址
自动关联。需运维核对交换机更换、地址复用或映射配置后处理冲突，不会自动猜测合并。

控制台新增“SNMP 探测池”，支持搜索、分页与 JSON 导出，分别显示访问状态、身份缓存
新鲜度、范围资格、正式设备 ID、拓扑关联和下一步。地址旁“已核验访问地址”只说明该 IP
曾直接响应，不宣称是设备唯一主管理 IP。未响应不等于没有设备；未安排不等于离线。
正式设备数、物理链路数与探测池地址/身份组分开统计。

## 手动补全与回退

原“补全地址并更新拓扑”仍使用两个本机 Chassis 标量，保持显式 bootstrap 的范围校验。
该次显式操作使用手动补全阶段，跳过自动预探测，共享全轮唯一目标预算；完整采集仍核验
身份。其阶段上限为 60 秒且不超过全轮三分之一，核心递归保持预留容量。

将 `discovery.preprobe.enabled` 设为 `false`，重启控制台或在下一次 CLI scan 生效，即恢复
原核心递归工作流。保留迁移 6 表与探测证据是首选回退方式，现有设备/端口/链路不受影响。
旧二进制不识别 preprobe 字段，回退旧二进制前还需删除该配置块。
迁移 down 文件仅供明确需要撤销新表的维护使用，会删除新探测池及进度并将新增地址来源
映射回旧枚举；它不删除正式设备、端口、链路。日常关闭功能不需要执行 down。

## 验证

离线：`go test ./...`、`go build ./...`、`go vet ./...`、
`node --check internal/webui/assets/app.js`、`pwsh -File scripts/race.ps1`。
Windows 编译器无权写系统临时目录时，将 TEMP、TMP、GOTMPDIR 设为工作区 `.tools/tmp`。

PostgreSQL 只使用随机独立 schema，不设置会重建 public 的变量：

```powershell
Remove-Item Env:GONET_TEST_DATABASE_URL -ErrorAction SilentlyContinue
$env:GONET_ISOLATED_TEST_DATABASE_URL = $env:GONET_DATABASE_URL
go test ./internal/store/postgres -run 'Test(PreprobeIsolatedSchemaPersistence|RediscoveryIsolatedSchemaPersistence|NoIPIsolatedSchemaPersistence)$' -count=1 -v
```

实际证据与限制见 本次验收记录。
