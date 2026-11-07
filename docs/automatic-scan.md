# Windows 扫描与自动运行

## 控制台内的拓扑自动扫描（0.19.0）

“扫描设置”中，接口状态采集右侧新增“拓扑自动扫描频率”。输入 0 关闭自动更新；输入正整数并选择分/时/日后保存，服务会按该周期执行与“更新拓扑”相同的完整流程，包括原有预探测、设备发现、LLDP、物理链路和聚合证据更新。接口状态采集频率独立保持。

首次启用以及周期变化时，从保存后开始计算下一次运行时间；不会因保存立即扫描。自动与手动更新共用任务进度、取消操作和数据库锁。已有扫描运行时跳过该次定时触发，不叠加排队。设为 0 后不再触发新的自动任务；正在运行的一轮继续完成，也可使用原“停止扫描”取消。

配置写入 `config.yaml`：

```yaml
topology_scan:
  interval: 0s  # 0s 关闭；如 30m、2h、24h
```

原 `PUT /api/settings` 和 `/api/state` 的 settings 增加可选字段 `topology_scan_interval: {"value": 0, "unit": "minute"}`，unit 支持 minute/hour/day。单位和值一并保存，刷新或服务重启后保留。旧客户端省略该字段时保留现有周期。默认关闭，无数据库迁移。服务内调度随 GoNet 服务运行；下文为独立的 Windows 任务计划用法。


scan 本身已实现从核心出发的自动递归发现。0.11.0-dev 开启 preprobe 后，计划任务也共用网段预探测、持久身份索引与核心递归流程，见 [预探测说明](preprobe.md)。Windows 任务计划负责定期重复运行一轮；
不用逐台执行 collect。IP 用于 SNMP 访问，拓扑仍以 chassis/port 匹配。

本机可视化入口：`pwsh -NoProfile -File scripts/start-ui.ps1`，打开
<http://127.0.0.1:8787>，点击“更新拓扑”。设备列表、范围和新设备接入说明见
[local-console.md](local-console.md)。当前仅一个核心起点，已实测递归 83 台 / 96 条链路；
后文第 5、9 轮记录为历史阶段，83 个台账起点模式已被单核心模式取代。

## 立即执行

```powershell
Set-Location E:\gonet.0
pwsh -NoProfile -File .\scripts\scan.ps1
```

工作区根目录已放置当前 gonet.exe；源代码环境也可回退到 .tools/gonet-service.exe。
开发包自带 gonet.exe 与所需 Windows 脚本，解压后在包根目录创建自己的 config.yaml。
脚本按配置中 `_env` 引用读取 Windows 用户环境变量，已有本机团体名/数据库连接无需
重填。若未保存用户变量，则使用当前进程已有值。它设置正确工作目录，不依赖手动 cd。

输出：

| 文件 | 用途 |
| --- | --- |
| outputs/topology-latest.json | 最新已提交拓扑：正式设备/链路、待识别节点/连接、覆盖状态 |
| outputs/topology-latest.svg / .png | 可直接打开的拓扑图；SVG 可缩放并悬停看端口 |
| outputs/topology-devices.csv / topology-links.csv | 设备和链路列表；L 编号对应图中连线 |
| outputs/latest-status.json | 轮次、扫描状态、CLI 退出码、数量及当前日志路径 |
| outputs/scan-时间戳-随机后缀.json | 每轮持久化摘要 |
| outputs/scan-时间戳-随机后缀.log | 每轮诊断日志 |

只导出现有数据库、不采集设备：

```powershell
pwsh -NoProfile -File .\scripts\scan.ps1 -ExportOnly
```

业务数据始终在现有 PostgreSQL 服务的 gonet 库。脚本不自动创建数据库、执行迁移，
也不修改设备配置。升级时按 runbook 单独执行 migrate up。

## 定时运行

当前尚未替用户注册任务。运行下面命令一次即可创建每 15 分钟的任务：

```powershell
pwsh -NoProfile -File .\scripts\register-scan-task.ps1 -EveryMinutes 15
```

任务名 GoNet-Scan，首次约一分钟后执行，登录时也触发；定时持续生效。需要电脑唤醒、
网络可达且当前 Windows 用户处于登录状态，锁屏仍可执行。使用该用户的交互令牌、
普通权限，隐藏 PowerShell 窗口，不保存新的账号密码。不添加开机服务或另一套 PostgreSQL。

同一任务运行时忽略新的重叠触发；GoNet 数据库会话锁也会阻止并发写入。任务最长
20 分钟，默认扫描 deadline 为 15 分钟。可通过 EveryMinutes 改间隔，结合实际耗时选择。
脚本若发现同名任务已存在会拒绝覆盖。预览定义可加 -Preview，不会注册任务。

```powershell
# 查看运行状态
Get-ScheduledTask -TaskName GoNet-Scan
Get-ScheduledTaskInfo -TaskName GoNet-Scan
# 立即触发已注册任务
Start-ScheduledTask -TaskName GoNet-Scan
# 暂停 / 恢复
Disable-ScheduledTask -TaskName GoNet-Scan
Enable-ScheduledTask -TaskName GoNet-Scan
```

需要修改间隔时，可在 Windows 任务计划程序修改该任务的触发器；保留现有操作和
工作目录。未登录时持续运行需要另配合适服务账号及凭据来源，应按实际运行环境配置。

## 结果判读与已验证范围

latest-status.json 的 partial 表示扫描已提交，但存在未知身份、无访问地址或其他缺口。
scan.ps1 对“扫描提交并导出成功”返回 0，原 CLI 的退出码（partial=3）和状态保存在
latest-status.json，不会因 partial 自动重试。持锁跳过也返回 0，状态为 skipped_locked。
配置错误、无可用结果、数据库或导出失败返回非 0，旧拓扑文件保留，最新状态记 failed。
直接调用 gonet.exe 的原退出码约定不变。

自动递归仅访问允许且未排除的管理网段内，由标准 LLDP 管理地址（开关启用时）、
配置访问清单或历史已验证地址提供的采集通道。
没有访问通道的邻居仍保留在 pending_nodes/pending_links，不会由名称猜 IP 或全网扫地址。

2026-10-31：脚本语法和任务定义预览通过；已真实运行一次一键脚本，第 5 轮提交
partial、3 台交换机、2 条双向链路，36 个待识别节点、57 条待确认连接，写库/导出成功。
任务动作/触发器/重叠策略已构造验证，但未实际注册周期任务，长期运行尚未验收。

第 9 轮首次按台账以 82 个明确入选地址
作为起点、精确 /32 白名单访问，确认 81 台交换机、60 条本轮双向链路，1 个目标超时。
脚本联网前校验 `config/scan-scope.json`，图和列表按已核验 chassis 过滤历史设备。
当前范围模式与原单核心递归模式的差别、空 LLDP 表等缺口见 `inventory-scope.md`。
用户随后明确要求核心交换机保留，当前白名单为 83 个地址，包含 TS7914；其他排除
范围保持不变。拓扑图优先以核心为根，双机堆叠显示为一个 LLDP chassis。
