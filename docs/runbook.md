# GoNet 首次运行与恢复

当前构建为 `0.11.0-dev`。两厂商 CLI 对照尚未验收，状态见 `acceptance/M5.md` 和
`vendor-support.md`。采集需要 GoNet、只读 SNMP 与 PostgreSQL，可选内嵌网页。
Linux 部署与内网入口见 [linux-deployment.md](linux-deployment.md)，历史保留见 [history-retention.md](history-retention.md)。

升级至本版本先执行迁移 6；预探测的预算、探测池及关闭/回退方法见 [preprobe.md](preprobe.md)。

## 准备

从源码构建需要 Go 1.25+；当前验证为 Windows amd64、Go 1.27.1、PostgreSQL 18.1。
PostgreSQL 最低版本为 16。开发包使用 `scripts/build.ps1` 生成，附 SHA256SUMS；
Linux amd64 包为交叉编译产物，Linux 启动和实机流程 NOT RUN，解压后须先 `chmod +x gonet`。

在包根目录运行命令，复制 `config/config.example.yaml` 为 `config.yaml`。替换核心种子和
允许管理 CIDR，填入已验证的准确型号规则，保留只读 SNMP view。配置规则路径相对于
进程工作目录，计划任务必须设置“起始于”为包根目录。

删除不用的 SNMP profile，把 `default_profile` 指向要使用的 profile；不同管理网段
可通过 `profile_rules` 选择凭据。配置中所有 profile 引用的环境变量均须非空：实验
v2c 使用 `GONET_SNMP_COMMUNITY`，生产 v3 authPriv 使用 USER/AUTH/PRIV 对应变量。
从密钥管理工具注入环境，不把密钥放进 YAML、命令参数、快照或版本库。
数据库连接由 `GONET_DATABASE_URL` 提供；生产使用 `sslmode=verify-full` 及匹配的 CA
和主机名。只在隔离的本机测试库使用文档中的 trust/disable 配置。

本机目前改用现有 Windows 服务 `postgresql-x64-18` / 5432。初始化业务库、清理旧
项目测试实例及连接变量的配置位置，见 `postgresql-service.md`。不要再按历史验收
记录的 initdb 命令创建 `.pgdata` / 55432 实例。

## 首次运行顺序

以下命令由授权设备环境的运维人员执行；本轮没有访问任何示例管理 IP。

```text
gonet version
gonet config validate --config config.yaml
gonet collect --config config.yaml --target <授权核心IP> --output snapshot.json
gonet scan --config config.yaml --dry-run --output scan-dry-run.json
gonet migrate up --config config.yaml
gonet scan --config config.yaml --output scan-summary.json
gonet topology export --config config.yaml --state all --output topology.json
```

在 Windows PowerShell 中把 `gonet` 写为 `./gonet.exe`。数据库及账号由运维预先创建，
迁移不会自动创建数据库。`config validate` 不发 SNMP 请求，也不验证数据库连通性。
文件已存在时默认拒绝覆盖；确认需要替换时显式添加 `--overwrite`。

先把 collect 的 chassis、完整三元索引、远端端口及管理地址与 CLI LLDP 逐项核对。
再检查 dry-run 的正式设备/物理链路、excluded、unknown、未决观察和分支终止原因。
空规则会导致 unknown，不应为获得 completed 而放宽为整厂商白名单。
实际 SNMP view、LLDP 接收和启动宽限时间未确认前，不启用负面资格。

首次持久化后复核设备、端口与并行链路数量；重复扫描不得增长相同实体的数量。
链路必须能追溯到 observations。导出 `fresh` 指最新 completed/partial 提交轮的正面
观察，不表示端口当前 Up；旧 active 的 `fresh=false`/`coverage_gap=true` 必须保留。

## 调度与退出码

本机已提供 `scripts/scan.ps1` 一键扫描并导出，以及 `scripts/register-scan-task.ps1`
注册 Windows 周期任务。默认每 15 分钟、当前用户登录时运行；执行注册命令前不会
启用周期采集。命令及结果判读见 `automatic-scan.md`。

由 Windows 计划任务或系统 cron 周期调用单次 scan。建议从 5 分钟开始，但应大于
实测最坏耗时；可能重叠时依赖同一数据库会话锁跳过重叠轮次。不要把调度次数当作 miss。

| 退出码 | 运维处理 |
| --- | --- |
| 0 | 完整成功 |
| 2 | 修正参数、配置、缺失环境变量或输出路径 |
| 3 | 已保留部分结果；检查 unknown、预算和未决原因，避免无限重试 |
| 4 | 无可用结果或数据库提交失败；检查诊断及 scan_runs |
| 5 | 其他 scan/迁移持锁，本轮跳过 |
| 130 | 人工中断；独立提交 context 尝试保存已完成正面结果，禁止老化 |

stderr 是日志，stdout 是 JSON/命令结果；不要把两者合并后当成 JSON 解析。

## 恢复步骤

1. 进程崩溃：确认旧进程已经退出；下轮取得会话锁后会把遗留 running 标为 aborted。
   旧轮不执行负面老化。不要手动重交旧轮去增加 miss。
2. 数据库提交失败：整批结果回滚；短事务尝试写 failed。连接断开时可留下 running，
   按上一条恢复。先恢复数据库与凭据，再重扫，不对未提交结果报告成功。
3. 设备超时或网络分区：保留可用拓扑；未覆盖/不合格端点的旧链路冻结，不从旧数据库
   设备列表补扫。恢复核心可达性后重新从种子扫描。
4. IP 复用或 chassis 冲突：检查原始观察与设备实际身份，保存审计记录。维护人员确认
   更换设备后，在同一写锁保护下把旧地址绑定退役；若确认是错误冲突，再人工解除原
   设备冲突状态。不能覆盖旧设备的强身份或把新观察写到旧设备。完成后重新扫描。
5. PORT_ID_CHANGED：检查型号/固件与原始 typed key；仅在一对一对应得到验证后增加
   有 reason 的端口 alias 覆盖，并回放样本。禁止依靠 ifIndex 强行合并端口。
6. 备份/还原：使用 PostgreSQL 原生 pg_dump/pg_restore，备份全部领域表及
   schema_migrations；通过 service/passfile 注入凭据。先还原到独立数据库验证，再
   切换 DSN。恢复后按正常逐设备资格处理，不清空链路、不重置全部 miss。

## 本地验收

`database-testing.md` 的集成测试会重建独立测试库的 public schema，不能指向业务库。

```powershell
$env:GOCACHE = Join-Path (Get-Location) '.gocache'
$env:TEMP = Join-Path (Get-Location) '.tools/tmp'
New-Item -ItemType Directory -Force -Path $env:TEMP | Out-Null
$env:TMP = $env:TEMP
# 按 database-testing.md 启动独立测试库并设置 GONET_TEST_DATABASE_URL
go build ./...
go test ./... -count=1
go vet ./...
pwsh -File scripts/race.ps1
pwsh -File scripts/stability.ps1
pwsh -File scripts/build.ps1
```

没有授权设备时只执行离线与本机数据库测试。当前已有 TS7914/H3C/华为授权实采及 partial
扫描写库，CLI 对照尚未完成；实际状态见 `acceptance/live-scan-2026-10-31.md`。
