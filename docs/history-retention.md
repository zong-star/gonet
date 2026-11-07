# 历史保留与自动清理（0.9.0-dev）

配置位于实际使用的 config.yaml：

```yaml
history:
  keep_scans: 500
```

默认 500，允许 2–100000。旧配置未写此项时也默认 500；控制台下次规范化保存会写入该项。
配置值为 0 按默认值处理，负值或 1 拒绝。扫描每次加载配置，不需要另设清理计划任务。
网页尚无保留数量输入框，修改此配置后后续扫描生效。

## 数据库

每轮提交（包括 failed / aborted）或明确标记失败时，在同一事务和扫描锁中清理超期数据：

- 最多保留 500 个已结束轮次（completed / partial / failed / aborted 合计），正在运行的轮次不删除。
- 最近一次可用 completed / partial 拓扑占用这 500 个名额之一，即使后来连续失败，也保留其设备采集和邻居证据；其余名额按轮次 ID 从新到旧保留。
- 删除过期 scan_runs 以及相应 observations、scan_devices，包括原始邻居 JSON 和诊断。
- 不删除 devices、device_identities、device_addresses、ports、links；稳定 ID、最后发现时间、置信度和 stale / miss 状态保留。
- 不重用扫描 ID。第 501 轮之后移除过期轮次，不把旧 ID 改写成新轮次。
- 清理失败会回滚结果事务，之前已提交拓扑仍在；不会局部删除历史后保留半轮新结果。

迁移 4 将 links 的 last_seen_scan_id / last_evaluated_scan_id 改为可空外键，删除过期轮次时
设为 NULL，避免因为旧链路引用而永远无法清理。导出 last_seen_scan_id 可为 null，含义为
该次历史已过期；last_seen_at 仍保留，fresh=false，不把该链路伪装成本轮观察。
后续真实重新发现会更新同一个 link ID 并恢复有效扫描引用。最近可用拓扑与运行轮次不会因此删除。

清理后过期轮次不能再查询、追溯完整 observation 或重交；保留窗口内的提交仍具备幂等性。
这是采集历史上限，不是整个数据库的固定字节上限：新增真实设备 / 端口 / 链路仍会增加主记录。

## 本地文件

网页更新、带文件输出的持久化 CLI scan，以及 Windows scan.ps1 自动执行文件清理。
手动导出-only 脚本同样清理历史输出，避免反复导出造成累积。

outputs 顶层的以下文件最多保留 500 组，网页与脚本历史共用组数：

- `scan-ui-轮次.json`：一组。
- `scan-YYYYMMDD-HHmmss-fff-六位随机值.json/.log` 与同戳的 `topology-export-...json`：合为一组。

组数按最近文件时间排序，同时间的网页轮次按数字 ID 排序。latest-status.json 指向的当前输出优先保留在上限内。
只清理程序命名格式的顶层普通文件；不递归，不跟随符号链接 / 目录链接。
`topology-latest.*`、CSV、最新状态、手工快照、diagnostics 子目录、配置备份和数据库备份不删除。
这些诊断 / 备份文件不是自动采集历史，需运维按自己的备份要求管理。
数据库上限按轮次计；文件上限按输出批次计。一次仅导出也会产生文件批次，不产生数据库轮次。

## 手动执行与升级

```powershell
cd E:\gonet.0
# 先升级可执行文件，并在停止采集后显式迁移一次；SQL 已嵌入程序。
.\gonet.exe migrate up --config config.yaml
# 按配置同时清理数据库与历史文件；运行中的扫描 / 迁移会使其返回退出码 5。
.\gonet.exe history prune --config config.yaml --output-dir outputs
# 仅清理已知命名的历史文件，不连接数据库。
.\gonet.exe history prune --config config.yaml --output-dir outputs --files-only
```

Linux 将 `./gonet.exe` 换成实际二进制路径，并由服务环境注入凭据；工作目录须与规则路径一致。
命令输出保留上限、删除轮次 / 观察 / 采集行数及文件组数，不输出凭据。
不足 500 轮时数据库不会删除任何轮次。减少 keep_scans 会在下一次扫描结束或手动清理时删除超额历史。

## 磁盘空间

PostgreSQL 删除记录后，autovacuum 回收空间供后续记录复用；数据文件通常不会立即变小。
目标是稳定复用空间，不是在每轮自动执行会锁表的 VACUUM FULL。
应保持 autovacuum 启用；WAL、系统 journal、手工备份由服务器各自的保留策略管理。
依据：[PostgreSQL 18 日常 VACUUM](https://www.postgresql.org/docs/18/routine-vacuuming.html#VACUUM-FOR-SPACE-RECOVERY)。

测试使用独立临时 schema，覆盖实际 500 上限、旧证据删除、旧链路保留、重新发现、失败风暴、
运行轮次保护、锁互斥和清理失败回滚；文件测试覆盖 503→500、成组删除、同时间数字排序、
保护当前文件、忽略手工文件及子目录。业务库不会用于这类超量模拟。
