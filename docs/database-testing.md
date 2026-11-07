# PostgreSQL 数据库测试

日常运行使用现有 Windows 服务 `postgresql-x64-18`、`127.0.0.1:5432`，业务库默认
`gonet`。服务及连接配置见 [postgresql-service.md](postgresql-service.md)。不再默认使用
项目 `.pgdata` / 55432 测试实例，不在测试脚本中自动启动另一套 postgres.exe。

## 普通检查

```powershell
go build ./...
go test ./...
go vet ./...
pwsh -File scripts/race.ps1
```

不设置 `GONET_TEST_DATABASE_URL` 时，PostgreSQL 集成测试会明确跳过；其余离线测试
照常运行。不要将普通单元测试通过描述为数据库集成测试通过。

## 需要集成测试时

集成测试会执行 `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`，因此只允许使用
独立、可清空的测试数据库。**不能把业务库 gonet 或其他业务库配置为测试库**。

如需验证 P01–P06、S01–S05 等用例，可由管理员在同一个 Windows PostgreSQL 服务上
另行创建独立数据库和仅拥有该库的测试账号，无须初始化另一个数据库实例：

```sql
-- 在现有 5432 服务中，由管理员执行；账号密码由本机安全输入配置。
CREATE DATABASE gonet_test OWNER gonet_test_user;
```

`gonet_test_user` 必须预先创建为独立 LOGIN 角色，不授予业务库权限。测试账号需要
对自己的数据库执行 schema/表 DDL 的权限；不需要成为超级用户。

在专门的 PowerShell 测试会话中设置连接，密码须 URL 编码，不写入项目文件：

```powershell
# 格式示意，替换为本机测试账号的连接信息后执行。
$env:GONET_TEST_DATABASE_URL = 'postgresql://gonet_test_user:<URL编码密码>@127.0.0.1:5432/gonet_test?sslmode=disable'
go test ./internal/store/postgres -count=1 -v
pwsh -File scripts/race.ps1
Remove-Item Env:GONET_TEST_DATABASE_URL
```

初始化日常业务环境的 `setup-postgres-service.ps1` 不创建测试数据库，也不把集成测试
指向业务库。正式的 `GONET_DATABASE_URL` 与测试用的 `GONET_TEST_DATABASE_URL` 必须分开。

## 无 IP 模块的独立 schema 验证

`TestNoIPIsolatedSchemaPersistence` 不调用上述 resetDB，不删除 public。它在既有服务
中新建随机命名的 `gonet_test_noip_*` schema，将该专用连接 search_path 仅设为这个
schema，完成迁移、uint32 索引、未知节点/连接保存、别名恢复、重复轮次、单向保留、
离线冻结和 stale 验证后，关闭连接并删除该测试 schema。不创建第二个 PostgreSQL 实例。

```powershell
Remove-Item Env:GONET_TEST_DATABASE_URL -ErrorAction SilentlyContinue
$env:GONET_ISOLATED_TEST_DATABASE_URL = [Environment]::GetEnvironmentVariable('GONET_DATABASE_URL','User')
go test ./internal/store/postgres -run '^TestNoIPIsolatedSchemaPersistence$' -count=1 -v
Remove-Item Env:GONET_ISOLATED_TEST_DATABASE_URL
```

该变量只供这个隔离用例使用，不能替代原破坏性用例的 GONET_TEST_DATABASE_URL。
2026-10-31 已实际通过普通与 race 运行，随后核验无遗留测试 schema。

`TestRediscoveryIsolatedSchemaPersistence` 使用另一个随机 `gonet_test_discovery_*`
schema 验证迁移 5、历史待核验数据回填、管理地址修正、SNMP 暂时失败恢复、递归、双上联
以及设备/链路 ID 稳定性。它只在自身私有 schema 内模拟旧版本，不操作业务 public。
与前一个用例一同执行可使用：

```powershell
go test ./internal/store/postgres -run 'Test(RediscoveryIsolatedSchemaPersistence|NoIPIsolatedSchemaPersistence)$' -count=1 -v
```

## 历史环境

M4/M5 的早期集成测试使用过 `E:\gonet.0\.pgdata` / 55432，本次按用户要求停用并清理。
当时的真实测试结果仍保留在 acceptance 目录。临时库清理曾遇到 Windows 进程信号
权限问题，记录见 `acceptance/environment-note-2026-10-31.md`；之后以服务切换记录为准。

预探测模块另有 `TestPreprobeIsolatedSchemaPersistence`，复用同一独立 schema 方式，
验证 5→6 升级、无管理地址递归、多访问 IP 关联、取消、重复提交、缓存重启、
失败保留成功事实和扫描历史清理。可将它加入上述三个测试的运行表达式。
