# PostgreSQL Windows 服务与 GoNet 配置

使用现有安装，不另建 PostgreSQL 实例：

| 项目 | 位置 / 值 |
| --- | --- |
| Windows 服务名 | `postgresql-x64-18` |
| PostgreSQL 数据目录 | `D:\PostgreSQL\data` |
| 连接地址 | `127.0.0.1:5432` |
| GoNet 业务数据库 | `gonet` |
| GoNet 数据库账号 | `gonet_app`，只拥有自己的业务库 |
| GoNet 主配置 | `E:\gonet.0\config.yaml` |
| GoNet 连接串 | 当前 Windows 用户环境变量 `GONET_DATABASE_URL` |

## 本机初始化

在普通 PowerShell 7 窗口运行：

```powershell
cd E:\gonet.0
pwsh -NoProfile -File .\scripts\setup-postgres-service.ps1
```

脚本会请求一次 Windows 管理员授权，用来启动现有服务、设置自动启动，以及停止并
删除项目内旧测试实例 `E:\gonet.0\.pgdata`（包括其中的测试库和挂起清理后端）。
只在精确路径、进程归属和非链接目录校验通过后删除；不删除或重建服务数据目录。
旧测试库里是模拟数据，不导入业务库。

接着在本机窗口输入**已有的 PostgreSQL 管理员密码**，默认管理员用户名为 postgres。
密码不发送到聊天，不打印、不写入 YAML；脚本不重置管理员密码、不改为 trust 认证。
它创建 gonet_app 和 gonet，生成应用密码，保存连接环境变量，并执行迁移与导出验证。
已存在的应用角色不会被自动重置密码；同名数据库由其他角色拥有时会停止并要求换名。

可以用 `-AdminUser`、`-DatabaseName`、`-AppRole` 指定其他名称。现有服务已经启动时，
脚本直接复用它，不重启服务。操作进度保存在 `.tools/postgres-service-*-status.json`，
状态文件不含密码或完整连接串。服务/清理成功与建库/迁移成功分别记录，不把局部成功
当作全部完成。

服务切换与旧实例清理已完成、只需继续建库时，可以运行：

```powershell
pwsh -NoProfile -File .\scripts\setup-postgres-service.ps1 -DatabaseOnly
```

此模式核对旧目录已删除且现有服务运行，然后只在本机读取密码、建库和配置连接，
不再次申请 Windows 管理员授权。现有同名数据库若归属其他账号，会在本机窗口要求
选择新库名，不覆盖原库。

## 在哪里修改连接

`config.yaml` 中只指定连接串环境变量的名称：

```yaml
database:
  dsn_env: GONET_DATABASE_URL
  statement_timeout: 30s
```

实际主机、端口、库名、账号和密码在 `GONET_DATABASE_URL` 中，格式为：

```text
postgresql://gonet_app:<URL编码后的密码>@127.0.0.1:5432/gonet?sslmode=disable
```

在 Windows“系统属性 → 高级 → 环境变量 → 用户变量”里编辑此变量。不要把密码写到
项目配置文件。新终端会读取新值；已打开的 PowerShell 可在**不显示连接串**的情况下刷新：

```powershell
$env:GONET_DATABASE_URL = [Environment]::GetEnvironmentVariable('GONET_DATABASE_URL', 'User')
```

这里配置的是本机回环地址上的开发/实验连接。连接远程生产数据库时使用 verify-full
和对应 CA/主机名配置，不沿用本机 sslmode=disable。

PostgreSQL 服务本身的端口/监听地址配置在 `D:\PostgreSQL\data\postgresql.conf`；
认证规则在 `D:\PostgreSQL\data\pg_hba.conf`。本次切换不修改这两个文件。
它们与 GoNet 的业务连接配置是不同层次。

## 使用与测试

```powershell
cd E:\gonet.0
go run ./cmd/gonet migrate up --config config.yaml
go run ./cmd/gonet topology export --config config.yaml --state all --output -
```

数据库初始化不扫描交换机。采集前仍需在 config.yaml 填写授权核心 IP、管理 CIDR 和
SNMP 密钥环境变量。初始配置没有扫描种子，避免访问示例地址。

**不要把 `GONET_TEST_DATABASE_URL` 指向 gonet 或其他业务库。** 集成测试会重建 public schema，
如需运行这些测试，只在同一个服务里另建独立测试库；默认初始化不会创建测试库。
