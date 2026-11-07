# gonet

基于 Go、SNMP 和 LLDP 的网络拓扑发现工具，提供网页控制台、递归发现、设备与端口核验、PostgreSQL 持久化和只读拓扑 API。支持 Windows 和 Linux。

## 功能

- 从指定核心交换机沿 LLDP 递归发现物理连接，以 Chassis ID 和 Port ID 核验设备与端口。
- 对授权管理 IPv4 范围进行 SNMP 预探测，保留可达地址与身份事实；探测成功与拓扑关联分别展示。
- 设备列表、未知邻居、探测池、拓扑图、上联路径、聚合连接与接口运行状态。
- 网页配置扫描范围、SNMP v2c 凭据、采集间隔和拓扑定时更新。
- PostgreSQL 保存扫描记录与历史证据；支持管理员登录、会话保护和独立只读 API Key。
- 支持经过限定型号/固件规则验证的 H3C、华为、信锐设备；不保证所有品牌和固件都可自动识别。

## 快速开始

需要 Go 1.25 或更新版本、PostgreSQL，以及可读取目标设备 LLDP-MIB / IF-MIB 的 SNMP 权限。

```sh
git clone https://github.com/zong-star/gonet.git
cd gonet
go build -o gonet ./cmd/gonet
cp config/config.example.yaml config.yaml
```

Windows 可使用 `go build -o gonet.exe ./cmd/gonet`，并用 PowerShell 的 `Copy-Item` 复制示例配置。

编辑 `config.yaml` 的 `discovery.seeds`、`management_cidrs` 和排除项，填写自己获授权管理的网络。示例地址是占位值，需要替换。按实际设备配置 SNMP profile 和所需的精确适配器。

通过环境变量配置数据库连接与 SNMP 团体名，避免写入仓库：

```sh
export GONET_DATABASE_URL='postgresql://gonet_app:CHANGE_ME@127.0.0.1:5432/gonet?sslmode=disable'
export GONET_SNMP_COMMUNITY='CHANGE_ME'
./gonet config validate --config config.yaml
./gonet migrate up --config config.yaml
./gonet scan --config config.yaml --output outputs/scan.json
```

`gonet` 不会创建 PostgreSQL 账号和数据库；首次部署先按 [Linux 部署说明](docs/linux-deployment.md) 或 [Windows PostgreSQL 说明](docs/postgresql-service.md) 完成初始化。扫描结果有部分缺口时退出码为 `3`，可用结果仍会保存。

## 网页控制台

```sh
./gonet auth hash-password
# 按命令提示生成摘要，将它设置为 GONET_ADMIN_PASSWORD_HASH。
export GONET_ADMIN_USERNAME='admin'
export GONET_ADMIN_PASSWORD_HASH='YOUR_BCRYPT_HASH'
export GONET_COOKIE_SECURE='false'  # 仅用于本机回环 HTTP 开发
./gonet serve --config config.yaml --listen 127.0.0.1:8787
```

访问 `http://127.0.0.1:8787`。对内网提供服务时使用 HTTPS 并保持 Secure Cookie，参见 [Linux 部署说明](docs/linux-deployment.md)。Windows 启停脚本见 `scripts/start-ui.ps1` 和 `scripts/stop-ui.ps1`。

## 常用命令

```sh
./gonet probe --config config.yaml --target YOUR_DEVICE_IP
./gonet collect --config config.yaml --target YOUR_DEVICE_IP --output outputs/device.json
./gonet scan --config config.yaml --plan
./gonet topology export --config config.yaml --state active --output outputs/topology.json
```

SNMP 仅提供访问与采集证据。探测池中的地址不自动成为拓扑起点；未核验身份、端口或链路会保留明确的诊断状态。

## 开发与测试

```sh
go test ./...
go vet ./...
go build ./...
node --test internal/webui/*.test.cjs
```

普通测试不需要真实交换机。数据库集成与浏览器验收是可选测试，须显式配置；数据库测试请先阅读 [隔离测试说明](docs/database-testing.md)，不要把生产数据库设置为破坏性测试库。

测试样本采用合成或脱敏数据。仓库不包含真实运行配置、访问凭据、证书私钥、数据库备份、完整生产拓扑或本机部署记录。

## 文档

- [网页控制台](docs/local-console.md)
- [预探测与身份索引](docs/preprobe.md)
- [接口运行状态](docs/interface-status.md)
- [聚合与上联推断](docs/lag-vendor-adaptation.md)
- [型号支持与接入流程](docs/vendor-support.md)
- [API 使用说明](docs/api/agent-topology.md) · [OpenAPI](docs/api/openapi.yaml)

## License

[MIT](LICENSE)
