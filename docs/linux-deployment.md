# Linux 部署

本项目提供 `deploy/linux/` 中的 systemd、环境文件和 Nginx 模板。推荐专用服务账号、独立 PostgreSQL 数据库与 HTTPS 入口。网页资源嵌入程序，运行时不需要 Node.js。

## 构建与安装

```sh
go build -trimpath -o gonet ./cmd/gonet
sudo useradd --system --user-group --home-dir /var/lib/gonet --shell /usr/sbin/nologin gonet
sudo install -d -m 0755 /opt/gonet
sudo install -m 0755 gonet /opt/gonet/gonet
sudo install -d -o gonet -g gonet -m 0750 /var/lib/gonet/config /var/lib/gonet/outputs
sudo install -d -m 0700 /etc/gonet
sudo install -o gonet -g gonet -m 0640 config/config.example.yaml /var/lib/gonet/config.yaml
sudo install -o gonet -g gonet -m 0640 config/device_rules.yaml config/port_rules.yaml /var/lib/gonet/config/
```

账号已存在时不必重复创建。编辑 `/var/lib/gonet/config.yaml`，替换发现起点和允许范围。相对规则路径以 `/var/lib/gonet` 为工作目录。

## 数据库与认证

安装 PostgreSQL 16 或更新版本，通过交互式 `psql` 创建专用账号与空库：

```sql
CREATE ROLE gonet_app LOGIN;
\password gonet_app
CREATE DATABASE gonet OWNER gonet_app;
```

将 `deploy/linux/gonet.env.example` 安装为 `/etc/gonet/gonet.env`，由 root 持有且权限为 `0600`，填写数据库连接、SNMP 团体名、管理员用户名和密码摘要。数据库密码中的特殊字符需要 URL 编码。

运行 `/opt/gonet/gonet auth hash-password` 交互式生成管理员摘要。HTTPS 部署保留 `GONET_COOKIE_SECURE=true`，使用 Nginx 模板时按实际代理地址设置信任范围。

```sh
sudo install -m 0644 deploy/linux/gonet*.service deploy/linux/gonet-scan.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start gonet-migrate.service
sudo systemctl enable --now gonet.service
curl --fail http://127.0.0.1:8787/health
```

迁移前备份已有业务库，不要对生产数据库设置破坏性测试环境变量。跨机器迁移使用 `pg_dump` / `pg_restore`，不要复制数据库数据目录。

## HTTPS 与扫描

参考 `deploy/linux/nginx-gonet.conf.example` 配置 Nginx，替换域名和证书路径。应用默认监听 `127.0.0.1:8787`，对外入口使用 HTTPS，不公开 PostgreSQL 端口。

登录网页后配置管理范围并更新拓扑。也可启动 `gonet-scan.service` 运行一轮，或启用 `gonet-scan.timer` 定时执行。网页自身支持拓扑定时更新，选择一种调度方式即可，同一数据库使用锁防止扫描并发。

```sh
sudo systemctl start gonet-scan.service
sudo journalctl -u gonet.service -u gonet-scan.service -n 50 --no-pager
sudo systemctl stop gonet.service
```

扫描退出码 `3` 表示部分结果，`5` 表示因持锁跳过。健康接口只说明 HTTP 进程正常，实际采集结果还需查看扫描状态与诊断。

规则文件在下一轮扫描重新加载；环境文件或程序本身变更后才需要重启服务。保留配置、证书、凭据与数据库备份在仓库之外。
