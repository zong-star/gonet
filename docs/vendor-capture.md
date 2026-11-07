# 信锐、H3C、华为实采准备

2026-10-31 用户指定范围：信锐 TS7914/RS 系列、H3C S5560/5130、华为 S5735。
已通过授权 SNMP 采集 TS7914 核心、H3C S5130S-28P-EI 及华为 S5735-L8T4S-QA2，保存脱敏子集；
CLI 输出尚缺。当前结果见 `acceptance/live-scan-2026-10-31.md`，以下清单用于补齐对照。

## 每个目标组需要保存的内容

为五个目标组分别保存：完整型号/板卡信息、固件版本、运行模式、采样时间、只读 view
范围、是否允许 LLDP 接收、原始数字 sysObjectID 与 sysDescr、collect JSON、同时间段
CLI 的本地 chassis/端口及邻居详情、IF-MIB 映射。RS 还需注明胖/瘦模式及控制器版本。

原始采样先保存在版本库之外，脱敏后按准确型号和固件放入 fixture。不要提交 SNMP
密钥或真实管理地址；保留原始字节长度、MAC 二进制编码、subtype、管理地址 family、
完整三元索引及关联关系。`raw_hex`/base64 必须同步替换。

在用户指定 IP、配置和凭据环境已经准备好后，由授权人员执行：

```text
gonet config validate --config config.yaml
gonet collect --config config.yaml --target <该型号授权管理IP> --output <型号-固件-snapshot.json>
```

先逐设备采集，再做跨厂商递归扫描。程序不会通过 SSH 执行下面的 CLI 命令；使用已有
运维入口人工取得只读输出，不修改 LLDP/SNMP 配置。

## 官方资料核对与只读 CLI

| 目标 | 可用于准备的资料 / 只读输出 | 尚不能据此认定的事项 |
| --- | --- | --- |
| 信锐 TS7914 | [TS79 安装手册](https://support.sundray.com.cn/productDocument/read?category_id=2009&product_id=21&version_id=1004)确认产品范围；[TS SNMP OID 汇总](https://support.sundray.com/productDocument/read?category_id=3611&product_id=21&version_id=1004)附件已读取，未见 LLDP 项；[TS 控制台说明](https://support.sundray.com.cn/productDocument/read?category_id=876&product_id=21&version_id=1004)未给出本次异常表的解释 | 不把 RS CLI 套用到 TS7914；需对应 SW-CHASSIS3.8 固件 MIB/本机帮助或同时间段邻居详情 |
| 信锐 RS | [RS 控制台命令说明](https://support.sundray.com.cn/productDocument/read?category_id=871&product_id=20&version_id=1003)列出 `list lldp neighbor_info`，并注明 SW3.6 及之后支持；另有 [RS SNMP OID 汇总附件入口](https://support.sundray.com.cn/productDocument/read?category_id=3610&product_id=20&version_id=1003) | 未读取汇总附件、未验证用户设备固件，不假设所有 RS 都暴露标准 LLDP-MIB |
| H3C 5130 | [S5130-HI LLDP 命令参考](https://www.h3c.com/en/d_201905/1176179_294551_0.htm/1319301)包含 `display lldp local-information`、`display lldp neighbor-information verbose`、`display lldp status` | 文档针对 S5130-HI 指定 Release，不能直接推广到 S5130S/其他后缀 |
| H3C S5560 | [S5560X-EI LLDP 参考](https://www.h3c.com/en/Support/Resource_Center/EN/Switches/Catalog/S5560X/S5560X-EI/Technical_Documents/Reference_Guides/Command_References/H3C_CR-27503/03/202507/2581094_294551_0.htm)可帮助准备同类只读输出 | S5560X-EI 仅是资料入口，不能替代用户 S5560 的实际后缀和 Comware 版本 |
| 华为 S5735 | [华为 LLDP 邻居检查](https://info.support.huawei.com/network/ptmngsys/Web/tsrev_s/en/content/s/38_edesk_lldp_neighbors_failing/edesk_lldp_neighbors_failing_edesk001.html)使用 `display lldp neighbor brief`；[S5735-L24P4X-A1 MIB 查询入口](https://info.support.huawei.com/info-finder/search-center/en/enterprise/Switches/S5735-L24P4X-A1-pid-C00000001272/mib)按型号/版本组织 | 该入口不是全 S5735 的支持清单；brief 只作邻接数量交叉核对，身份/端口 subtype 仍需详细输出与 SNMP 原始值 |

公开资料仅作采样准备。TS OID 汇总附件已读取但不足以解码本次管理地址异常；真实
fixture 来自授权设备 SNMP，不来自网页示例。逐型号状态见 `vendor-support.md`；CLI 对照均 NOT RUN。

## 首轮对照重点

- TS7914：核对管理板/业务板呈现的逻辑 chassis、成员端口编号和 ifIndex；单一 LLDP
  chassis 按规范视为一个逻辑设备，不根据板卡数量拆分设备。
- RS：确认胖/瘦运行模式与固件下的 SNMP view，实际能否读取标准 LLDP-MIB；缺失对象
  记录 unsupported，不能把空 walk 当作零邻居。
- H3C：记录完整 S5560/5130 子型号；对照 localPortNum、IF-MIB 和 LLDP port subtype，
  不从 CLI 的缩写显示推断 SNMP typed ID 或把 LLDP 端口号当作 ifIndex。
- 华为：记录完整 S5735 后缀/VRP；比较真实广告 port ID 与 ifName/ifDescr，不能因为
  CLI 显示缩写就自动展开名称。
- 已采 S5735-L8T4S-QA2 / V200R023C00SPC500 的内置 ViewDefault 不可修改，且仅覆盖
  internet（1.3.6.1）。标准 LLDP（1.0.8802.1.1.2）需由设备管理者配置自定义只读视图
  并绑定团体；保留原排除项和 ACL。系统信息可读不代表 LLDP 已开放，隐藏表不能当零邻居。
- 三厂商交叉连接：确认同一链路两个方向、同设备并行端口、管理地址 family，以及
  聚合接口/成员接口的实际 LLDP 行。正式链路只使用经证明的物理端点。

优先取得 TS7914 核心和任一 H3C/华为相邻交换机的两端样本，验证跨厂商互联；再扩展
RS、另一 H3C 系列及剩余厂商。此顺序是采样建议，不授权程序访问任何设备。
