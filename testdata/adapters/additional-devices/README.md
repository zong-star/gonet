# S5720 与 AC6507S 实采子集

来源：2026-11-01 用户授权的只读 SNMP v2c 采集。CLI LLDP 对照 NOT RUN。

| 型号 | 精确固件 | 产品 OID | 验证范围 |
| --- | --- | --- | --- |
| Huawei S5720-28TP-PWR-LI-AC | VRP 5.170 / V200R011C10SPC600 | .1.3.6.1.4.1.2011.2.23.462 | 两台系统、接口、本端与远端 LLDP；H3C 配对上联 |
| Huawei AC6507S | VRP 5.170 / V200R010C00SPC700 | .1.3.6.1.4.1.2011.2.240.19 | 系统及 17 个接口可读；本端 LLDP 不可读，不能确认本端 Chassis / 物理连接 |

`models.json` 保存精确型号事实。`uplink.json` 保存 S5720 与 H3C
S3100V2-26TP-SI（5.20 R5203P05）的真实互联子集；两个输入顺序都应得到一条双向链路。
`ac-no-local-lldp.json` 保留 AC 的缺失本端 LLDP 情形，不能用于生成已确认节点。

地址统一替换为 RFC 5737 文档地址，Chassis / 端口 MAC 一致替换为本地管理地址，
名称去标识，接口别名清空；保留型号、固件、subtype、原始端口与互联关系。
这些是诊断子集，collection_complete / absence_eligible 均为 false，不用于缺失老化。
无团体名、密码、连接串或企业管理地址。路由器 ER5200G3 已按用户要求停止采集，
没有它的实采适配或 fixture；通用 router 分类仅有合成测试。
