# 旧款接入交换机实采子集

来源：2026-11-01，用户授权的管理网段，只读 SNMP v2c，未修改设备配置。
原始完整快照仅保留在本机 outputs/diagnostics/legacy，不进入开发包。

| 型号 | 系统版本 / 固件 | 证据范围 |
| --- | --- | --- |
| H3C S3100V2-26TP-SI | Comware 5.20 R5203P05 | 五台直接采集完整；sysObjectID .25506.1.655；标准 LLDP 与 ifType=6 |
| H3C S3100V2-26TP-SI | Comware 5.20 R5103P01 | 一台直接采集完整；相同产品 OID；标准 LLDP 与 ifType=6 |
| Huawei S2700-9TP-EI-AC | VRP 5.70 / S2700 V100R006C05 | 直接读取系统、13 个接口；产品 OID .2011.2.23.114；本端 LLDP 标量 NoSuchInstance |
| Huawei S2318TP-EI | VRP 5.70 / S2300 V100R006C03 | 运维启用 SNMP 后系统/22 个接口可读；产品 OID .2011.2.23.90；本端 LLDP 仍不可读 |

models.json 保留直接实采的型号、固件、产品 OID 与描述。S2318 启用 SNMP 后已核实
精确产品 OID，规则收敛到 .2011.2.23.90；直接身份仍须核验自身 LLDP Chassis。

uplinks.json 从两种 H3C 固件各保留一条真实上联及汇聚的反向观察；两个采集顺序都应
形成三设备、两条双向物理链路，不应出现未决端口或冲突。MAC 作全局一致替换，
IP 改为文档网段，设备名称与接口描述脱敏，IF-MIB 与 typed 端口对应关系保留。
因是子集，collection_complete 与 absence_eligible 均设为 false，不作为缺失老化证据。

huawei-no-local-lldp.json 与 s2318-no-local-lldp.json 保留实际可读的系统/接口结构与不可读的本端 LLDP 状态，
MAC/IP/名称已脱敏。即使型号规则命中，也不能用 IP 或接口 MAC 伪造 LLDP Chassis。
该样本必须保持未完成、不具备缺失老化资格，不能生成已核验设备或双向连接。

规则测试还覆盖换行与空白差异、相近型号、未采固件、版本字符串及数字 OID 段边界。
CLI LLDP 对照未提供；两台华为的本端 LLDP 与双向端口兼容仍未实机验证。
