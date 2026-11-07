# 旧 H3C / 华为兼容与读取条件

`0.7.1-dev` 新增以下有样本支持的识别规则：

| 厂商 / 型号 | 软件 / 固件 | 当前验证 |
| --- | --- | --- |
| H3C S3100V2-26TP-SI | 5.20 R5203P05、R5103P01；原 R5213P08 保留 | 六台旧固件实采成功，六条上联双向确认 |
| Huawei S2700-9TP-EI-AC | VRP 5.70 / S2700 V100R006C05 | 系统、接口与型号识别通过，本端 LLDP 不可读 |
| Huawei S2318TP-EI | VRP 5.70 / S2300 V100R006C03 | SNMP 启用后系统/22 接口可读，产品 OID .2011.2.23.90；本端 LLDP 不可读 |

识别要求厂商 OID、具体型号和固件同时匹配，接受版本号附近的空格、Tab 及 CRLF/LF 差异。
不能仅凭 `Version 5.20` / `5.70` 确认任意交换机。原始 LLDP Chassis、端口和 ifType 保留。
新采到的 H3C 接口为标准 ifType=6，不需要套用旧 S5120 的 ifType=117 兼容。

## 最初的华为读取限制与处理记录

以下保留最初诊断。用户调整读取条件后，第 25 轮 S2318 和 S2700 均已沿核心 LLDP
递归采集成功，并各有一条已核验上联；表格中的初始不可读状态不再是当前结果。
第 25 轮记录见 设备类型与新增型号验收。

用户提供的只读命令输出已经确认：

- S2318：用户已启用 SNMP agent，现有凭据可读系统和 22 个接口；当前同样使用默认 internet 视图，尚未覆盖 LLDP。
- S2700：现有 ViewDefault 只包含 `internet`，不覆盖标准 LLDP 的 `1.0.8802.1.1.2`。
  只读实测系统 OID 返回正常，本端 LLDP 两个标量返回 NoSuchInstance，GETNEXT 越出 LLDP 子树。

软件规则无法使设备返回未开放的 OID。GoNet 不用 IP、sysName 或接口 MAC 伪造缺失的
本端 LLDP Chassis，也不会把不可读表当作“没有邻居”的有效空表。

以下是供运维人员自行处理的设备侧条件，本次未通过 GoNet 或其他工具执行：

1. 两台的现有只读 v2c 访问已经验证，不必重新设置版本或凭据。
2. 两台都让实际使用的只读 SNMP 视图覆盖系统/接口与标准 LLDP 子树。
   不修改或删除默认 ViewDefault，可创建一个自定义视图。例如交换机命令格式：

   ```text
   system-view
   snmp-agent mib-view included GoNetRead internet
   snmp-agent mib-view included GoNetRead 1.0.8802.1.1.2
   snmp-agent mib-view excluded GoNetRead snmpUsmMIB
   snmp-agent mib-view excluded GoNetRead snmpVacmMIB
   snmp-agent mib-view excluded GoNetRead snmpModules.18
   ```

3. 按设备版本语法，将实际使用的只读团体绑定到 GoNetRead，保留原凭据和来源 ACL。
   只创建视图但不绑定团体不会改变已有 SNMP 访问。完整团体配置不需要发送到聊天。
   旧版命令形式为 `snmp-agent community read <现有只读团体名> mib-view GoNetRead`，
   如果现有团体命令带 `acl` 等限制参数，重新绑定时原样保留这些参数；不要创建 write 团体。
4. 在设备上只读复核 `display snmp-agent mib-view`。默认视图可继续存在，关键是团体所用
   自定义视图包含 LLDP。随后在 GoNet 点击一次“补全地址并更新拓扑”，成功后日常普通更新即可。

华为官方的[网络设备 SNMP 配置参考](https://info.support.huawei.com/storage/docs/zh-cn/fusioncube-1000-6.0/documentation/Enabl_SNMP_Network_Device.html)
同样说明管理视图需要包含 iso，并提示命令随设备型号与版本不同。上面的两个子树用于明确
GoNet 所需读取范围；视图权限与现有 ACL 仍由设备运维人员维护。

软件测试、实采数据与限制见 验收记录。
