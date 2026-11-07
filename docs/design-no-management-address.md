# 无邻居管理 IP 依赖的增量设计

依据：`gonet_无IP依赖拓扑要求.md`。本要求优先于旧规范中必须读取管理地址表、
禁止全部 local MAC 跨类型匹配的限制；保留原始值、唯一性和物理端口门禁继续有效。

1. 保留既有 devices / device_identities / device_addresses / ports / observations /
   links 等表和设备 ID。IP 仅用于访问与地址冲突检查；身份匹配不使用 IP 或 sysName。
2. 标准管理地址表默认不请求；可显式开启用于其他已验证设备，但 TS 适配始终跳过。
   不读取该表不降低本地/远端 LLDP 完整性。单一标量错误不丢弃其他可读对象。
3. MAC 内容采用严格完整格式解析，原 subtype/raw 不修改。同 subtype 的规范化键优先；
   跨 subtype 4/7 只在唯一 MAC 所有者下绑定别名，歧义隔离，别名持久化。
4. TS 端口 0 + MAC 文本通过显式启用、匹配已实采固件指纹的独立适配器转为可匹配端口；
   原端口值及适配器来源保留。标准解析器继续拒绝非法 subtype。
5. BFS 地址来自显式 identity.address_overrides 或历史已验证 device_addresses。没有
   地址的身份和本端—邻居观测仍入库并导出为 pending_nodes / pending_links，不发请求。
   unknown 设备不混入已确认交换机/物理 links；已确认单向链路保持原生命周期规则。
6. 原始 observations 足以存储待识别节点/连接，不另建重复实体表；增量迁移将 remIndex
   改为 bigint 并约束 uint32 范围。export 从最新提交轮次生成待确认节点、连接及原始身份。
7. 以脱敏真实 TS/H3C/华为数据证明：去掉全部管理地址仍匹配；MAC 跨类型、重复/歧义、
   无地址节点、离线、单向、重复扫描和稳定数据库 ID。破坏性集成测试只用独立测试库。

第一阶段已核验现有结构，build 与 identity/topology/discovery 基线测试通过。
后续各阶段的文件、检查结果和实际扫描见最终验收记录。
