# S5120V2-28P-SI / Release 6318P01

System OID and description come from direct SNMP preprobe facts saved in
`outputs/topology-latest.json` on 2026-11-07. The operator also supplied the
upstream switch's CLI LLDP output confirming the exact model and firmware.
This fixture contains system facts only, with addresses, names and chassis IDs
omitted. It validates classification, not full port or topology support.

The deployment must verify direct collection and the downstream LLDP path in a
new scan. Other releases and nearby product OIDs are not covered by this rule.
