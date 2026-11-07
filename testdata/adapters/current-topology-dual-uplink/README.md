# Current topology / dual uplink regression fixture

Minimized from the two direct read-only captures on 2026-11-06. Device names,
addresses and MACs are replaced with lab values. The verified software/OID
fingerprints, typed LLDP IDs, independent localPortNum/ifIndex values and the
physical-27 / aggregate-719 shared MAC are retained. The original collector
left local port 27 unresolved while port 28 resolved; the fixture preserves it.

Core ge1_1_19 (81) / ge2_1_19 (140) advertise Gi1/1/19 / Gi2/1/19.
H3C physical 27 and 28 are IEEE LAG members of Bridge-Aggregation1 (719).
The resolver must create two bidirectional physical links in either scan order.
