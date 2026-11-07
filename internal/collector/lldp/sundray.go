package lldp

import (
	"github.com/gosnmp/gosnmp"
	"gonet/internal/identity"
	"gonet/internal/model"
	"strings"
)

const TS7914Adapter = "sundray_ts7914_chassis38_20251010"
const RS39Adapter = "sundray_rs39_20251011"

// These three kernel fingerprints were collected from operator-listed RS3300
// and RS3320 devices. A generic vendor OID alone never enables translation.
func IsRS39Adapter(d model.DeviceInfo, enabled []string) bool {
	active := false
	for _, id := range enabled {
		active = active || id == RS39Adapter
	}
	if !active || strings.TrimPrefix(d.SysObjectID, ".") != "1.3.6.1.4.1.45577" {
		return false
	}
	switch d.SysDescription {
	case "Linux (none) 3.6.5-Broadcom Linux #10 Sat Oct 11 09:37:35 UTC 2025 armv7l",
		"Linux (none) 3.6.5-Broadcom Linux #10 Sat Oct 11 10:24:38 UTC 2025 armv7l",
		"Linux (none) 4.4.39-Broadcom Linux #1 SMP Sat Oct 11 10:45:52 UTC 2025 armv7l":
		return true
	}
	return false
}

// The product firmware is operator-verified from the paired advertisement.
// Activation is explicit; the direct kernel and vendor OID must also match.
func IsTS7914Adapter(d model.DeviceInfo, enabled []string) bool {
	active := false
	for _, id := range enabled {
		if id == TS7914Adapter {
			active = true
		}
	}
	return active && strings.TrimPrefix(d.SysObjectID, ".") == "1.3.6.1.4.1.45577" && d.SysDescription == "Linux Sundray 4.14.76-10.3.4.0-4-Marvell #2 SMP Fri Oct 10 03:09:01 UTC 2025 aarch64"
}

// ParseRemoteForDevice leaves standard parsing strict. Only the independently
// verified TS/RS encoding is translated; the unmodified typed port stays in JSON.
func ParseRemoteForDevice(pdus []gosnmp.SnmpPDU, d model.DeviceInfo, enabled []string) ([]model.LLDPNeighbor, []model.Issue) {
	adapter := ""
	if IsTS7914Adapter(d, enabled) {
		adapter = TS7914Adapter
	}
	if IsRS39Adapter(d, enabled) {
		adapter = RS39Adapter
	}
	if adapter == "" {
		return ParseRemoteNeighbors(pdus)
	}
	ids := map[model.NeighborIndex][]byte{}
	zero := map[model.NeighborIndex]bool{}
	for _, p := range pdus {
		col, idx, e := remoteInstance(p)
		if e != nil {
			continue
		}
		if col == LldpRemPortID {
			if b, e := AsBytes(p); e == nil {
				ids[idx] = b
			}
		}
		if col == LldpRemPortIDSubtype && p.Type == gosnmp.Integer {
			if v, e := AsUint32(p); e == nil && v == 0 {
				zero[idx] = true
			}
		}
	}
	originals := map[model.NeighborIndex]model.TypedID{}
	normalized := append([]gosnmp.SnmpPDU(nil), pdus...)
	for i, p := range normalized {
		col, idx, e := remoteInstance(p)
		if e != nil || !zero[idx] {
			continue
		}
		mac, ok := identity.ParseMACContent(ids[idx])
		if !ok || len(ids[idx]) != 17 {
			continue
		}
		originals[idx] = model.TypedID{Subtype: 0, Raw: append([]byte(nil), ids[idx]...)}
		if col == LldpRemPortIDSubtype {
			normalized[i].Value = 3
		}
		if col == LldpRemPortID {
			normalized[i].Value = mac
		}
	}
	rows, issues := ParseRemoteNeighbors(normalized)
	for i := range rows {
		if original, ok := originals[rows[i].Index]; ok {
			rows[i].OriginalPort = &original
			rows[i].EncodingAdapter = adapter
		}
	}
	return rows, issues
}
