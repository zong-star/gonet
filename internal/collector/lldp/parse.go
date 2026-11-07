package lldp

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"

	"github.com/gosnmp/gosnmp"

	"gonet/internal/collector/oidutil"
	"gonet/internal/model"
)

// remoteInstance maps a lldpRemTable varbind to its column and full triple
// index. Only the three-segment index (timeMark, localPortNum, remIndex) is
// accepted; a wrong segment count is a decode error, never a silent skip.
func remoteInstance(pdu gosnmp.SnmpPDU) (string, model.NeighborIndex, error) {
	cols := []string{
		LldpRemChassisIDSubtype, LldpRemChassisID,
		LldpRemPortIDSubtype, LldpRemPortID, LldpRemPortDesc,
		LldpRemSysName, LldpRemSysDesc,
		LldpRemSysCapSupported, LldpRemSysCapEnabled,
	}
	for _, c := range cols {
		suf, err := oidutil.Suffix(c, pdu.Name)
		if err != nil {
			continue
		}
		if len(suf) != 3 {
			return "", model.NeighborIndex{}, fmt.Errorf("remote row %q has %d index segments, want 3", pdu.Name, len(suf))
		}
		return c, model.NeighborIndex{TimeMark: suf[0], LocalPortNum: suf[1], RemoteIndex: suf[2]}, nil
	}
	return "", model.NeighborIndex{}, fmt.Errorf("OID %q is not below any lldpRemTable column", pdu.Name)
}

// ParseRemoteNeighbors assembles lldpRemTable varbinds into neighbors keyed by
// the full triple index. Column order does not matter (C01), and two rows that
// share remIndex but differ in localPortNum stay separate (C02).
func ParseRemoteNeighbors(pdus []gosnmp.SnmpPDU) ([]model.LLDPNeighbor, []model.Issue) {
	type accum struct {
		n          model.LLDPNeighbor
		haveChID   bool
		havePortID bool
	}
	rows := map[model.NeighborIndex]*accum{}
	var issues []model.Issue

	for _, pdu := range pdus {
		col, idx, err := remoteInstance(pdu)
		if err != nil {
			issues = append(issues, model.Issue{Code: "DECODE_ERROR", Component: "lldp_rem", Message: err.Error()})
			continue
		}
		a := rows[idx]
		if a == nil {
			a = &accum{n: model.LLDPNeighbor{Index: idx}}
			rows[idx] = a
		}
		switch col {
		case LldpRemChassisIDSubtype:
			if v, err := asSubtype(pdu); err == nil {
				a.n.Chassis.Subtype = uint8(v)
			} else {
				issues = append(issues, decodeIssue("lldp_rem", err))
			}
		case LldpRemChassisID:
			if v, err := AsBytes(pdu); err == nil {
				a.n.Chassis.Raw = v
				a.haveChID = true
			} else {
				issues = append(issues, decodeIssue("lldp_rem", err))
			}
		case LldpRemPortIDSubtype:
			if v, err := asSubtype(pdu); err == nil {
				a.n.Port.Subtype = uint8(v)
			} else {
				issues = append(issues, decodeIssue("lldp_rem", err))
			}
		case LldpRemPortID:
			if v, err := AsBytes(pdu); err == nil {
				a.n.Port.Raw = v
				a.havePortID = true
			} else {
				issues = append(issues, decodeIssue("lldp_rem", err))
			}
		case LldpRemPortDesc:
			if v, err := AsString(pdu); err == nil {
				a.n.PortDescription = v
			} else {
				issues = append(issues, decodeIssue("lldp_rem", err))
			}
		case LldpRemSysName:
			if v, err := AsString(pdu); err == nil {
				a.n.SysName = v
			} else {
				issues = append(issues, decodeIssue("lldp_rem", err))
			}
		case LldpRemSysDesc:
			if v, err := AsString(pdu); err == nil {
				a.n.SysDescription = v
			} else {
				issues = append(issues, decodeIssue("lldp_rem", err))
			}
		case LldpRemSysCapSupported:
			if v, err := AsBits(pdu); err == nil {
				a.n.CapSupported = v
			} else {
				issues = append(issues, decodeIssue("lldp_rem", err))
			}
		case LldpRemSysCapEnabled:
			if v, err := AsBits(pdu); err == nil {
				a.n.CapEnabled = v
				a.n.CapNames = CapabilityNames(v)
			} else {
				issues = append(issues, decodeIssue("lldp_rem", err))
			}
		}
	}

	out := make([]model.LLDPNeighbor, 0, len(rows))
	for idx, a := range rows {
		if idx.LocalPortNum == 0 || idx.RemoteIndex == 0 || a.n.Chassis.Subtype < 1 || a.n.Chassis.Subtype > 7 || a.n.Port.Subtype < 1 || a.n.Port.Subtype > 7 || len(a.n.Chassis.Raw) == 0 || len(a.n.Chassis.Raw) > 255 || len(a.n.Port.Raw) == 0 || len(a.n.Port.Raw) > 255 {
			a.n.Issues = append(a.n.Issues, decodeIssue("lldp_rem", fmt.Errorf("remote row %v has missing or invalid identity/port fields", idx)))
		}
		if !a.haveChID {
			a.n.Issues = append(a.n.Issues, model.Issue{
				Code: "DECODE_ERROR", Component: "lldp_rem",
				Message: fmt.Sprintf("remote row %v missing chassis id", idx),
			})
		}
		if !a.havePortID {
			a.n.Issues = append(a.n.Issues, model.Issue{
				Code: "DECODE_ERROR", Component: "lldp_rem",
				Message: fmt.Sprintf("remote row %v missing port id", idx),
			})
		}
		out = append(out, a.n)
		issues = append(issues, a.n.Issues...)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Index, out[j].Index
		if a.TimeMark != b.TimeMark {
			return a.TimeMark < b.TimeMark
		}
		if a.LocalPortNum != b.LocalPortNum {
			return a.LocalPortNum < b.LocalPortNum
		}
		return a.RemoteIndex < b.RemoteIndex
	})
	return out, issues
}

// ParseLocalPorts assembles lldpLocPortTable varbinds keyed by locPortNum.
// Number is the LLDP port number and is never an ifIndex (C09).
func ParseLocalPorts(pdus []gosnmp.SnmpPDU) ([]model.LocalPort, []model.Issue) {
	type accum struct {
		p model.LocalPort
	}
	rows := map[uint32]*accum{}
	var issues []model.Issue

	for _, pdu := range pdus {
		col, num, err := localInstance(pdu)
		if err != nil {
			issues = append(issues, decodeIssue("lldp_local_port", err))
			continue
		}
		a := rows[num]
		if a == nil {
			a = &accum{p: model.LocalPort{Number: num}}
			rows[num] = a
		}
		switch col {
		case LldpLocPortIDSubtype:
			if v, err := asSubtype(pdu); err == nil {
				a.p.ID.Subtype = uint8(v)
			} else {
				issues = append(issues, decodeIssue("lldp_local_port", err))
			}
		case LldpLocPortID:
			if v, err := AsBytes(pdu); err == nil {
				a.p.ID.Raw = v
			} else {
				issues = append(issues, decodeIssue("lldp_local_port", err))
			}
		case LldpLocPortDesc:
			if v, err := AsString(pdu); err == nil {
				a.p.Description = v
			} else {
				issues = append(issues, decodeIssue("lldp_local_port", err))
			}
		}
	}

	out := make([]model.LocalPort, 0, len(rows))
	for _, a := range rows {
		if len(a.p.ID.Raw) == 0 || len(a.p.ID.Raw) > 255 || a.p.ID.Subtype < 1 || a.p.ID.Subtype > 7 || a.p.Number == 0 {
			a.p.MappingRule = "unresolved"
			issues = append(issues, decodeIssue("lldp_local_port", fmt.Errorf("local port %d has invalid typed identity", a.p.Number)))
		}
		out = append(out, a.p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Number < out[j].Number })
	return out, issues
}

func asSubtype(p gosnmp.SnmpPDU) (uint32, error) {
	v, err := AsUint32(p)
	if err != nil {
		return 0, err
	}
	if p.Type != gosnmp.Integer || v < 1 || v > 7 {
		return 0, fmt.Errorf("invalid subtype at %s", p.Name)
	}
	return v, nil
}

func localInstance(pdu gosnmp.SnmpPDU) (string, uint32, error) {
	for _, c := range []string{LldpLocPortIDSubtype, LldpLocPortID, LldpLocPortDesc} {
		suf, err := oidutil.Suffix(c, pdu.Name)
		if err != nil {
			continue
		}
		if len(suf) != 1 {
			return "", 0, fmt.Errorf("local port row %q has %d index segments, want 1", pdu.Name, len(suf))
		}
		return c, suf[0], nil
	}
	return "", 0, fmt.Errorf("OID %q is not below any lldpLocPortTable column", pdu.Name)
}

// ParseMgmtAddresses decodes management addresses from lldpRemManAddrTable OID
// indexes. The address octets come from the instance suffix
// (timeMark.localPortNum.remIndex.addressFamily.length.addressOctets); the
// varbind value (ifSubtype/ifId) is not used for the address.
func ParseMgmtAddresses(pdus []gosnmp.SnmpPDU) (map[model.NeighborIndex][]netip.Addr, []model.Issue) {
	out := map[model.NeighborIndex][]netip.Addr{}
	var issues []model.Issue
	for _, pdu := range pdus {
		suf, err := oidutil.Suffix(LldpRemManAddrTable+".1", pdu.Name)
		if err != nil {
			issues = append(issues, decodeIssue("lldp_man_addr", err))
			continue
		}
		// suf = [col, timeMark, localPortNum, remIndex, family, length, octets...]
		if len(suf) < 6 {
			issues = append(issues, model.Issue{Code: "DECODE_ERROR", Component: "lldp_man_addr",
				Message: fmt.Sprintf("management address OID %q has %d segments, want >=6", pdu.Name, len(suf))})
			continue
		}
		idx := model.NeighborIndex{TimeMark: suf[1], LocalPortNum: suf[2], RemoteIndex: suf[3]}
		family := suf[4]
		length := suf[5]
		octets := suf[6:]
		addr, err := addrFromOctets(family, length, octets)
		if err != nil {
			issues = append(issues, model.Issue{Code: "DECODE_ERROR", Component: "lldp_man_addr",
				Message: fmt.Sprintf("%s: %v", pdu.Name, err)})
			continue
		}
		out[idx] = append(out[idx], addr)
	}
	for idx, addrs := range out {
		out[idx] = dedupeSorted(addrs)
	}
	return out, issues
}

func addrFromOctets(family, length uint32, octets []uint32) (netip.Addr, error) {
	if uint32(len(octets)) != length {
		return netip.Addr{}, fmt.Errorf("address length %d but %d octets present", length, len(octets))
	}
	switch {
	case family == 1 && length == 4:
		var b [4]byte
		for i, o := range octets {
			if o > 255 {
				return netip.Addr{}, fmt.Errorf("IPv4 octet %d out of range", o)
			}
			b[i] = byte(o)
		}
		return netip.AddrFrom4(b), nil
	case family == 2 && length == 16:
		var b [16]byte
		for i, o := range octets {
			if o > 255 {
				return netip.Addr{}, fmt.Errorf("IPv6 octet %d out of range", o)
			}
			b[i] = byte(o)
		}
		return netip.AddrFrom16(b), nil
	default:
		return netip.Addr{}, fmt.Errorf("unsupported address family %d length %d", family, length)
	}
}

func dedupeSorted(addrs []netip.Addr) []netip.Addr {
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	out := addrs[:0]
	var prev netip.Addr
	for i, a := range addrs {
		if i == 0 || a != prev {
			out = append(out, a)
			prev = a
		}
	}
	return out
}

// ParseInterfaces assembles IF-MIB ifTable/ifXTable varbinds keyed by ifIndex.
func ParseInterfaces(pdus []gosnmp.SnmpPDU) ([]model.Interface, []model.Issue) {
	type accum struct {
		i model.Interface
	}
	rows := map[int32]*accum{}
	var issues []model.Issue

	for _, pdu := range pdus {
		col, ifIndex, err := ifInstance(pdu)
		if err != nil {
			issues = append(issues, decodeIssue("if_mib", err))
			continue
		}
		a := rows[ifIndex]
		if a == nil {
			a = &accum{i: model.Interface{IfIndex: ifIndex}}
			rows[ifIndex] = a
		}
		switch col {
		case IfDescr:
			if v, err := AsString(pdu); err == nil {
				a.i.Description = v
			} else {
				issues = append(issues, decodeIssue("if_mib", err))
			}
		case IfType:
			if v, err := AsUint32(pdu); err == nil {
				a.i.Type = int32(v)
			} else {
				issues = append(issues, decodeIssue("if_mib", err))
			}
		case IfPhysAddress:
			if v, err := AsBytes(pdu); err == nil {
				a.i.PhysAddress = v
				a.i.PhysAddressHex = hex.EncodeToString(v)
			} else {
				issues = append(issues, decodeIssue("if_mib", err))
			}
		case IfName:
			if v, err := AsString(pdu); err == nil {
				a.i.Name = v
			} else {
				issues = append(issues, decodeIssue("if_mib", err))
			}
		case IfAlias:
			if v, err := AsString(pdu); err == nil {
				a.i.Alias = v
				a.i.AliasCollected = true
			} else {
				issues = append(issues, decodeIssue("if_mib", err))
			}
		}
	}

	out := make([]model.Interface, 0, len(rows))
	for _, a := range rows {
		out = append(out, a.i)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IfIndex < out[j].IfIndex })
	return out, issues
}

func ifInstance(pdu gosnmp.SnmpPDU) (string, int32, error) {
	for _, c := range []string{IfIndex, IfDescr, IfType, IfPhysAddress, IfName, IfAlias} {
		suf, err := oidutil.Suffix(c, pdu.Name)
		if err != nil {
			continue
		}
		if len(suf) != 1 {
			return "", 0, fmt.Errorf("interface row %q has %d index segments, want 1", pdu.Name, len(suf))
		}
		return c, int32(suf[0]), nil
	}
	return "", 0, fmt.Errorf("OID %q is not below any IF-MIB column", pdu.Name)
}

func decodeIssue(component string, err error) model.Issue {
	return model.Issue{Code: "DECODE_ERROR", Component: component, Message: err.Error()}
}
