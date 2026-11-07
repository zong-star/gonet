package lldp

import (
	"net/netip"
	"strconv"
	"testing"

	"github.com/gosnmp/gosnmp"

	"gonet/internal/model"
)

func TestParseInterfacesAliasPresence(t *testing.T) {
	pdus := []gosnmp.SnmpPDU{
		{Name: IfName + ".1", Type: gosnmp.OctetString, Value: []byte("GE1/0/1")},
		{Name: IfDescr + ".1", Type: gosnmp.OctetString, Value: []byte("device text")},
		{Name: IfAlias + ".1", Type: gosnmp.OctetString, Value: []byte{}},
		{Name: IfName + ".2", Type: gosnmp.OctetString, Value: []byte("GE1/0/2")},
		{Name: IfAlias + ".3", Type: gosnmp.Integer, Value: 44},
	}
	rows, issues := ParseInterfaces(pdus)
	if len(rows) != 3 || len(issues) != 1 || rows[0].Name != "GE1/0/1" || rows[0].Description != "device text" ||
		rows[0].Alias != "" || !rows[0].AliasCollected || rows[1].AliasCollected || rows[2].AliasCollected {
		t.Fatalf("interface evidence: %+v, issues: %+v", rows, issues)
	}
}

func remPDU(colBase string, tm, lpn, ri uint32, typ gosnmp.Asn1BER, val any) gosnmp.SnmpPDU {
	return gosnmp.SnmpPDU{
		Name:  colBase + "." + u(tm) + "." + u(lpn) + "." + u(ri),
		Type:  typ,
		Value: val,
	}
}

func u(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

func manPDU(col, tm, lpn, ri, family, length uint32, octets ...uint32) gosnmp.SnmpPDU {
	oid := LldpRemManAddrTable + ".1" + "." + u(col) + "." + u(tm) + "." + u(lpn) + "." + u(ri) + "." + u(family) + "." + u(length)
	for _, o := range octets {
		oid += "." + u(o)
	}
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Integer, Value: 1}
}

func idx(tm, lpn, ri uint32) model.NeighborIndex {
	return model.NeighborIndex{TimeMark: tm, LocalPortNum: lpn, RemoteIndex: ri}
}

// C01: two neighbors with shuffled column order must assemble by full triple
// index with no cross-contamination.
func TestParseRemoteNeighborsShuffled(t *testing.T) {
	pdus := []gosnmp.SnmpPDU{
		remPDU(LldpRemChassisID, 1, 5, 2, gosnmp.OctetString, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02}),
		remPDU(LldpRemChassisIDSubtype, 1, 5, 1, gosnmp.Integer, 4),
		remPDU(LldpRemChassisID, 1, 5, 1, gosnmp.OctetString, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}),
		remPDU(LldpRemPortID, 1, 5, 2, gosnmp.OctetString, []byte("Gig0/2")),
		remPDU(LldpRemChassisIDSubtype, 1, 5, 2, gosnmp.Integer, 4),
		remPDU(LldpRemPortIDSubtype, 1, 5, 1, gosnmp.Integer, 5),
		remPDU(LldpRemPortID, 1, 5, 1, gosnmp.OctetString, []byte("Gig0/1")),
		remPDU(LldpRemPortIDSubtype, 1, 5, 2, gosnmp.Integer, 5),
	}
	got, issues := ParseRemoteNeighbors(pdus)
	if len(issues) != 0 {
		t.Fatalf("issues = %v, want none", issues)
	}
	if len(got) != 2 {
		t.Fatalf("neighbors = %d, want 2", len(got))
	}
	if got[0].Index.RemoteIndex != 1 || got[1].Index.RemoteIndex != 2 {
		t.Fatalf("unexpected order: %+v", got)
	}
	if string(got[0].Chassis.Raw) != string([]byte{0, 0, 0, 0, 0, 1}) {
		t.Errorf("neighbor 1 chassis = %x, want ...01", got[0].Chassis.Raw)
	}
	if string(got[0].Port.Raw) != "Gig0/1" {
		t.Errorf("neighbor 1 port = %q, want Gig0/1", got[0].Port.Raw)
	}
	if string(got[1].Port.Raw) != "Gig0/2" {
		t.Errorf("neighbor 2 port = %q, want Gig0/2", got[1].Port.Raw)
	}
}

// C02: same remIndex, different localPortNum stay separate.
func TestParseRemoteNeighborsLocalPortNum(t *testing.T) {
	pdus := []gosnmp.SnmpPDU{
		remPDU(LldpRemChassisIDSubtype, 1, 5, 1, gosnmp.Integer, 4),
		remPDU(LldpRemChassisID, 1, 5, 1, gosnmp.OctetString, []byte{1}),
		remPDU(LldpRemPortIDSubtype, 1, 5, 1, gosnmp.Integer, 5),
		remPDU(LldpRemPortID, 1, 5, 1, gosnmp.OctetString, []byte("A")),
		remPDU(LldpRemChassisIDSubtype, 1, 6, 1, gosnmp.Integer, 4),
		remPDU(LldpRemChassisID, 1, 6, 1, gosnmp.OctetString, []byte{2}),
		remPDU(LldpRemPortIDSubtype, 1, 6, 1, gosnmp.Integer, 5),
		remPDU(LldpRemPortID, 1, 6, 1, gosnmp.OctetString, []byte("B")),
	}
	got, _ := ParseRemoteNeighbors(pdus)
	if len(got) != 2 {
		t.Fatalf("neighbors = %d, want 2", len(got))
	}
	if got[0].Index.LocalPortNum != 5 || got[1].Index.LocalPortNum != 6 {
		t.Fatalf("localPortNum not preserved: %+v", got)
	}
	if string(got[0].Port.Raw) != "A" || string(got[1].Port.Raw) != "B" {
		t.Errorf("ports overwritten: %+v", got)
	}
}

// C03: multiple management addresses (IPv4 + IPv6, duplicate) parse with the
// correct family/length and are stably deduped.
func TestParseMgmtAddresses(t *testing.T) {
	ipv4 := []uint32{192, 0, 2, 1}
	ipv6 := []uint32{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	pdus := []gosnmp.SnmpPDU{
		manPDU(3, 1, 5, 1, 1, 4, ipv4...),
		manPDU(3, 1, 5, 1, 2, 16, ipv6...),
		manPDU(4, 1, 5, 1, 1, 4, ipv4...), // duplicate from the IfId column
	}
	got, issues := ParseMgmtAddresses(pdus)
	if len(issues) != 0 {
		t.Fatalf("issues = %v", issues)
	}
	addrs := got[idx(1, 5, 1)]
	if len(addrs) != 2 {
		t.Fatalf("addresses = %d, want 2 (deduped)", len(addrs))
	}
	if addrs[0] != netip.MustParseAddr("192.0.2.1") {
		t.Errorf("addr[0] = %v, want 192.0.2.1", addrs[0])
	}
	if addrs[1] != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("addr[1] = %v, want 2001:db8::1", addrs[1])
	}
}

// C04: malformed OID, length mismatch and illegal ASN.1 type must not panic
// and must produce diagnostics.
func TestParseMalformed(t *testing.T) {
	bad1 := gosnmp.SnmpPDU{Name: LldpRemChassisID + ".1.5", Type: gosnmp.OctetString, Value: []byte{1}}
	bad2 := remPDU(LldpRemChassisIDSubtype, 1, 5, 1, gosnmp.Integer, "not-an-int")
	bad3 := manPDU(3, 1, 5, 1, 1, 4, 192, 0)

	_, issues := ParseRemoteNeighbors([]gosnmp.SnmpPDU{bad1, bad2})
	if len(issues) == 0 {
		t.Error("remote parse: expected issues for malformed input")
	}
	_, mIssues := ParseMgmtAddresses([]gosnmp.SnmpPDU{bad3})
	if len(mIssues) == 0 {
		t.Error("mgmt parse: expected issue for length mismatch")
	}
}

// C05: capability BITS bit order; bridge+router is legal (does not exclude a
// layer-3 switch).
func TestCapabilityNames(t *testing.T) {
	if got := CapabilityNames([]byte{0x20}); len(got) != 1 || got[0] != "bridge" {
		t.Errorf("0x20 = %v, want [bridge]", got)
	}
	got := CapabilityNames([]byte{0x28})
	if len(got) != 2 || got[0] != "bridge" || got[1] != "router" {
		t.Errorf("0x28 = %v, want [bridge router]", got)
	}
	if got := CapabilityNames([]byte{0x08}); len(got) != 1 || got[0] != "router" {
		t.Errorf("0x08 = %v, want [router]", got)
	}
	if got := CapabilityNames(nil); len(got) != 0 {
		t.Errorf("nil = %v, want empty", got)
	}
}
