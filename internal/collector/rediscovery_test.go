package collector

import (
	"net/netip"
	"testing"

	"github.com/gosnmp/gosnmp"
	"gonet/internal/collector/lldp"
)

func TestTSManagementTableReadAfterAddressCorrection(t *testing.T) {
	f := sampleFixture()
	f[lldp.SysObjectID] = gosnmp.SnmpPDU{Name: lldp.SysObjectID, Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.4.1.45577"}
	f[lldp.SysDescr] = gosnmp.SnmpPDU{Name: lldp.SysDescr, Type: gosnmp.OctetString, Value: []byte("Linux Sundray 4.14.76-10.3.4.0-4-Marvell #2 SMP Fri Oct 10 03:09:01 UTC 2025 aarch64")}
	s := collectSafetyFixture(t, f, func(o *Options) { o.CollectManagementAddresses = true; o.Adapters = []string{lldp.TS7914Adapter} })
	if s.Components["lldp_man_addr"].Skipped || len(s.Neighbors[0].MgmtAddresses) != 1 || s.Neighbors[0].MgmtAddresses[0] != netip.MustParseAddr("192.0.2.11") {
		t.Fatalf("TS adapter still hides corrected management addresses: %+v", s.Neighbors)
	}
}

func TestMalformedManagementTableRetainsNeighborAndInterfaces(t *testing.T) {
	f := sampleFixture()
	for key := range f {
		if len(key) > len(lldp.LldpRemManAddrTable) && key[:len(lldp.LldpRemManAddrTable)] == lldp.LldpRemManAddrTable {
			delete(f, key)
		}
	}
	key := lldp.LldpRemManAddrTable + ".1.3.7.1.3061629953.1.0"
	f[key] = gosnmp.SnmpPDU{Name: key, Type: gosnmp.Integer, Value: 0}
	s := collectSafetyFixture(t, f, func(o *Options) { o.CollectManagementAddresses = true })
	if len(s.Neighbors) != 2 || len(s.Interfaces) != 2 || len(s.Neighbors[0].MgmtAddresses) != 0 || s.Components["lldp_man_addr"].DecodeComplete {
		t.Fatalf("malformed table destroyed facts or invented an IP: %+v", s)
	}
}
