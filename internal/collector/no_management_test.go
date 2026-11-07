package collector

import (
	"context"
	"gonet/internal/collector/lldp"
	"gonet/internal/collector/snmp"
	"gonet/internal/model"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestManagementTableIsOptionalAndNotRequestedByDefault(t *testing.T) {
	// A valid topology remains complete even when this table is absent.
	f := sampleFixture()
	for key := range f {
		if len(key) >= len(lldp.LldpRemManAddrTable) && key[:len(lldp.LldpRemManAddrTable)] == lldp.LldpRemManAddrTable {
			delete(f, key)
		}
	}
	s := collectSafetyFixture(t, f, nil)
	if !s.CollectionComplete || !s.Components["lldp_man_addr"].Skipped || len(s.Neighbors) != 2 {
		t.Fatalf("optional table suppressed LLDP: %+v", s.Issues)
	}
	for _, n := range s.Neighbors {
		if len(n.MgmtAddresses) != 0 {
			t.Fatal("management addresses were invented")
		}
	}
}

func TestNoManagementRequestsAndIsolatedScalarFailure(t *testing.T) {
	a := startFixture(t, sampleFixture())
	a.mu.Lock()
	a.failScalar = lldp.LldpLocSysCapSupported
	a.mu.Unlock()
	host, portText, _ := net.SplitHostPort(a.addr())
	port, _ := strconv.Atoi(portText)
	s, err := New(Options{Params: snmp.Params{Version: "2c", Community: "public", Port: uint16(port), Timeout: time.Second, MaxPDUs: 100}, DeviceTimeout: 3 * time.Second}).Collect(context.Background(), model.DiscoveryTarget{Address: mustAddr(host)})
	if s == nil || len(s.Neighbors) != 2 || s.Device.SysObjectID == "" || err == nil {
		t.Fatalf("one failed scalar discarded available LLDP: snapshot=%v error=%v", s != nil, err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, oid := range a.requested {
		if strings.HasPrefix(oid, lldp.LldpRemManAddrTable) {
			t.Fatalf("management table was requested: %s", oid)
		}
	}
}
