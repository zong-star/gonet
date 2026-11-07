package collector

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"gonet/internal/collector/lldp"
	"gonet/internal/collector/snmp"
	"gonet/internal/model"
)

func collectSafetyFixture(t *testing.T, fixture map[string]gosnmp.SnmpPDU, edit func(*Options)) *model.DeviceSnapshot {
	t.Helper()
	a := startFixture(t, fixture)
	host, portText, _ := net.SplitHostPort(a.addr())
	port, _ := strconv.Atoi(portText)
	opts := Options{Params: snmp.Params{Port: uint16(port), Timeout: time.Second, MaxPDUs: 500, MaxRepetitions: 20, Version: "2c", Community: "public"}, ViewVerified: true, DeviceTimeout: time.Second * 3}
	if edit != nil {
		edit(&opts)
	}
	snap, err := New(opts).Collect(context.Background(), model.DiscoveryTarget{Address: mustAddr(host)})
	if err != nil || snap == nil {
		t.Fatalf("collect: %v", err)
	}
	return snap
}

func TestMissingLocalLLDPIsReportedWithoutInventedIdentity(t *testing.T) {
	f := sampleFixture()
	for oid := range f {
		if strings.HasPrefix(oid, "1.0.8802.") || strings.HasPrefix(oid, ".1.0.8802.") {
			delete(f, oid)
		}
	}
	s := collectSafetyFixture(t, f, nil)
	found := false
	for _, issue := range s.Issues {
		found = found || issue.Code == "LLDP_LOCAL_UNAVAILABLE"
	}
	if !found || len(s.Device.Chassis.Raw) != 0 || s.AbsenceEligible || s.CollectionComplete {
		t.Fatalf("missing LLDP was accepted: %+v", s)
	}
}

func TestC08MissingLastChangeCannotAge(t *testing.T) {
	f := sampleFixture()
	delete(f, lldp.LldpStatsRemTablesLastChangeTime)
	s := collectSafetyFixture(t, f, nil)
	if s.SnapshotStable || s.AbsenceEligible {
		t.Fatal("missing lastChange was accepted as stable zero")
	}
	if !s.CollectionComplete || len(s.Neighbors) != 2 {
		t.Fatal("positive evidence must remain available")
	}
}

func TestStartupGraceUsesCentiseconds(t *testing.T) {
	f := sampleFixture()
	p := f[lldp.SysUpTime]
	p.Value = uint32(10000)
	f[lldp.SysUpTime] = p
	s := collectSafetyFixture(t, f, func(o *Options) { o.StartupGrace = 180 * time.Second })
	if !s.SnapshotStable || s.AbsenceEligible {
		t.Fatal("100 seconds uptime must stay below 180-second grace")
	}
}

func TestEveryLLDPPortMustReceive(t *testing.T) {
	f := sampleFixture()
	p := f[lldp.LldpPortConfigAdminStatus+".2"]
	p.Value = 1
	f[p.Name] = p
	s := collectSafetyFixture(t, f, nil)
	if s.AbsenceEligible {
		t.Fatal("one receive-disabled port must withhold device negative evidence")
	}
}

func TestNeighborLimitWithholdsCompleteness(t *testing.T) {
	s := collectSafetyFixture(t, sampleFixture(), func(o *Options) { o.MaxNeighbors = 1 })
	if s.CollectionComplete || s.AbsenceEligible {
		t.Fatal("neighbor budget cannot retain completeness")
	}
}

func TestUnmappedLocalPortCannotAge(t *testing.T) {
	f := sampleFixture()
	p := f[lldp.IfName+".102"]
	p.Value = []byte("different-name")
	f[p.Name] = p
	s := collectSafetyFixture(t, f, nil)
	if s.AbsenceEligible {
		t.Fatal("unmapped local port must withhold negative evidence")
	}
}

func TestC04IncompleteRemoteRowDisablesCompleteness(t *testing.T) {
	f := sampleFixture()
	delete(f, lldp.LldpRemPortIDSubtype+".7.1.1")
	s := collectSafetyFixture(t, f, nil)
	if s.CollectionComplete || s.AbsenceEligible {
		t.Fatal("row missing subtype did not disable completeness")
	}
}

func TestConsistencyRetriesSharePDUBudget(t *testing.T) {
	a := startFixtureSeq(t, sampleFixture(), map[string][]any{lldp.SysUpTime: {uint32(1000), uint32(900), uint32(500), uint32(400)}})
	host, text, _ := net.SplitHostPort(a.addr())
	port, _ := strconv.Atoi(text)
	s, _ := New(Options{Params: snmp.Params{Port: uint16(port), Timeout: time.Second, MaxPDUs: 12, MaxRepetitions: 20, Version: "2c", Community: "public"}, ViewVerified: true, ConsistencyRetries: 1, DeviceTimeout: 3 * time.Second}).Collect(context.Background(), model.DiscoveryTarget{Address: mustAddr(host)})
	if s != nil && (s.CollectionComplete || s.AbsenceEligible) {
		t.Fatal("consistency retry received a fresh PDU budget")
	}
}
