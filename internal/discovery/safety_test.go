package discovery

import (
	"context"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/topology"
	"net/netip"
	"testing"
)

func TestL05ScanRejectsNonPhysicalEndpoint(t *testing.T) {
	snaps := ringTopology(t)
	snaps[mustAddr(t, "192.0.2.2")].Interfaces[0].Type = 161
	fc := newFakeCollector(snaps)
	out := newRingCoordinator(t, fc, []netip.Addr{mustAddr(t, "192.0.2.1")}).Run(context.Background())
	if len(out.Links) != 2 || out.Status != "partial" || len(out.Unresolved) == 0 {
		t.Fatalf("nonphysical endpoint leaked: links=%d status=%s", len(out.Links), out.Status)
	}
}

func TestD02UnresolvedRemotePortStillDiscovered(t *testing.T) {
	snaps := linearTopology(t)
	b := mustAddr(t, "192.0.2.2")
	snaps[mustAddr(t, "192.0.2.1")].Neighbors[0].Port = model.TypedID{Subtype: 7, Raw: []byte("opaque")}
	snaps[b].LocalPorts[0].ID = model.TypedID{Subtype: 7, Raw: []byte("opaque")}
	fc := newFakeCollector(snaps)
	newRingCoordinator(t, fc, []netip.Addr{mustAddr(t, "192.0.2.1")}).Run(context.Background())
	if fc.callCount(b) != 1 {
		t.Fatal("port resolution prevented address discovery")
	}
}

func TestL06ConflictWithholdsAbsence(t *testing.T) {
	snaps := ringTopology(t)
	a := mustAddr(t, "192.0.2.1")
	snaps[a].AbsenceEligible = true
	snaps[a].Neighbors[1].Index.LocalPortNum = 1
	out := newRingCoordinator(t, newFakeCollector(snaps), []netip.Addr{a}).Run(context.Background())
	if out.Status != "partial" || !hasIssue(out.Issues, "TOPOLOGY_CONFLICT") {
		t.Fatal("conflict not surfaced")
	}
	for _, o := range out.Outcomes {
		if o.Target.Address == a && o.Snapshot.AbsenceEligible {
			t.Fatal("conflicted device remained eligible")
		}
	}
	if !snaps[a].AbsenceEligible {
		t.Fatal("coordinator mutated supplied snapshot")
	}
}

func TestPersistedContextIsNotASeedOrDeviceBudget(t *testing.T) {
	a, b := mustAddr(t, "192.0.2.1"), mustAddr(t, "192.0.2.2")
	mac := []byte{0, 0, 0, 0, 0, 1}
	fc := newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{a: devSnap(a, mac, "A", nil, nil, nil)})
	coord := newCoord(t, fc, Options{Seeds: []netip.Addr{a}, ManagementCIDRs: []netip.Prefix{mustPrefix(t, "192.0.2.0/24")}, MaxDevices: 1, MaxTargets: 1})
	contextDevices := []*identity.Device{
		{Ref: 100, StrongKey: "lldp:4:000000000001", State: identity.StateVerified, Classification: identity.Classification{Result: "switch"}, Addresses: []identity.Address{{Addr: a, State: identity.AddrVerified}}},
		{Ref: 200, StrongKey: "lldp:4:000000000002", State: identity.StateVerified, Classification: identity.Classification{Result: "switch"}, Addresses: []identity.Address{{Addr: b, State: identity.AddrVerified}}},
	}
	if err := coord.RestoreContext(contextDevices, nil); err != nil {
		t.Fatal(err)
	}
	out := coord.Run(context.Background())
	if out.Status != "completed" || len(out.Devices) != 1 || fc.callCount(b) != 0 {
		t.Fatalf("old context leaked: status=%s devices=%d old-target-calls=%d", out.Status, len(out.Devices), fc.callCount(b))
	}
}

func TestPortIDChangeWithoutNeighborsCannotAge(t *testing.T) {
	a := mustAddr(t, "192.0.2.1")
	mac := []byte{0, 0, 0, 0, 0, 1}
	s := devSnap(a, mac, "A", []model.LocalPort{lp(1, "new")}, []model.Interface{ifc(101, "new")}, nil)
	s.AbsenceEligible = true
	coord := newRingCoordinator(t, newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{a: s}), []netip.Addr{a})
	idx := int32(101)
	if err := coord.RestoreContext([]*identity.Device{{Ref: 10, StrongKey: "lldp:4:000000000001", State: identity.StateVerified, Classification: identity.Classification{Result: "switch"}, Addresses: []identity.Address{{Addr: a, State: identity.AddrVerified}}}}, []*topology.Port{{Ref: 20, Device: 10, Key: topology.MakePortKey(5, []byte("old")), IfIndex: &idx}}); err != nil {
		t.Fatal(err)
	}
	out := coord.Run(context.Background())
	if out.Status != "partial" || !hasIssue(out.Issues, "PORT_ID_CHANGED") || out.Outcomes[0].Snapshot.AbsenceEligible {
		t.Fatal("port identity change without neighbors remained absence eligible")
	}
}

func TestPartialSnapshotDiagnosticsSurviveScan(t *testing.T) {
	a := mustAddr(t, "192.0.2.1")
	s := devSnap(a, []byte{0, 0, 0, 0, 0, 1}, "A", nil, nil, nil)
	s.CollectionComplete = false
	s.Issues = []model.Issue{{Code: "SNMP_TIMEOUT", Component: "lldp_rem", Message: "timeout"}}
	out := newRingCoordinator(t, newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{a: s}), []netip.Addr{a}).Run(context.Background())
	if !hasIssue(out.Issues, "SNMP_TIMEOUT") || !hasIssue(out.Outcomes[0].Issues, "SNMP_TIMEOUT") {
		t.Fatal("partial collection diagnostics disappeared")
	}
}

func TestBadPortDoesNotBlockVerifiedManualAddress(t *testing.T) {
	snaps := linearTopology(t)
	a, b := mustAddr(t, "192.0.2.1"), mustAddr(t, "192.0.2.2")
	snaps[a].AbsenceEligible = true
	snaps[a].Neighbors[0].Port = model.TypedID{Subtype: 0, Raw: []byte("invalid")}
	snaps[a].Neighbors[0].Issues = []model.Issue{{Code: "DECODE_ERROR", Component: "lldp_rem", Message: "invalid port subtype"}}
	snaps[a].Neighbors[0].MgmtAddresses = nil
	fc := newFakeCollector(snaps)
	coord := newCoord(t, fc, Options{Seeds: []netip.Addr{a}, ManagementCIDRs: []netip.Prefix{mustPrefix(t, "192.0.2.0/24")}, MaxDepth: 1, AddressOverrides: map[string][]netip.Addr{"lldp:4:000000000002": {b}}})
	out := coord.Run(context.Background())
	if fc.callCount(b) != 1 {
		t.Fatal("corrupt port suppressed an independently verified manual peer address")
	}
	if len(out.Links) != 0 || out.Outcomes[0].Snapshot.AbsenceEligible {
		t.Fatal("bad port was promoted to a link/negative evidence")
	}
}

func TestUnknownNeighborCountedOnce(t *testing.T) {
	for _, bridge := range []bool{false, true} {
		t.Run(map[bool]string{false: "unclassified", true: "bridge-candidate"}[bridge], func(t *testing.T) {
			a := mustAddr(t, "192.0.2.1")
			n := model.LLDPNeighbor{Index: model.NeighborIndex{TimeMark: 1, LocalPortNum: 1, RemoteIndex: 1}, Chassis: model.TypedID{Subtype: 7, Raw: []byte("weak-host")}, Port: model.TypedID{Subtype: 5, Raw: []byte("eth0")}}
			if bridge {
				n.CapEnabled = []byte{0x20}
			}
			s := devSnap(a, []byte{0, 0, 0, 0, 0, 1}, "A", []model.LocalPort{lp(1, "Gi1")}, []model.Interface{ifc(101, "Gi1")}, []model.LLDPNeighbor{n})
			out := newRingCoordinator(t, newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{a: s}), []netip.Addr{a}).Run(context.Background())
			if out.Counts.UnknownNeighbors != 1 || len(out.Unresolved) != 1 {
				t.Fatalf("one weak neighbor counted incorrectly: %+v", out.Counts)
			}
		})
	}
}

func TestScopeRejectionIsNotBudgetExhaustion(t *testing.T) {
	snaps := linearTopology(t)
	a := mustAddr(t, "192.0.2.1")
	snaps[a].Neighbors[0].MgmtAddresses = []netip.Addr{mustAddr(t, "2001:db8::1")}
	out := newCoord(t, newFakeCollector(snaps), Options{Seeds: []netip.Addr{a}, ManagementCIDRs: []netip.Prefix{mustPrefix(t, "192.0.2.0/24")}}).Run(context.Background())
	if out.Status != "partial" || out.Counts.TruncatedBranches != 1 || out.Termination != "errors_retained" || !hasIssue(out.Issues, "ADDRESS_OUT_OF_SCOPE") {
		t.Fatalf("scope rejection misreported: status=%s termination=%s counts=%+v", out.Status, out.Termination, out.Counts)
	}
	budget := newCoord(t, newFakeCollector(snaps), Options{Seeds: []netip.Addr{a}, ManagementCIDRs: []netip.Prefix{mustPrefix(t, "192.0.2.0/24")}, MaxDevices: 1}).Run(context.Background())
	if budget.Termination != "budget_exhausted" {
		t.Fatalf("device budget termination lost: %s", budget.Termination)
	}
}
