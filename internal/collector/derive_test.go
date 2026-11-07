package collector

import (
	"testing"

	"gonet/internal/collector/lldp"
	"gonet/internal/collector/snmp"
	"gonet/internal/model"
)

func TestLocalMACMappingExcludesLogicalReuseButRejectsPhysicalAmbiguity(t *testing.T) {
	mac := []byte{2, 0, 0, 0, 0, 27}
	lp := model.LocalPort{Number: 999, ID: model.TypedID{Subtype: 3, Raw: mac}}
	ifaces := []model.Interface{{IfIndex: 27, Type: 6, PhysAddress: mac}, {IfIndex: 719, Type: 161, PhysAddress: mac}}
	ports := []model.LocalPort{lp}
	(&Collector{}).associateLocalPorts(ports, ifaces)
	if ports[0].IfIndex == nil || *ports[0].IfIndex != 27 || !ports[0].Physical {
		t.Fatalf("physical member hidden by shared logical MAC: %+v", ports[0])
	}
	ports = []model.LocalPort{lp}
	ifaces = append(ifaces, model.Interface{IfIndex: 28, Type: 6, PhysAddress: mac})
	(&Collector{}).associateLocalPorts(ports, ifaces)
	if ports[0].IfIndex != nil || ports[0].Physical {
		t.Fatalf("ambiguous physical MAC accepted: %+v", ports[0])
	}
}

// C07: a verified empty table is distinguishable from noSuchObject/unsupported.
func TestRemoteComponentStatusEmptyVsUnsupported(t *testing.T) {
	// noSuchObject / end-of-mib-view on first request.
	cs := remoteComponentStatus(snmp.WalkSummary{FirstEndOfView: true}, nil, true, false, false, true)
	if cs.Supported {
		t.Error("noSuchObject must be unsupported")
	}
	found := false
	for _, i := range cs.Issues {
		if i.Code == "MIB_UNSUPPORTED" {
			found = true
		}
	}
	if !found {
		t.Error("expected MIB_UNSUPPORTED issue")
	}

	// LLDP present + view verified + empty walk => valid empty table.
	cs2 := remoteComponentStatus(snmp.WalkSummary{}, nil, true, false, true, true)
	if !cs2.Supported {
		t.Error("verified empty table should be supported")
	}

	// LLDP present but view not verified => must not be treated as empty.
	cs3 := remoteComponentStatus(snmp.WalkSummary{}, nil, true, false, true, false)
	if cs3.Supported {
		t.Error("unverified empty walk must not be supported")
	}
}

// C08: snapshot stability — restart/wrap and lastChange change both make the
// snapshot unstable and disable absence eligibility.
func TestDeriveSnapshotStable(t *testing.T) {
	base := func(upBefore, upAfter, lcBefore, lcAfter uint32) *model.DeviceSnapshot {
		return &model.DeviceSnapshot{
			Components: map[string]model.ComponentStatus{
				"system":     {Supported: true, WalkComplete: true, DecodeComplete: true},
				"lldp_local": {Supported: true, WalkComplete: true, DecodeComplete: true},
				"lldp_rem":   {Supported: true, WalkComplete: true, DecodeComplete: true},
				"stability":  {Supported: true, WalkComplete: true, DecodeComplete: true},
			},
			Device: model.DeviceInfo{
				UptimeBefore: upBefore, UptimeAfter: upAfter,
				LastChangeBefore: lcBefore, LastChangeAfter: lcAfter,
			},
		}
	}

	c := New(Options{ViewVerified: true})

	snap := base(1000, 500, 7, 7)
	var issues []model.Issue
	c.derive(snap, true, true, true, true, &issues)
	if snap.SnapshotStable {
		t.Error("uptime decrease must be unstable")
	}
	if snap.AbsenceEligible {
		t.Error("unstable must disable absence eligibility")
	}

	snap2 := base(1000, 1000, 7, 8)
	c.derive(snap2, true, true, true, true, &issues)
	if snap2.SnapshotStable {
		t.Error("lastChange change must be unstable")
	}

	snap3 := base(1000, 1000, 7, 7)
	c.derive(snap3, true, true, true, true, &issues)
	if !snap3.SnapshotStable || !snap3.CollectionComplete {
		t.Error("stable consistent snapshot should be complete and stable")
	}
}

// C08/C07: unsupported remote table makes the device collection incomplete.
func TestDeriveUnsupportedRemote(t *testing.T) {
	c := New(Options{ViewVerified: true})
	snap := &model.DeviceSnapshot{
		Components: map[string]model.ComponentStatus{
			"system":     {Supported: true, WalkComplete: true, DecodeComplete: true},
			"lldp_local": {Supported: true, WalkComplete: true, DecodeComplete: true},
			"lldp_rem":   {Supported: false, WalkComplete: true, DecodeComplete: true},
		},
		Device: model.DeviceInfo{UptimeBefore: 1000, UptimeAfter: 1000},
	}
	var issues []model.Issue
	c.derive(snap, true, true, true, true, &issues)
	if snap.CollectionComplete {
		t.Error("unsupported remote must make collection incomplete")
	}
}

// C09: locPortNum=27 maps to ifIndex=1031 via interfaceName; no fake
// interface numbered 27 is produced.
func TestAssociateLocalPortsIfIndex(t *testing.T) {
	c := New(Options{})
	ports := []model.LocalPort{{
		Number: 27,
		ID:     model.TypedID{Subtype: lldp.PortSubtypeInterfaceName, Raw: []byte("Ten-GigabitEthernet1/0/31")},
	}}
	ifaces := []model.Interface{{
		IfIndex: 1031,
		Name:    "Ten-GigabitEthernet1/0/31",
		Type:    lldp.IfTypeEthernetCsmacd,
	}}
	c.associateLocalPorts(ports, ifaces)

	lp := ports[0]
	if lp.Number != 27 {
		t.Errorf("Number = %d, want 27 (must not be an ifIndex)", lp.Number)
	}
	if lp.IfIndex == nil || *lp.IfIndex != int32(1031) {
		t.Errorf("IfIndex = %v, want 1031", lp.IfIndex)
	}
	if !lp.Physical {
		t.Error("Physical = false, want true for ethernetCsmacd")
	}
	if lp.MappingRule != "ifname-exact" {
		t.Errorf("MappingRule = %q, want ifname-exact", lp.MappingRule)
	}
}

// C09: ambiguous interfaceName (duplicate) must not pick a first match.
func TestAssociateLocalPortsAmbiguous(t *testing.T) {
	c := New(Options{})
	ports := []model.LocalPort{{
		Number: 27,
		ID:     model.TypedID{Subtype: lldp.PortSubtypeInterfaceName, Raw: []byte("eth0")},
	}}
	ifaces := []model.Interface{
		{IfIndex: 100, Name: "eth0"},
		{IfIndex: 200, Name: "eth0"},
	}
	c.associateLocalPorts(ports, ifaces)
	if ports[0].IfIndex != nil {
		t.Errorf("ambiguous name should leave IfIndex nil, got %v", *ports[0].IfIndex)
	}
	if ports[0].MappingRule != "unresolved" {
		t.Errorf("MappingRule = %q, want unresolved", ports[0].MappingRule)
	}
}
