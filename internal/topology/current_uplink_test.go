package topology

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"gonet/internal/identity"
	"gonet/internal/model"
)

func currentUplinkPair(t *testing.T) (model.DeviceSnapshot, model.DeviceSnapshot) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/adapters/current-topology-dual-uplink/pair.json")
	if err != nil {
		t.Fatal(err)
	}
	var pair struct{ Core, Peer model.DeviceSnapshot }
	if err := json.Unmarshal(b, &pair); err != nil {
		t.Fatal(err)
	}
	return pair.Core, pair.Peer
}

func TestCurrentDualUplinkRealPairBothOrders(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		core, peer := currentUplinkPair(t)
		rules, err := identity.LoadRules("../../config/device_rules.yaml")
		if err != nil {
			t.Fatal(err)
		}
		reg, err := identity.New(identity.Options{Rules: rules, Overrides: []identity.Override{
			{Subtype: core.Device.Chassis.Subtype, RawHex: hex.EncodeToString(core.Device.Chassis.Raw), CanonicalKey: "manual:lab-core"},
			{Subtype: peer.Neighbors[0].Chassis.Subtype, RawHex: hex.EncodeToString(peer.Neighbors[0].Chassis.Raw), CanonicalKey: "manual:lab-core"},
			{Subtype: peer.Device.Chassis.Subtype, RawHex: hex.EncodeToString(peer.Device.Chassis.Raw), CanonicalKey: "manual:lab-peer"},
			{Subtype: core.Neighbors[0].Chassis.Subtype, RawHex: hex.EncodeToString(core.Neighbors[0].Chassis.Raw), CanonicalKey: "manual:lab-peer"},
		}, ClassificationOverrides: []identity.ClassificationOverride{{IdentityKey: "manual:lab-core", Result: "switch", Reason: "verified fixture"}}})
		if err != nil {
			t.Fatal(err)
		}
		builder := NewBuilder(reg, NewResolver(nil))
		if reverse {
			builder.AddSnapshot(&peer)
			builder.AddSnapshot(&core)
		} else {
			builder.AddSnapshot(&core)
			builder.AddSnapshot(&peer)
		}
		g := builder.Build()
		if len(g.Links) != 2 || len(g.Observations) != 4 || len(g.Unresolved) != 0 || len(g.Conflicts) != 0 {
			t.Fatalf("reverse=%v links=%d observations=%d unresolved=%+v issues=%+v", reverse, len(g.Links), len(g.Observations), g.Unresolved, g.Issues)
		}
		for _, l := range g.Links {
			if l.Confidence() != "bidirectional" {
				t.Fatalf("not reconciled: %+v", l)
			}
		}
	}
}

func TestPhysicalMACRejectsAmbiguousAndLogicalOnly(t *testing.T) {
	mac := []byte{2, 0, 0, 0, 0, 1}
	for _, test := range []struct {
		name  string
		types []int32
		want  bool
	}{
		{"physical_and_lag", []int32{6, 161}, true},
		{"two_physical", []int32{6, 6, 161}, false},
		{"logical_only", []int32{161}, false},
		{"no_match", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var ifaces []model.Interface
			for i, typ := range test.types {
				ifaces = append(ifaces, model.Interface{IfIndex: int32(i + 20), Type: typ, PhysAddress: mac})
			}
			r := NewResolver(nil)
			lp := model.LocalPort{Number: 999, ID: model.TypedID{Subtype: 3, Raw: mac}}
			p := r.ResolveLocalPort(1, lp, ifaces).Port
			if p.Physical != test.want {
				t.Fatalf("unexpected MAC mapping: %+v", p)
			}
			if p.Physical && *p.IfIndex == 999 {
				t.Fatal("used LLDP number as ifIndex")
			}
			r.SetDeviceSnapshot(1, &model.DeviceSnapshot{Interfaces: ifaces})
			if !test.want {
				code, _ := r.RemotePortFailure(1, lp.ID)
				want := "REMOTE_MAC_NO_PHYSICAL_MATCH"
				if len(test.types) > 1 {
					want = "REMOTE_MAC_AMBIGUOUS"
				}
				if code != want {
					t.Fatalf("got %s want %s", code, want)
				}
			}
		})
	}
}

func TestTS7914AliasPromotesPlaceholderAndSurvivesRestore(t *testing.T) {
	core, _ := currentUplinkPair(t)
	r := NewResolver(nil)
	id := model.TypedID{Subtype: 5, Raw: []byte("Gi1/1/19")}
	n := model.LLDPNeighbor{Port: id}
	placeholder := r.ResolveRemotePort(1, n, nil, nil).Port
	r.SetDeviceSnapshot(1, &core)
	canonical := r.ResolveLocalPort(1, core.LocalPorts[0], core.Interfaces).Port
	resolved := r.ResolveRemotePort(1, n, nil, nil).Port
	if !resolved.Physical || resolved.Ref != canonical.Ref || resolved.Ref == placeholder.Ref || *resolved.IfIndex != 81 {
		t.Fatalf("alias not promoted: %+v", resolved)
	}
	for _, reverse := range []bool{false, true} {
		copyPort := *canonical
		copyPlaceholder := *placeholder
		ports := []*Port{&copyPort, &copyPlaceholder}
		if reverse {
			ports[0], ports[1] = ports[1], ports[0]
		}
		registry := NewPortRegistry(nil)
		if err := registry.Restore(ports); err != nil {
			t.Fatal(err)
		}
		restarted := NewResolver(registry)
		restarted.SetDeviceSnapshot(1, &core)
		p := restarted.ResolveLocalPort(1, core.LocalPorts[0], core.Interfaces)
		if p.State != PortVerified || p.Port.Ref != canonical.Ref || len(p.Issues) != 0 {
			t.Fatalf("restart changed identity: %+v", p)
		}
		if got := restarted.ResolveRemotePort(1, n, nil, nil); got.Port.Ref != canonical.Ref || !got.Port.Physical {
			t.Fatalf("restart lost alias: %+v", got)
		}
	}
}

func TestTS7914AliasRequiresFingerprintAndUniqueCurrentPhysical(t *testing.T) {
	for _, failure := range []string{"fingerprint", "missing_local", "nonphysical", "duplicate_name", "mapped_alias"} {
		t.Run(failure, func(t *testing.T) {
			core, _ := currentUplinkPair(t)
			r := NewResolver(nil)
			id := model.TypedID{Subtype: 5, Raw: []byte("Gi1/1/19")}
			switch failure {
			case "fingerprint":
				core.Device.SysDescription = "unverified firmware"
			case "missing_local":
				core.LocalPorts = nil
			case "nonphysical":
				core.Interfaces[0].Type = 161
			case "duplicate_name":
				core.Interfaces = append(core.Interfaces, core.Interfaces[0])
			case "mapped_alias":
				r.ResolveLocalPort(1, model.LocalPort{ID: id}, []model.Interface{{IfIndex: 999, Type: 6, Name: "Gi1/1/19"}})
			}
			r.SetDeviceSnapshot(1, &core)
			for _, lp := range core.LocalPorts {
				r.ResolveLocalPort(1, lp, core.Interfaces)
			}
			p := r.ResolveRemotePort(1, model.LLDPNeighbor{Port: id}, nil, nil)
			if p.Port.Physical {
				t.Fatalf("unsafe alias accepted: %+v", p)
			}
		})
	}
}
