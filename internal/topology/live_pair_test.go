package topology

import (
	"encoding/hex"
	"encoding/json"
	"gonet/internal/identity"
	"gonet/internal/model"
	"os"
	"testing"
)

func TestRealTS7914H3CPairUsesOnlyReliableDirection(t *testing.T) {
	b, err := os.ReadFile("../../testdata/adapters/sundray-ts7914/h3c-pair.json")
	if err != nil {
		t.Fatal(err)
	}
	var pair struct {
		Core model.DeviceSnapshot `json:"core"`
		Peer model.DeviceSnapshot `json:"peer"`
	}
	if err := json.Unmarshal(b, &pair); err != nil {
		t.Fatal(err)
	}
	coreKey, peerKey := "manual:lab-core", "manual:lab-peer"
	rules, err := identity.LoadRules("../../config/device_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := identity.New(identity.Options{Rules: rules, Overrides: []identity.Override{
		{Subtype: 7, RawHex: hex.EncodeToString(pair.Core.Device.Chassis.Raw), CanonicalKey: coreKey},
		{Subtype: 4, RawHex: hex.EncodeToString(pair.Peer.Neighbors[0].Chassis.Raw), CanonicalKey: coreKey},
		{Subtype: 7, RawHex: hex.EncodeToString(pair.Core.Neighbors[0].Chassis.Raw), CanonicalKey: peerKey},
		{Subtype: 4, RawHex: hex.EncodeToString(pair.Peer.Device.Chassis.Raw), CanonicalKey: peerKey},
	}, ClassificationOverrides: []identity.ClassificationOverride{{IdentityKey: coreKey, Result: "switch", Reason: "operator confirmed the stack"}}})
	if err != nil {
		t.Fatal(err)
	}
	res := newTestResolver()
	if err := res.SetOverrides([]Override{{IdentityKey: coreKey, CanonicalKey: MakePortKey(5, pair.Core.LocalPorts[0].ID.Raw), Aliases: []PortKey{MakePortKey(5, pair.Peer.Neighbors[0].Port.Raw)}, Physical: true, Reason: "paired raw samples uniquely match the physical uplink"}}); err != nil {
		t.Fatal(err)
	}
	builder := NewBuilder(reg, res)
	builder.AddSnapshot(&pair.Core)
	builder.AddSnapshot(&pair.Peer)
	graph := builder.Build()
	if len(graph.Links) != 1 || graph.Links[0].Confidence() != "single_sided" || len(graph.Observations) != 1 || len(graph.Unresolved) != 1 {
		t.Fatalf("paired evidence was over-promoted: links=%+v obs=%d unresolved=%d", graph.Links, len(graph.Observations), len(graph.Unresolved))
	}
	if graph.Unresolved[0].Raw.Port.Subtype != 0 {
		t.Fatal("invalid Sundray port subtype was rewritten")
	}
	if !graph.Devices[1].Classification.Switch() {
		t.Fatal("real model rule did not confirm the H3C")
	}
}

func TestRealH3CHuaweiPairIsBidirectional(t *testing.T) {
	b, err := os.ReadFile("../../testdata/adapters/huawei-s5735-l8t4s-qa2/h3c-pair.json")
	if err != nil {
		t.Fatal(err)
	}
	var pair struct {
		H3C    model.DeviceSnapshot `json:"h3c"`
		Huawei model.DeviceSnapshot `json:"huawei"`
	}
	if err := json.Unmarshal(b, &pair); err != nil {
		t.Fatal(err)
	}
	rules, err := identity.LoadRules("../../config/device_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, reverse := range []bool{false, true} {
		reg, err := identity.New(identity.Options{Rules: rules})
		if err != nil {
			t.Fatal(err)
		}
		builder := NewBuilder(reg, NewResolver(nil))
		if reverse {
			builder.AddSnapshot(&pair.Huawei)
			builder.AddSnapshot(&pair.H3C)
		} else {
			builder.AddSnapshot(&pair.H3C)
			builder.AddSnapshot(&pair.Huawei)
		}
		g := builder.Build()
		if len(g.Devices) != 2 || len(g.Ports) != 2 || len(g.Links) != 1 || g.Links[0].Confidence() != "bidirectional" || len(g.Observations) != 2 || len(g.Unresolved) != 0 || len(g.Conflicts) != 0 {
			t.Fatalf("real paired uplink did not resolve: reverse=%v devices=%d ports=%d links=%+v observations=%d unresolved=%+v", reverse, len(g.Devices), len(g.Ports), g.Links, len(g.Observations), g.Unresolved)
		}
		for _, p := range g.Ports {
			if !p.Physical || p.IfIndex == nil || *p.IfIndex != 6 {
				t.Fatalf("unverified physical endpoint: %+v", p)
			}
		}
		// Huawei's LLDP localPortNum is 1 while its ifIndex is 6.
		if pair.Huawei.LocalPorts[0].Number != 1 || *pair.Huawei.LocalPorts[0].IfIndex != 6 {
			t.Fatal("fixture lost the independent LLDP/IF-MIB indexes")
		}
	}
}
