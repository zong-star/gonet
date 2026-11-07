package discovery

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/topology"
	"net/netip"
	"os"
	"testing"
)

func discoveryCurrentPair(t *testing.T) (model.DeviceSnapshot, model.DeviceSnapshot) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/adapters/current-topology-dual-uplink/pair.json")
	if err != nil {
		t.Fatal(err)
	}
	var pair struct{ Core, Peer model.DeviceSnapshot }
	if err = json.Unmarshal(b, &pair); err != nil {
		t.Fatal(err)
	}
	return pair.Core, pair.Peer
}
func TestCurrentDualUplinkCoordinatorReconcilesBothDirections(t *testing.T) {
	core, peer := discoveryCurrentPair(t)
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
	fc := newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{core.Device.Target: &core, peer.Device.Target: &peer})
	c, err := New(Options{Seeds: []netip.Addr{core.Device.Target, peer.Device.Target}, ManagementCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, Workers: 2, MaxDepth: 2, MaxTargets: 8, Collector: fc, Registry: reg, Resolver: topology.NewResolver(nil)})
	if err != nil {
		t.Fatal(err)
	}
	result := c.Run(context.Background())
	if len(result.Links) != 2 || len(result.Observations) != 4 || len(result.Unresolved) != 0 {
		t.Fatalf("coordinator did not reconcile physical pair: links=%d obs=%d unresolved=%+v issues=%+v", len(result.Links), len(result.Observations), result.Unresolved, result.Issues)
	}
	for _, l := range result.Links {
		if l.Confidence() != "bidirectional" {
			t.Fatalf("direction did not converge: %+v", l)
		}
	}
}
