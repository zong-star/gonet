package identity

import (
	"gonet/internal/model"
	"net/netip"
	"testing"
)

func TestNormalizedMACExactCrossTypeAndAmbiguity(t *testing.T) {
	r, e := New(Options{})
	if e != nil {
		t.Fatal(e)
	}
	local := model.TypedID{Subtype: 7, Raw: []byte("02:00:00:00:00:20")}
	d, ok := r.EnsureAdvertised(model.LLDPNeighbor{Chassis: local})
	if !ok {
		t.Fatal("MAC local chassis was lost")
	}
	binary := model.TypedID{Subtype: 4, Raw: []byte{2, 0, 0, 0, 0, 32}}
	got := r.ResolveDirect(&model.DeviceSnapshot{Device: model.DeviceInfo{Target: netip.MustParseAddr("192.0.2.20"), Chassis: binary}})
	if got.Device != d || got.Device.State != StateVerified || string(local.Raw) != "02:00:00:00:00:20" {
		t.Fatal("cross-type identity or raw preservation failed")
	}
	// Address is an attribute: a second access address does not create a device.
	again := r.ResolveDirect(&model.DeviceSnapshot{Device: model.DeviceInfo{Target: netip.MustParseAddr("192.0.2.21"), Chassis: local}})
	if again.Device != d || len(r.Devices()) != 1 {
		t.Fatal("identity depended on access IP")
	}
	for _, raw := range []string{"foobar", "prefix02:00:00:00:00:20", "01:00:00:00:00:20", "00:00:00:00:00:00"} {
		if _, ok := NormalizedKey(model.TypedID{Subtype: 7, Raw: []byte(raw)}, false); ok {
			t.Fatalf("unsafe local value promoted: %q", raw)
		}
	}
	conflict, _ := New(Options{})
	if e := conflict.Restore([]*Device{{Ref: 1, StrongKey: "manual:one", Chassis: binary}, {Ref: 2, StrongKey: "manual:two", Chassis: local}}); e != nil {
		t.Fatal(e)
	}
	if got := conflict.ResolveAdvertised(model.LLDPNeighbor{Chassis: local}); got.State != ResolvedConflict {
		t.Fatal("ambiguous MAC owners merged")
	}
	// An exact typed owner takes precedence over a different-type candidate.
	conflict.byKey["lldp:4:020000000020"] = conflict.devices[1]
	if got := conflict.ResolveAdvertised(model.LLDPNeighbor{Chassis: binary}); got.Device != conflict.devices[1] {
		t.Fatal("exact typed key lost precedence")
	}
}
