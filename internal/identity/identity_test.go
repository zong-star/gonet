package identity

import (
	"net/netip"
	"testing"
	"time"

	"gonet/internal/model"
)

func newTestRegistry(t *testing.T, opts ...Options) *Registry {
	t.Helper()
	o := Options{Now: func() time.Time { return time.Unix(1000, 0).UTC() }}
	if len(opts) > 0 {
		o = opts[0]
		if o.Now == nil {
			o.Now = func() time.Time { return time.Unix(1000, 0).UTC() }
		}
	}
	r, err := New(o)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return r
}

func macChassis(mac ...byte) model.TypedID {
	return model.TypedID{Subtype: 4, Raw: mac}
}

func weakChassis(raw string) model.TypedID {
	return model.TypedID{Subtype: 7, Raw: []byte(raw)}
}

func snap(addr, sysName string, chassis model.TypedID, caps []byte) *model.DeviceSnapshot {
	return &model.DeviceSnapshot{
		Device: model.DeviceInfo{
			Target:       netip.MustParseAddr(addr),
			Chassis:      chassis,
			SysName:      sysName,
			SysObjectID:  "1.3.6.1.4.1.99999.1.1",
			CapSupported: caps,
			CapEnabled:   caps,
		},
	}
}

// I01: same MAC chassis, multiple IPs, renamed -> one device, new verified
// address, stable ref.
func TestI01SameChassisMultipleIPs(t *testing.T) {
	r := newTestRegistry(t)
	d1 := r.ResolveDirect(snap("10.0.0.1", "sw1", macChassis(0, 1, 2, 3, 4, 5), []byte{0x20})).Device
	res := r.ResolveDirect(snap("10.0.0.2", "sw1-renamed", macChassis(0, 1, 2, 3, 4, 5), []byte{0x20}))
	if res.State != Resolved {
		t.Fatalf("state = %v, want resolved", res.State)
	}
	if res.Device.Ref != d1.Ref {
		t.Errorf("ref changed: %d -> %d", d1.Ref, res.Device.Ref)
	}
	if len(res.Device.Addresses) != 2 {
		t.Fatalf("addresses = %d, want 2", len(res.Device.Addresses))
	}
	for _, a := range res.Device.Addresses {
		if a.State != AddrVerified {
			t.Errorf("address %v state = %v, want verified", a.Addr, a.State)
		}
	}
	if len(r.Devices()) != 1 {
		t.Errorf("devices = %d, want 1", len(r.Devices()))
	}
}

// I02: same sysName, different chassis -> two devices; never merge by name.
func TestI02SameSysNameDifferentChassis(t *testing.T) {
	r := newTestRegistry(t)
	d1 := r.ResolveDirect(snap("10.0.0.1", "sw", macChassis(0, 1, 2, 3, 4, 5), []byte{0x20})).Device
	d2 := r.ResolveDirect(snap("10.0.0.2", "sw", macChassis(0, 1, 2, 3, 4, 6), []byte{0x20})).Device
	if d1.Ref == d2.Ref {
		t.Error("devices with the same sysName but different chassis were merged")
	}
	if len(r.Devices()) != 2 {
		t.Errorf("devices = %d, want 2", len(r.Devices()))
	}
}

// I03: identical weak (local) chassis bytes on two devices must not merge.
func TestI03WeakIdentityNotMerged(t *testing.T) {
	r := newTestRegistry(t)
	d1 := r.ResolveDirect(snap("10.0.0.1", "a", weakChassis("abc"), nil)).Device
	d2 := r.ResolveDirect(snap("10.0.0.2", "b", weakChassis("abc"), nil)).Device
	if d1.Ref == d2.Ref {
		t.Error("weak identity was merged globally")
	}
	if d1.StrongKey != "" || d2.StrongKey != "" {
		t.Errorf("weak identity produced strong key: %q / %q", d1.StrongKey, d2.StrongKey)
	}
}

// I04: an IP temporary device gains a unique strong identity in place.
func TestI04TempUpgrade(t *testing.T) {
	r := newTestRegistry(t)
	temp := r.ResolveDirect(snap("10.0.0.1", "sw", model.TypedID{}, nil)).Device
	if temp.State != StateProvisional {
		t.Fatalf("temp state = %v, want provisional", temp.State)
	}
	res := r.ResolveDirect(snap("10.0.0.1", "sw", macChassis(0, 1, 2, 3, 4, 5), []byte{0x20}))
	if res.Device.Ref != temp.Ref {
		t.Errorf("device ref changed on upgrade: %d -> %d", temp.Ref, res.Device.Ref)
	}
	if res.Device.State != StateVerified {
		t.Errorf("state = %v, want verified", res.Device.State)
	}
	if res.Device.StrongKey != "lldp:4:000102030405" {
		t.Errorf("strong key = %q", res.Device.StrongKey)
	}
}

// I05: address reuse by a different strong chassis -> conflict, no rebind.
func TestI05AddressReuseConflict(t *testing.T) {
	r := newTestRegistry(t)
	d1 := r.ResolveDirect(snap("10.0.0.1", "sw1", macChassis(0, 1, 2, 3, 4, 5), []byte{0x20})).Device
	res := r.ResolveDirect(snap("10.0.0.1", "sw2", macChassis(0, 1, 2, 3, 4, 6), []byte{0x20}))
	if res.State != ResolvedConflict {
		t.Fatalf("state = %v, want conflict", res.State)
	}
	if res.Device != nil {
		t.Error("conflict must not return a device")
	}
	got, _ := r.ByRef(d1.Ref)
	if got.StrongKey != "lldp:4:000102030405" {
		t.Errorf("old device identity overwritten: %q", got.StrongKey)
	}
	if len(got.Addresses) != 1 || got.Addresses[0].State != AddrConflict {
		t.Errorf("address not marked conflict: %+v", got.Addresses)
	}
}

// I05 (variant): strong identity already owned by another record must not merge
// a temporary device into it.
func TestI05IdentityOwnedElsewhereConflict(t *testing.T) {
	r := newTestRegistry(t)
	r.ResolveDirect(snap("10.0.0.1", "sw1", macChassis(0, 1, 2, 3, 4, 5), []byte{0x20}))
	temp := r.ResolveDirect(snap("10.0.0.2", "temp", model.TypedID{}, nil)).Device
	res := r.ResolveDirect(snap("10.0.0.2", "sw1", macChassis(0, 1, 2, 3, 4, 5), []byte{0x20}))
	if res.State != ResolvedConflict {
		t.Fatalf("state = %v, want conflict (identity owned elsewhere)", res.State)
	}
	got, _ := r.ByRef(temp.Ref)
	if got.StrongKey != "" {
		t.Error("temporary device was silently merged into an existing strong device")
	}
}

// C05: capability bit order; bridge+router (0x28) is not excluded, router-only
// and AP/telephone/stationOnly are.
func TestC05CapabilityClassification(t *testing.T) {
	c, err := NewClassifier(nil)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		bits         []byte
		wantExcluded bool
	}{
		{[]byte{0x20}, false}, // bridge
		{[]byte{0x28}, false}, // bridge + router
		{[]byte{0x08}, true},  // router only
		{[]byte{0x10}, true},  // wlanAccessPoint
		{[]byte{0x04}, true},  // telephone
		{[]byte{0x01}, true},  // stationOnly
	}
	for _, tc := range cases {
		got := c.Classify("", "", tc.bits, tc.bits)
		if gotExcluded := got.Result == "excluded"; gotExcluded != tc.wantExcluded {
			t.Errorf("bits %#x: result=%v wantExcluded=%v", tc.bits, got.Result, tc.wantExcluded)
		}
	}

	// sysObjectID rule confirms a switch even with bridge+router.
	c2, err := NewClassifier([]Rule{{ID: "vendor-sw", SysObjectIDPrefix: "1.3.6.1.4.1.9", Action: "switch"}})
	if err != nil {
		t.Fatal(err)
	}
	got := c2.Classify("1.3.6.1.4.1.9.1.1", "", []byte{0x28}, []byte{0x28})
	if got.Result != "switch" || got.RuleID != "vendor-sw" {
		t.Errorf("sysObjectID rule: %+v, want switch/vendor-sw", got)
	}
}

// Description rules can confirm an inaccessible neighbor by verified model.
func TestDescriptionRule(t *testing.T) {
	c, err := NewClassifier([]Rule{{ID: "desc-sw", DescriptionRegex: `(?i)switch`, Action: "switch"}})
	if err != nil {
		t.Fatal(err)
	}
	got := c.Classify("", "Core Switch 9300", nil, nil)
	if got.Result != "switch" {
		t.Errorf("result = %v, want switch", got)
	}
}

// ResolveAdvertised never binds advertised addresses and stays unresolved
// without a known strong identity.
func TestResolveAdvertised(t *testing.T) {
	r := newTestRegistry(t)
	known := r.ResolveDirect(snap("10.0.0.1", "sw1", macChassis(0, 1, 2, 3, 4, 5), []byte{0x20})).Device

	got := r.ResolveAdvertised(model.LLDPNeighbor{Chassis: macChassis(0, 1, 2, 3, 4, 5)})
	if got.State != Resolved || got.Device != known {
		t.Errorf("known strong chassis: state=%v device=%v, want resolved device", got.State, got.Device)
	}

	unknown := r.ResolveAdvertised(model.LLDPNeighbor{Chassis: macChassis(0, 9, 9, 9, 9, 9)})
	if unknown.State != ResolvedUnresolved || unknown.Device != nil {
		t.Errorf("unknown strong chassis: state=%v device=%v, want unresolved", unknown.State, unknown.Device)
	}

	weak := r.ResolveAdvertised(model.LLDPNeighbor{Chassis: weakChassis("abc")})
	if weak.State != ResolvedUnresolved || weak.Device != nil {
		t.Errorf("weak chassis: state=%v device=%v, want unresolved", weak.State, weak.Device)
	}
}
