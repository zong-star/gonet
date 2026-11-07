package identity

import (
	"encoding/hex"
	"testing"
)

func TestOperatorClassificationIsIdentityScoped(t *testing.T) {
	weak := weakChassis("02:00:00:00:00:01")
	r := newTestRegistry(t, Options{Overrides: []Override{{Subtype: 7, RawHex: hex.EncodeToString(weak.Raw), CanonicalKey: "manual:confirmed-stack"}}, ClassificationOverrides: []ClassificationOverride{{IdentityKey: "manual:confirmed-stack", Result: "switch", Reason: "operator confirmed two-member switch stack"}}})
	core := snap("192.0.2.1", "generic-linux", weak, nil)
	core.Device.SysObjectID = "1.3.6.1.4.1.45577"
	core.Device.SysDescription = "Linux Sundray"
	known := r.ResolveDirect(core).Device
	if known == nil || !known.Classification.Switch() || known.StrongKey != "manual:confirmed-stack" {
		t.Fatal("operator identity override did not classify confirmed core")
	}
	other := snap("192.0.2.2", "same-name", weakChassis("02:00:00:00:00:02"), nil)
	other.Device.SysObjectID = core.Device.SysObjectID
	other.Device.SysDescription = core.Device.SysDescription
	if r.ResolveDirect(other).Device.Classification.Switch() {
		t.Fatal("manual classification leaked to another generic vendor device")
	}
}

func TestOperatorClassificationRejectsWeakOrAmbiguousKeys(t *testing.T) {
	for _, key := range []string{"", "lldp:7:6162", "lldp:4:010000000001", "vendor:45577"} {
		if _, err := New(Options{ClassificationOverrides: []ClassificationOverride{{IdentityKey: key, Result: "switch", Reason: "invalid"}}}); err == nil {
			t.Fatalf("unsafe override accepted: %q", key)
		}
	}
}

func TestConfiguredClassificationSurvivesRestoredPrimaryIdentity(t *testing.T) {
	chassis := weakChassis("02:00:00:00:00:01")
	before := newTestRegistry(t)
	device := before.ResolveDirect(snap("192.0.2.1", "generic", chassis, nil)).Device
	oldKey, oldRef := device.StrongKey, device.Ref
	after := newTestRegistry(t, Options{Overrides: []Override{{Subtype: 7, RawHex: hex.EncodeToString(chassis.Raw), CanonicalKey: "manual:confirmed"}}, ClassificationOverrides: []ClassificationOverride{{IdentityKey: "manual:confirmed", Result: "switch", Reason: "operator inventory and direct chassis verification"}}})
	if err := after.Restore(before.Devices()); err != nil {
		t.Fatal(err)
	}
	got := after.ResolveDirect(snap("192.0.2.1", "generic", chassis, nil))
	if got.State != Resolved || got.Device.Ref != oldRef || got.Device.StrongKey != oldKey || !got.Device.Classification.Switch() {
		t.Fatal("restored identity lost explicit classification or stable ID")
	}
}
