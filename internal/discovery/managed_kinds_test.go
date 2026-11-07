package discovery

import (
	"context"
	"encoding/json"
	"gonet/internal/identity"
	"gonet/internal/model"
	"net/netip"
	"os"
	"testing"
)

func TestManagedKindsRecurseWithoutPromotingOtherAPs(t *testing.T) {
	snaps := ringTopology(t)
	names := []string{"LabSwitch", "LabRouter", "LabController"}
	kinds := []string{"switch", "router", "wireless_controller"}
	caps := []byte{0x20, 0x08, 0x10}
	rules := []identity.Rule{}
	for i, raw := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		s := snaps[netip.MustParseAddr(raw)]
		s.Device.SysObjectID = "1.3.6.1.4.1.99999.1." + string(rune('1'+i))
		s.Device.SysDescription = names[i]
		s.Device.CapEnabled = []byte{caps[i]}
		rules = append(rules, identity.Rule{ID: kinds[i], SysObjectIDPrefix: s.Device.SysObjectID, DescriptionRegex: "^" + names[i] + "$", Action: kinds[i]})
	}
	for _, s := range snaps {
		for i := range s.Neighbors {
			n := &s.Neighbors[i]
			idx := int(n.Chassis.Raw[5]) - 1
			n.SysDescription = names[idx]
			n.CapEnabled = []byte{caps[idx]}
		}
	}
	reg, err := identity.New(identity.Options{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	fc := newFakeCollector(snaps)
	c := newRingCoordinator(t, fc, []netip.Addr{mustAddr(t, "192.0.2.1")})
	c.opts.Registry = reg
	r := c.Run(context.Background())
	if len(r.Devices) != 3 || len(r.Links) != 3 || r.Counts.DevicesCollected != 3 {
		t.Fatalf("typed recursion lost devices/links: %+v issues=%+v", r.Counts, r.Issues)
	}
	seen := map[string]int{}
	for _, d := range r.Devices {
		seen[d.Classification.Result]++
	}
	for _, k := range kinds {
		if seen[k] != 1 {
			t.Fatalf("kind %s missing: %v", k, seen)
		}
	}
	for _, l := range r.Links {
		if l.Confidence() != "bidirectional" {
			t.Fatal("typed link lost reverse evidence")
		}
	}
	classifier, _ := identity.NewClassifier(rules)
	if !classifier.ClassifyAdvertisement("Unverified AP", nil, []byte{0x10}).Excluded() {
		t.Fatal("generic AP was promoted by capability")
	}
}

func TestActualControllerWithoutLocalLLDPStaysUnconfirmed(t *testing.T) {
	b, err := os.ReadFile("../../testdata/adapters/additional-devices/ac-no-local-lldp.json")
	if err != nil {
		t.Fatal(err)
	}
	var snap model.DeviceSnapshot
	if err = json.Unmarshal(b, &snap); err != nil {
		t.Fatal(err)
	}
	rules, err := identity.LoadRules("../../config/device_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	reg, err := identity.New(identity.Options{Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	classifier, err := identity.NewClassifier(rules)
	if err != nil || classifier.Classify(snap.Device.SysObjectID, snap.Device.SysDescription, nil, nil).Result != "wireless_controller" {
		t.Fatal("fixture did not match the verified AC model rule")
	}
	c := newRingCoordinator(t, newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{snap.Device.Target: &snap}), []netip.Addr{snap.Device.Target})
	c.opts.Registry = reg
	r := c.Run(context.Background())
	if r.Status != "failed" || len(r.Devices) != 0 || len(r.Links) != 0 || r.Counts.DevicesCollected != 0 {
		t.Fatalf("missing local chassis created a confirmed device: %+v", r)
	}
}
