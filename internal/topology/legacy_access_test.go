package topology

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"gonet/internal/identity"
	"gonet/internal/model"
)

func TestLegacyModelAndFirmwareBoundaries(t *testing.T) {
	b, err := os.ReadFile("../../testdata/adapters/legacy-access/models.json")
	if err != nil {
		t.Fatal(err)
	}
	var facts []struct {
		ID, Vendor, Model, Source, Description string
		OID                                    string `json:"sys_object_id"`
	}
	if err = json.Unmarshal(b, &facts); err != nil {
		t.Fatal(err)
	}
	rules, err := identity.LoadRules("../../config/device_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := identity.NewClassifier(rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range facts {
		t.Run(f.ID, func(t *testing.T) {
			oid := f.OID
			if oid == "" {
				t.Fatal("direct product OID fixture missing")
			}
			good := []string{f.Description, strings.ReplaceAll(f.Description, "\r\n", "\n"), strings.ReplaceAll(strings.ReplaceAll(f.Description, "Version 5.70", "Version   5.70"), "Version 5.20", "Version\t5.20")}
			for _, descr := range good {
				if got := c.Classify(oid, descr, nil, nil); !got.Switch() || got.RuleID != f.ID {
					t.Fatalf("verified legacy sample rejected: %+v", got)
				}
			}
			bad := []string{strings.ReplaceAll(f.Description, f.Model, f.Model+"-Unverified"), strings.ReplaceAll(strings.ReplaceAll(f.Description, "5.20", "5.70"), "5.70", "9.99"), strings.ReplaceAll(strings.ReplaceAll(f.Description, "5203P05", "5203P99"), "5103P01", "5103P99")}
			if f.Vendor == "Huawei" {
				bad = append(bad, strings.ReplaceAll(f.Description, "V100R006C", "V100R999C"))
			}
			for _, descr := range bad {
				if descr != f.Description && c.Classify(oid, descr, nil, nil).Switch() {
					t.Fatalf("unverified model/firmware accepted: %q", descr)
				}
			}
			if c.Classify("1.3.6.1.4.1.99999.1", f.Description, nil, nil).Switch() || c.Classify(oid+"0", f.Description, nil, nil).Switch() {
				t.Fatal("OID segment boundary escaped")
			}
		})
	}
}

func TestRealLegacyH3CUplinksAreBidirectional(t *testing.T) {
	b, err := os.ReadFile("../../testdata/adapters/legacy-access/uplinks.json")
	if err != nil {
		t.Fatal(err)
	}
	var pair struct {
		Parent model.DeviceSnapshot
		Peers  []model.DeviceSnapshot
	}
	if err = json.Unmarshal(b, &pair); err != nil {
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
		resolver := NewResolver(nil)
		builder := NewBuilder(reg, resolver)
		if !reverse {
			builder.AddSnapshot(&pair.Parent)
		}
		for i := range pair.Peers {
			builder.AddSnapshot(&pair.Peers[i])
		}
		if reverse {
			builder.AddSnapshot(&pair.Parent)
		}
		g := builder.Build()
		if len(g.Devices) != 3 || len(g.Links) != 2 || len(g.Observations) != 4 || len(g.Unresolved) != 0 || len(g.Conflicts) != 0 {
			t.Fatalf("reverse=%v devices=%d links=%+v unresolved=%+v conflicts=%+v", reverse, len(g.Devices), g.Links, g.Unresolved, g.Conflicts)
		}
		for _, l := range g.Links {
			if l.Confidence() != "bidirectional" {
				t.Fatalf("lost paired evidence: %+v", l)
			}
		}
		// This model uses normal ifType=6; don't generalize the S5120 ifType=117 rule.
		for _, p := range g.Ports {
			if !p.Physical || p.IfType != 6 || p.IfIndex == nil {
				t.Fatalf("unverified physical endpoint: %+v", p)
			}
		}
	}
}

func TestLegacyHuaweiSystemWithoutLLDPIsNotVerifiedByIP(t *testing.T) {
	b, err := os.ReadFile("../../testdata/adapters/legacy-access/huawei-no-local-lldp.json")
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
	result := reg.ResolveDirect(&snap)
	if result.Device == nil || !result.Device.Classification.Switch() || result.Device.StrongKey != "" || result.Device.State == identity.StateVerified || snap.AbsenceEligible {
		t.Fatalf("missing local LLDP was promoted by IP: %+v", result)
	}
}
