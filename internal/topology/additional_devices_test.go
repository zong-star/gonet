package topology

import (
	"encoding/json"
	"gonet/internal/identity"
	"gonet/internal/model"
	"os"
	"testing"
)

func TestActualS5720AndControllerModelKinds(t *testing.T) {
	b, err := os.ReadFile("../../testdata/adapters/additional-devices/models.json")
	if err != nil {
		t.Fatal(err)
	}
	var facts []struct {
		ID, Kind, Description string
		OID                   string `json:"sys_object_id"`
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
		got := c.Classify(f.OID, f.Description, nil, nil)
		if got.Result != f.Kind || got.RuleID != f.ID {
			t.Fatalf("wrong managed kind: %+v", got)
		}
		if c.Classify(f.OID+"0", f.Description, nil, nil).Managed() {
			t.Fatal("product OID boundary escaped")
		}
		ad := c.ClassifyAdvertisement(f.Description, nil, []byte{0x10})
		if !ad.IsProbeCandidate() || ad.Managed() || ad.CandidateKind != f.Kind {
			t.Fatalf("advertisement claimed direct verification: %+v", ad)
		}
	}
}

func TestS5720ParentUnlocksSupportedH3CDownstream(t *testing.T) {
	b, err := os.ReadFile("../../testdata/adapters/additional-devices/uplink.json")
	if err != nil {
		t.Fatal(err)
	}
	var pair struct{ Parent, Peer model.DeviceSnapshot }
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
		builder := NewBuilder(reg, nil)
		if reverse {
			builder.AddSnapshot(&pair.Peer)
			builder.AddSnapshot(&pair.Parent)
		} else {
			builder.AddSnapshot(&pair.Parent)
			builder.AddSnapshot(&pair.Peer)
		}
		g := builder.Build()
		if len(g.Links) != 1 || g.Links[0].Confidence() != "bidirectional" || len(g.Unresolved) != 0 {
			t.Fatalf("paired legacy downlink failed: %+v unresolved=%+v", g.Links, g.Unresolved)
		}
	}
}
