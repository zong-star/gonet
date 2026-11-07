package topology

import (
	"encoding/json"
	"gonet/internal/model"
	"os"
	"testing"
)

func TestT501SyntheticAdapterFixture(t *testing.T) {
	rules, err := LoadPortRules("../../testdata/adapters/synthetic/port_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../testdata/adapters/synthetic/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		RuleID    string `json:"rule_id"`
		Port      string `json:"port"`
		Interface string `json:"interface"`
		IfType    int32  `json:"if_type"`
		Physical  bool   `json:"physical"`
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.RuleID+"/"+c.Port, func(t *testing.T) {
			r := newTestResolver()
			if err := r.SetRules(rules); err != nil {
				t.Fatal(err)
			}
			r.SetDeviceRule(1, c.RuleID)
			p := r.ResolveLocalPort(1, model.LocalPort{Number: 27, ID: model.TypedID{Subtype: 5, Raw: []byte(c.Port)}}, []model.Interface{{IfIndex: 1031, Name: c.Interface, Type: c.IfType}}).Port
			if p.Physical != c.Physical {
				t.Fatalf("physical=%v want %v", p.Physical, c.Physical)
			}
		})
	}
}

func TestT501OneToOnePortOverride(t *testing.T) {
	r := newTestResolver()
	r.SetDeviceIdentity(1, "manual:lab")
	oldKey := MakePortKey(5, []byte("old"))
	newKey := MakePortKey(5, []byte("new"))
	if err := r.SetOverrides([]Override{{IdentityKey: "manual:lab", CanonicalKey: oldKey, Aliases: []PortKey{newKey}, Physical: true, Reason: "synthetic verified mapping"}}); err != nil {
		t.Fatal(err)
	}
	p1 := r.ResolveLocalPort(1, model.LocalPort{Number: 1, ID: model.TypedID{Subtype: 5, Raw: []byte("old")}}, []model.Interface{{IfIndex: 101, Name: "old", Type: 6}}).Port
	p2 := r.ResolveLocalPort(1, model.LocalPort{Number: 1, ID: model.TypedID{Subtype: 5, Raw: []byte("new")}}, []model.Interface{{IfIndex: 101, Name: "new", Type: 6}}).Port
	if p1.Ref != p2.Ref || p2.Key != oldKey || !p2.Physical || len(r.Ports().All()) != 1 {
		t.Fatal("explicit alias did not preserve port identity")
	}
}

func TestT501AmbiguousRulesRejected(t *testing.T) {
	r := newTestResolver()
	if err := r.SetRules([]PortRule{{ID: "ambiguous", DeviceRuleID: "model", Fixture: "synthetic", Aliases: map[string]string{"a": "c", "b": "c"}}}); err == nil {
		t.Fatal("many-to-one alias accepted")
	}
	if err := r.SetOverrides([]Override{{IdentityKey: "manual:lab", CanonicalKey: "lldp:5:zz", Reason: "invalid"}}); err == nil {
		t.Fatal("invalid typed key accepted")
	}
}

func TestManualAliasCannotOverwriteExistingPhysicalPort(t *testing.T) {
	r := newTestResolver()
	r.SetDeviceIdentity(1, "manual:lab")
	old := model.LocalPort{Number: 1, ID: model.TypedID{Subtype: 5, Raw: []byte("old")}}
	first := r.ResolveLocalPort(1, old, []model.Interface{{IfIndex: 101, Name: "old", Type: 6}}).Port
	if err := r.SetOverrides([]Override{{IdentityKey: "manual:lab", CanonicalKey: MakePortKey(5, []byte("other")), Aliases: []PortKey{first.Key}, Physical: true, Reason: "collision"}}); err != nil {
		t.Fatal(err)
	}
	result := r.ResolveLocalPort(1, old, []model.Interface{{IfIndex: 101, Name: "old", Type: 6}})
	if result.State != PortConflict || first.Physical {
		t.Fatal("alias collision did not quarantine both ports")
	}
	if bound, _ := r.Ports().Get(1, MakePortKey(5, []byte("old"))); bound != first {
		t.Fatal("alias binding was overwritten")
	}
}

func TestVerifiedManualAliasPromotesNameOnlyPlaceholder(t *testing.T) {
	r := newTestResolver()
	r.SetDeviceIdentity(1, "manual:lab")
	alias := MakePortKey(5, []byte("Gi1/1/17"))
	placeholder := r.ResolveRemotePort(1, model.LLDPNeighbor{Port: model.TypedID{Subtype: 5, Raw: []byte("Gi1/1/17")}}, nil, nil).Port
	canonical := MakePortKey(5, []byte("ge1_1_17"))
	if err := r.SetOverrides([]Override{{IdentityKey: "manual:lab", CanonicalKey: canonical, Aliases: []PortKey{alias}, Physical: true, Reason: "paired direct samples"}}); err != nil {
		t.Fatal(err)
	}
	result := r.ResolveLocalPort(1, model.LocalPort{Number: 17, ID: model.TypedID{Subtype: 5, Raw: []byte("ge1_1_17")}}, []model.Interface{{IfIndex: 117, Name: "ge1_1_17", Type: 6}})
	if result.State != PortVerified || !result.Port.Physical || len(result.Issues) != 0 || len(r.Ports().All()) != 1 {
		t.Fatalf("placeholder blocked verified alias: %+v", result)
	}
	if bound, _ := r.Ports().Get(1, alias); bound != result.Port {
		t.Fatal("alias did not resolve to canonical port")
	}
	if _, exists := r.Ports().ByRef(placeholder.Ref); exists {
		t.Fatal("unused placeholder remains in current result")
	}
	// Repeat observation keeps the canonical port stable.
	again := r.ResolveLocalPort(1, model.LocalPort{ID: model.TypedID{Subtype: 5, Raw: []byte("ge1_1_17")}}, []model.Interface{{IfIndex: 117, Name: "ge1_1_17", Type: 6}})
	if again.Port.Ref != result.Port.Ref {
		t.Fatal("canonical identity changed")
	}
}
