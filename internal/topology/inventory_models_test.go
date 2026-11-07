package topology

import (
	"encoding/json"
	"gonet/internal/identity"
	"gonet/internal/model"
	"os"
	"testing"
)

func TestInventoryModelRulesAndLegacyPhysicalPorts(t *testing.T) {
	data, err := os.ReadFile("../../testdata/adapters/inventory-models/catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		ID          string `json:"id"`
		OID         string `json:"sys_object_id"`
		Description string `json:"description"`
		Legacy      bool   `json:"legacy"`
	}
	if err = json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	rules, err := identity.LoadRules("../../config/device_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	classifier, err := identity.NewClassifier(rules)
	if err != nil {
		t.Fatal(err)
	}
	portRules, err := LoadPortRules("../../config/port_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			got := classifier.Classify(c.OID, c.Description, nil, nil)
			if !got.Switch() {
				t.Fatal("verified product was not recognized")
			}
			if classifier.Classify(c.OID, "unverified firmware", nil, nil).Switch() {
				t.Fatal("generic OID promoted to switch")
			}
			if !c.Legacy {
				return
			}
			r := newTestResolver()
			if err := r.SetRules(portRules); err != nil {
				t.Fatal(err)
			}
			r.SetDeviceRule(1, got.RuleID)
			for i, tc := range []struct {
				Name     string
				Type     int32
				Physical bool
			}{
				{"GigabitEthernet1/0/27", 117, true}, {"GigabitEthernet1/0/28", 117, true},
				{"Bridge-Aggregation1", 161, false}, {"Vlan-interface1", 136, false},
				{"GigabitEthernet1/0/2.100", 117, false}, {"GigabitEthernet1/0/3", 161, false},
			} {
				p := r.ResolveLocalPort(1, model.LocalPort{Number: uint32(i + 1), ID: model.TypedID{Subtype: 5, Raw: []byte(tc.Name)}}, []model.Interface{{IfIndex: int32(i + 1), Name: tc.Name, Type: tc.Type}}).Port
				if p.Physical != tc.Physical || p.IfType != tc.Type {
					t.Fatalf("%s physical=%v type=%d", tc.Name, p.Physical, p.IfType)
				}
			}
			plain := newTestResolver().ResolveLocalPort(1, model.LocalPort{ID: model.TypedID{Subtype: 5, Raw: []byte("GigabitEthernet1/0/27")}}, []model.Interface{{IfIndex: 27, Name: "GigabitEthernet1/0/27", Type: 117}})
			if plain.Port.Physical {
				t.Fatal("legacy rule escaped model scope")
			}
		})
	}
}
