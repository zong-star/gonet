package webui

import (
	"encoding/json"
	"testing"

	"gonet/internal/store/postgres"
)

func TestProjectLinkEndpointEvidence(t *testing.T) {
	index := int32(101)
	name, alias, legacy := "GE1/0/1", "To_G1/0/12", "旧文本"
	trusted, empty := "GigabitEthernet1/0/12", ""
	for _, tc := range []struct {
		name  string
		facts postgres.LinkEndpointEvidence
		want  string
	}{
		{"independent alias", postgres.LinkEndpointEvidence{IfIndex: &index, Name: &legacy, IfName: &name, IfAlias: &alias},
			`{"device_id":"2","interface_name":"GE1/0/1","interface_description":"To_G1/0/12","if_index":101,"interface_name_source":"if_name","if_index_status":"known"}`},
		{"alias alone", postgres.LinkEndpointEvidence{Name: &alias, IfAlias: &alias},
			`{"device_id":"2","interface_name":null,"interface_description":"To_G1/0/12","if_index":null,"interface_name_source":null,"if_index_status":"unknown"}`},
		{"validated LLDP name", postgres.LinkEndpointEvidence{LLDPInterfaceName: &trusted, IfAlias: &empty},
			`{"device_id":"2","interface_name":"GigabitEthernet1/0/12","interface_description":"","if_index":null,"interface_name_source":"lldp_interface_name","if_index_status":"unknown"}`},
		{"legacy text alone", postgres.LinkEndpointEvidence{Name: &legacy},
			`{"device_id":"2","interface_name":null,"interface_description":null,"if_index":null,"interface_name_source":null,"if_index_status":"unknown"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(projectLinkEndpoint(2, tc.facts))
			if err != nil || string(got) != tc.want {
				t.Fatalf("endpoint: %s, %v, want %s", got, err, tc.want)
			}
		})
	}
}
