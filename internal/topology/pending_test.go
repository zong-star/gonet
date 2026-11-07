package topology

import (
	"gonet/internal/model"
	"testing"
)

func TestPendingStatesAndNameIndependentKeys(t *testing.T) {
	rows := []UnresolvedObservation{}
	for i, reason := range []string{"remote identity unresolved; no access address", "remote port unresolved", "identity conflict: duplicate owners"} {
		rows = append(rows, UnresolvedObservation{Observer: 1, Row: model.NeighborIndex{LocalPortNum: uint32(i + 1)}, Raw: model.LLDPNeighbor{Chassis: model.TypedID{Subtype: 7, Raw: []byte([]string{"02:00:00:00:00:11", "02:00:00:00:00:22", "02:00:00:00:00:33"}[i])}, Port: model.TypedID{Subtype: 5, Raw: []byte("Gi1")}, SysName: "same-name"}, Reason: reason})
	}
	nodes, links := PendingProjection(rows, map[string]uint64{"lldp:7:020000000022": 9})
	if len(nodes) != 2 || len(links) != 3 || links[0].Status != "neighbor_unknown" || links[1].Status != "port_match_failed" || links[1].RemoteDevice != 9 || links[2].Status != "identity_conflict" {
		t.Fatalf("pending states lost: %+v %+v", nodes, links)
	}
	old := nodes[0].Key
	rows[0].Raw.SysName = "renamed"
	again, _ := PendingProjection(rows, map[string]uint64{"lldp:7:020000000022": 9})
	if again[0].Key != old {
		t.Fatal("pending identity depended on system name")
	}
}

func TestWeakPendingChassisIsScopedToObservation(t *testing.T) {
	n := model.LLDPNeighbor{Chassis: model.TypedID{Subtype: 7, Raw: []byte("duplicate-host")}, SysName: "same-name"}
	rows := []UnresolvedObservation{{Observer: 1, Row: model.NeighborIndex{LocalPortNum: 1, RemoteIndex: 1}, Raw: n}, {Observer: 2, Row: model.NeighborIndex{LocalPortNum: 1, RemoteIndex: 1}, Raw: n}}
	nodes, links := PendingProjection(rows, nil)
	if len(nodes) != 2 || len(links) != 2 || nodes[0].Key == nodes[1].Key {
		t.Fatal("opaque local chassis values were globally merged")
	}
}
