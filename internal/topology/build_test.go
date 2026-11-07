package topology

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gonet/internal/identity"
	"gonet/internal/model"
)

var t204Time = time.Unix(1700000000, 0).UTC()

func t204Snap(target string, mac []byte, sysName string, ports []model.LocalPort, ifaces []model.Interface, neighbors []model.LLDPNeighbor) *model.DeviceSnapshot {
	return &model.DeviceSnapshot{
		Device: model.DeviceInfo{
			Target:       netip.MustParseAddr(target),
			Chassis:      model.TypedID{Subtype: 4, Raw: mac},
			SysName:      sysName,
			SysObjectID:  "1.3.6.1.4.1.99999.1.1",
			CapSupported: []byte{0x20},
			CapEnabled:   []byte{0x20},
		},
		LocalPorts:  ports,
		Interfaces:  ifaces,
		Neighbors:   neighbors,
		CollectedAt: t204Time,
	}
}

func t204Port(num uint32, ifName string) model.LocalPort {
	return model.LocalPort{Number: num, ID: model.TypedID{Subtype: 5, Raw: []byte(ifName)}}
}

func t204Iface(idx int32, name string) model.Interface {
	return model.Interface{IfIndex: idx, Name: name, Type: 6}
}

func t204Neighbor(tm, lpn, ri uint32, mac []byte, peerPort string) model.LLDPNeighbor {
	return model.LLDPNeighbor{
		Index:   model.NeighborIndex{TimeMark: tm, LocalPortNum: lpn, RemoteIndex: ri},
		Chassis: model.TypedID{Subtype: 4, Raw: mac},
		Port:    model.TypedID{Subtype: 5, Raw: []byte(peerPort)},
	}
}

func t204WeakNeighbor(tm, lpn, ri uint32, localID, peerPort string) model.LLDPNeighbor {
	return model.LLDPNeighbor{
		Index:   model.NeighborIndex{TimeMark: tm, LocalPortNum: lpn, RemoteIndex: ri},
		Chassis: model.TypedID{Subtype: 7, Raw: []byte(localID)},
		Port:    model.TypedID{Subtype: 5, Raw: []byte(peerPort)},
	}
}

// buildT204Graph constructs a three-device offline graph:
//
//	A(Gi1,Gi3) -- B(Gi2) bidirectional
//	A(Gi3)     -- C(Gi4) bidirectional
//	C also advertises an unresolved weak-chassis neighbor D.
func buildT204Graph(t *testing.T) *Graph {
	t.Helper()
	fixed := func() time.Time { return t204Time }
	reg, err := identity.New(identity.Options{Now: fixed, Rules: []identity.Rule{{ID: "fixture-switch", SysObjectIDPrefix: "1.3.6.1.4.1.99999", Action: "switch"}}})
	if err != nil {
		t.Fatal(err)
	}
	res := NewResolver(NewPortRegistry(fixed))
	b := NewBuilder(reg, res)

	macA := []byte{0, 0, 0, 0, 0, 1}
	macB := []byte{0, 0, 0, 0, 0, 2}
	macC := []byte{0, 0, 0, 0, 0, 3}

	b.AddSnapshot(t204Snap("192.0.2.1", macA, "A",
		[]model.LocalPort{t204Port(1, "Gi1"), t204Port(2, "Gi3")},
		[]model.Interface{t204Iface(101, "Gi1"), t204Iface(102, "Gi3")},
		[]model.LLDPNeighbor{
			t204Neighbor(7, 1, 1, macB, "Gi2"),
			t204Neighbor(7, 2, 1, macC, "Gi4"),
		}))
	b.AddSnapshot(t204Snap("192.0.2.2", macB, "B",
		[]model.LocalPort{t204Port(1, "Gi2")},
		[]model.Interface{t204Iface(201, "Gi2")},
		[]model.LLDPNeighbor{t204Neighbor(7, 1, 1, macA, "Gi1")}))
	b.AddSnapshot(t204Snap("192.0.2.3", macC, "C",
		[]model.LocalPort{t204Port(1, "Gi4")},
		[]model.Interface{t204Iface(301, "Gi4")},
		[]model.LLDPNeighbor{
			t204Neighbor(7, 1, 1, macA, "Gi3"),
			t204WeakNeighbor(7, 1, 2, "d-local", "Gi5"),
		}))
	return b.Build()
}

// T204: multi-snapshot offline construction, bidirectional links, unresolved
// observation preserved, every link traceable to a direction and raw row.
func TestT204MultiSnapshotGraph(t *testing.T) {
	g := buildT204Graph(t)

	if len(g.Devices) != 3 {
		t.Fatalf("devices = %d, want 3", len(g.Devices))
	}
	if len(g.Links) != 2 {
		t.Fatalf("links = %d, want 2 (A-B, A-C)", len(g.Links))
	}
	for _, ev := range g.Links {
		if ev.Confidence() != "bidirectional" {
			t.Errorf("link %+v confidence = %q, want bidirectional", ev.Key, ev.Confidence())
		}
	}
	if len(g.Observations) != 4 {
		t.Errorf("observations = %d, want 4", len(g.Observations))
	}
	if len(g.Unresolved) != 1 {
		t.Fatalf("unresolved = %d, want 1", len(g.Unresolved))
	}
	if g.Unresolved[0].Reason != "remote identity unresolved" {
		t.Errorf("unresolved reason = %q", g.Unresolved[0].Reason)
	}
	if len(g.Unresolved[0].Raw.Port.Raw) == 0 {
		t.Error("unresolved observation lost its raw row")
	}

	// Traceability: each link direction is backed by an observation whose raw
	// row is present, and the direction matches.
	for _, ev := range g.Links {
		var fromA, fromB bool
		for _, obs := range g.Observations {
			k, err := Canonical(obs.Observer, obs.LocalPort, obs.Remote, obs.RemotePort)
			if err != nil || k != ev.Key {
				continue
			}
			if len(obs.Raw.Port.Raw) == 0 || len(obs.Raw.Chassis.Raw) == 0 {
				t.Errorf("observation for %+v lost its raw row", ev.Key)
			}
			if obs.Observer == ev.Key.A {
				fromA = true
			} else {
				fromB = true
			}
		}
		if fromA != ev.SeenFromA || fromB != ev.SeenFromB {
			t.Errorf("link %+v directions A:%v B:%v not traceable (obs A:%v B:%v)",
				ev.Key, ev.SeenFromA, ev.SeenFromB, fromA, fromB)
		}
	}
}

// T204: the graph output is deterministic across independent builds, and it
// does not depend on a database.
func TestT204StableOutput(t *testing.T) {
	g1 := buildT204Graph(t)
	g2 := buildT204Graph(t)

	j1, err := json.MarshalIndent(g1, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	j2, err := json.MarshalIndent(g2, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(j1, j2) {
		t.Fatal("graph JSON is not stable across builds")
	}

	// Check schema_version and that no secret/sample IP leaked.
	if !bytes.Contains(j1, []byte(`"schema_version": 1`)) {
		t.Error("missing schema_version=1")
	}
	if bytes.Contains(j1, []byte("10.201.109")) {
		t.Error("graph contains a sample management IP")
	}

	example := filepath.Join("..", "..", "testdata", "topology.example.json")
	if err := os.MkdirAll(filepath.Dir(example), 0o755); err == nil {
		_ = os.WriteFile(example, append(j1, '\n'), 0o644)
	}
}
