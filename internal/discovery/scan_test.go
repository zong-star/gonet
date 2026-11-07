package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"gonet/internal/model"
)

func nbCaps(tm, lpn, ri uint32, mac []byte, peerPort string, peerIP netip.Addr, caps []byte) model.LLDPNeighbor {
	n := nb(tm, lpn, ri, mac, peerPort, peerIP)
	n.CapSupported = caps
	n.CapEnabled = caps
	return n
}

// fourSwitchTopology models Core/AggA/AggB/Access with the five physical links
// from the acceptance spec, plus an excluded AP and telephone on Access.
func fourSwitchTopology(t *testing.T) map[netip.Addr]*model.DeviceSnapshot {
	core := mustAddr(t, "192.0.2.1")
	agga := mustAddr(t, "192.0.2.2")
	aggb := mustAddr(t, "192.0.2.3")
	access := mustAddr(t, "192.0.2.4")
	ap := mustAddr(t, "192.0.2.201")
	phone := mustAddr(t, "192.0.2.202")

	macCore := []byte{0, 0, 0, 0, 0, 1}
	macAggA := []byte{0, 0, 0, 0, 0, 2}
	macAggB := []byte{0, 0, 0, 0, 0, 3}
	macAccess := []byte{0, 0, 0, 0, 0, 4}
	macAP := []byte{0, 0, 0, 0, 0, 0xa1}
	macPhone := []byte{0, 0, 0, 0, 0, 0xa2}

	bridge := []byte{0x20}
	apCaps := []byte{0x10}
	phoneCaps := []byte{0x04}

	return map[netip.Addr]*model.DeviceSnapshot{
		core: devSnap(core, macCore, "core-sw1",
			[]model.LocalPort{lp(1, "P1"), lp(2, "P2"), lp(3, "P3")},
			[]model.Interface{ifc(101, "P1"), ifc(102, "P2"), ifc(103, "P3")},
			[]model.LLDPNeighbor{
				nbCaps(7, 1, 1, macAggA, "P1", agga, bridge),
				nbCaps(7, 2, 1, macAggA, "P2", agga, bridge),
				nbCaps(7, 3, 1, macAggB, "P1", aggb, bridge),
			}),
		agga: devSnap(agga, macAggA, "agg-a",
			[]model.LocalPort{lp(1, "P1"), lp(2, "P2"), lp(3, "P3")},
			[]model.Interface{ifc(201, "P1"), ifc(202, "P2"), ifc(203, "P3")},
			[]model.LLDPNeighbor{
				nbCaps(7, 1, 1, macCore, "P1", core, bridge),
				nbCaps(7, 2, 1, macCore, "P2", core, bridge),
				nbCaps(7, 3, 1, macAccess, "P1", access, bridge),
			}),
		aggb: devSnap(aggb, macAggB, "agg-b",
			[]model.LocalPort{lp(1, "P1"), lp(2, "P2")},
			[]model.Interface{ifc(301, "P1"), ifc(302, "P2")},
			[]model.LLDPNeighbor{
				nbCaps(7, 1, 1, macCore, "P3", core, bridge),
				nbCaps(7, 2, 1, macAccess, "P2", access, bridge),
			}),
		access: devSnap(access, macAccess, "access-sw1",
			[]model.LocalPort{lp(1, "P1"), lp(2, "P2"), lp(3, "P3"), lp(4, "P4")},
			[]model.Interface{ifc(401, "P1"), ifc(402, "P2"), ifc(403, "P3"), ifc(404, "P4")},
			[]model.LLDPNeighbor{
				nbCaps(7, 1, 1, macAggA, "P3", agga, bridge),
				nbCaps(7, 2, 1, macAggB, "P2", aggb, bridge),
				nbCaps(7, 3, 1, macAP, "P1", ap, apCaps),
				nbCaps(7, 4, 1, macPhone, "P1", phone, phoneCaps),
			}),
	}
}

func runFourSwitch(t *testing.T) (*Coordinator, *fakeCollector, *Result) {
	t.Helper()
	fc := newFakeCollector(fourSwitchTopology(t))
	coord := newCoord(t, fc, Options{
		Seeds:                 []netip.Addr{mustAddr(t, "192.0.2.1")},
		ManagementCIDRs:       []netip.Prefix{mustPrefix(t, "192.0.2.0/24")},
		MaxDepth:              8,
		MaxDevices:            200,
		MaxTargets:            600,
		MaxAddressesPerDevice: 3,
	})
	return coord, fc, coord.Run(context.Background())
}

// T303: the simulated four-switch topology yields exactly 4 formal switches and
// 5 physical links; excluded AP/telephone neighbors stay out of the graph and
// are counted separately from unknown neighbors.
func TestT303FourSwitchTopology(t *testing.T) {
	_, _, out := runFourSwitch(t)

	if out.Status != "completed" {
		t.Fatalf("status = %q, want completed; issues=%+v", out.Status, out.Issues)
	}
	if len(out.Devices) != 4 {
		t.Fatalf("devices = %d, want 4", len(out.Devices))
	}
	if len(out.Links) != 5 {
		t.Fatalf("links = %d, want 5", len(out.Links))
	}
	for _, ev := range out.Links {
		if ev.Confidence() != "bidirectional" {
			t.Errorf("link %+v confidence = %q, want bidirectional", ev.Key, ev.Confidence())
		}
	}
	if out.Counts.ExcludedNeighbors != 2 {
		t.Errorf("excluded_neighbors = %d, want 2", out.Counts.ExcludedNeighbors)
	}
	if out.Counts.UnknownNeighbors != 0 {
		t.Errorf("unknown_neighbors = %d, want 0", out.Counts.UnknownNeighbors)
	}
	if out.Counts.DevicesCollected != 4 {
		t.Errorf("devices_collected = %d, want 4", out.Counts.DevicesCollected)
	}
	if out.Counts.LinksObserved != 5 {
		t.Errorf("links_observed = %d, want 5", out.Counts.LinksObserved)
	}

	// No excluded terminal/AP may appear as a formal device.
	for _, d := range out.Devices {
		if !d.Classification.Switch() {
			t.Errorf("non-switch device in formal graph: %+v", d)
		}
	}

	// The five expected links, by sysName pair.
	want := map[string]int{
		"agg-a|core-sw1":   2,
		"agg-b|core-sw1":   1,
		"access-sw1|agg-a": 1,
		"access-sw1|agg-b": 1,
	}
	nameByRef := map[model.DevRef]string{}
	for _, d := range out.Devices {
		nameByRef[d.Ref] = d.SysName
	}
	got := map[string]int{}
	for _, ev := range out.Links {
		a, b := nameByRef[ev.Key.A], nameByRef[ev.Key.B]
		if a > b {
			a, b = b, a
		}
		got[a+"|"+b]++
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("link %s = %d, want %d (all=%v)", k, got[k], v, got)
		}
	}

	// Excluded candidates are recorded separately and never collected.
	if len(out.Candidates) < 2 {
		t.Errorf("candidates = %d, want >=2 excluded rows", len(out.Candidates))
	}
}

// T303: the scan JSON is stable across independent runs and contains no DB
// state. It is written as the acceptance example.
func TestT303StableScanJSON(t *testing.T) {
	_, _, out1 := runFourSwitch(t)
	_, _, out2 := runFourSwitch(t)

	j1, err := json.MarshalIndent(out1, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	j2, err := json.MarshalIndent(out2, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(j1, j2) {
		t.Fatal("scan JSON is not stable across runs")
	}
	if !bytes.Contains(j1, []byte(`"status": "completed"`)) {
		t.Error("missing completed status")
	}
	if bytes.Contains(j1, []byte("10.201.109")) {
		t.Error("scan JSON contains a sample management IP")
	}

	example := filepath.Join("..", "..", "testdata", "scan.example.json")
	if err := os.MkdirAll(filepath.Dir(example), 0o755); err == nil {
		_ = os.WriteFile(example, append(j1, '\n'), 0o644)
	}
}
