package control

import (
	"encoding/json"
	"testing"
	"time"

	"gonet/internal/store/postgres"
)

func TestCurrentGraphFiltersWithoutMutatingHistory(t *testing.T) {
	now := time.Now()
	old, current := int64(31), int64(32)
	v := &View{LatestScanID: current, LatestScanStatus: "partial", LatestScanFinishedAt: &now, CoreIDs: []int64{1},
		Devices: []Device{{ExportDevice: postgres.ExportDevice{ID: 1}}, {ExportDevice: postgres.ExportDevice{ID: 2}}, {ExportDevice: postgres.ExportDevice{ID: 3}}, {ExportDevice: postgres.ExportDevice{ID: 4}, Status: "collected"}, {ExportDevice: postgres.ExportDevice{ID: 5}}},
		Links: []postgres.ExportLink{
			{ID: 249, DeviceAID: 1, DeviceBID: 2, DiscoveryState: "active", LastSeenScanID: &current},
			{ID: 250, DeviceAID: 1, DeviceBID: 2, DiscoveryState: "active", LastSeenScanID: &current},
			{ID: 2308, DeviceAID: 1, DeviceBID: 3, DiscoveryState: "active", LastSeenScanID: &old},
			{ID: 2309, DeviceAID: 1, DeviceBID: 3, DiscoveryState: "stale", LastSeenScanID: &current},
			{ID: 2310, DeviceAID: 1, DeviceBID: 3, DiscoveryState: "suspect_stale", LastSeenScanID: &current},
			{ID: 2311, DeviceAID: 1, DeviceBID: 3, DiscoveryState: "active"},
			{ID: 2312, DeviceAID: 1, DeviceBID: 99, DiscoveryState: "active", LastSeenScanID: &current},
		}}
	before, _ := json.Marshal(v)
	g := CurrentGraphView(v)
	if len(g.Links) != 2 || len(g.Devices) != 3 || g.Devices[2].ID != 4 {
		t.Fatalf("incorrect current projection: %+v", g)
	}
	// Positive LLDP endpoints survive even when one endpoint lacks direct SNMP.
	if g.Devices[1].ID != 2 {
		t.Fatal("current endpoint hidden")
	}
	// A failed attempt can still carry legacy collection_status=collected.
	// Positive current LLDP endpoints survive; isolated failed devices do not.
	v.Evidence = &postgres.TopologyEvidence{DeviceCoverage: map[int64]postgres.DeviceScanCoverage{2: {Outcome: "failed"}, 4: {Outcome: "failed"}}}
	if got := CurrentGraphView(v); len(got.Devices) != 2 {
		t.Fatalf("failed collection shown as a current isolated node: %+v", got.Devices)
	}
	v.Evidence.DeviceCoverage[4] = postgres.DeviceScanCoverage{Outcome: "partial"}
	if got := CurrentGraphView(v); len(got.Devices) != 3 {
		t.Fatal("positive partial collection was hidden")
	}
	v.Evidence = nil
	g.Devices[0].Name = "changed"
	g.Links[0].ID = 999
	after, _ := json.Marshal(v)
	if string(before) != string(after) {
		t.Fatal("mutated original history view")
	}
	for _, test := range []struct {
		name, status string
		id           int64
		finished     bool
	}{
		{"empty", "completed", 33, true}, {"no_scan", "", 0, false}, {"uncommitted", "running", 32, false}, {"missing_finish", "partial", 32, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			v.LatestScanID = test.id
			v.LatestScanStatus = test.status
			v.LatestScanFinishedAt = nil
			if test.finished {
				v.LatestScanFinishedAt = &now
			}
			if got := CurrentGraphView(v); len(got.Links) != 0 {
				t.Fatalf("backfilled old links: %+v", got.Links)
			}
		})
	}
}
