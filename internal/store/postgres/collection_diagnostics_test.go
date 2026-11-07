package postgres

import (
	"context"
	"net/netip"
	"testing"

	"gonet/internal/discovery"
	"gonet/internal/model"
)

func TestCollectionDiagnosticsCommittedSnapshot(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()
	r := sampleResult()
	r.Status = "partial"
	r.Outcomes[1] = model.ScanOutcome{Device: 2, Outcome: "failed", Target: model.DiscoveryTarget{Address: netip.MustParseAddr("192.0.2.2"), Depth: 1}, Issues: []model.Issue{{Code: "TIMEOUT", Component: "collect"}}}
	r.Counts = discovery.Counts{DevicesCollected: 1, DevicesFailed: 1}
	r.Issues = []model.Issue{{Code: "TIMEOUT", Component: "collect"}}
	r.Termination = "errors_retained"
	r.CollectionTargets = []discovery.CollectionTarget{{Device: 2, Address: "192.0.2.2", Status: "failed", ReasonCode: "TIMEOUT"}, {Address: "192.0.2.9", Status: "failed", ReasonCode: "TIMEOUT"}}
	commitRound(t, s, r)
	exp, err := ExportTopologyWithEvidence(ctx, s.Conn(), "all")
	if err != nil {
		t.Fatal(err)
	}
	if exp.Evidence.Collection == nil || exp.Evidence.Collection.Counts["devices_failed"] != 1 || len(exp.Evidence.Collection.Targets) != 2 {
		t.Fatalf("run diagnostics lost: %+v", exp.Evidence.Collection)
	}
	var failedID int64
	for _, device := range exp.Devices {
		if device.SysName == "B" {
			failedID = device.ID
			if device.DiscoveryDepth != nil {
				t.Fatal("failed attempt marked collected")
			}
		}
	}
	coverage := exp.Evidence.DeviceCoverage[failedID]
	if coverage.Outcome != "failed" || coverage.TargetIP != "192.0.2.2" || len(coverage.Issues) != 1 || coverage.Issues[0].Code != "TIMEOUT" || coverage.AbsenceEligible {
		t.Fatalf("device diagnostics lost: %+v", coverage)
	}
	if exp.Evidence.Collection.Targets[0].DeviceID != failedID {
		t.Fatal("temporary reference leaked")
	}
	// A new running scan must not replace the committed snapshot diagnostics.
	running, err := s.BeginScan(ctx, ScanInput{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.1")}})
	if err != nil {
		t.Fatal(err)
	}
	exp2, err := ExportTopologyWithEvidence(ctx, s.Conn(), "all")
	if err != nil {
		t.Fatal(err)
	}
	if exp2.LatestScanID != exp.LatestScanID || exp2.Evidence.LatestScan.ID != running || exp2.Evidence.Collection.Counts["devices_failed"] != 1 {
		t.Fatal("running scan mixed with snapshot")
	}
}
