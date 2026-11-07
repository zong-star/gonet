package webui

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"gonet/internal/store/postgres"
)

func TestTopologyV2NeighborsAndCounts(t *testing.T) {
	view := pathChain(22)
	view.LatestScanStatus = "partial"
	view.Evidence = &postgres.TopologyEvidence{
		Links:          map[int64]postgres.PhysicalLinkEvidence{},
		DeviceCoverage: map[int64]postgres.DeviceScanCoverage{1: {Outcome: "success", AbsenceEligible: true}},
	}
	for i := range view.Links {
		view.Links[i].DeviceAID, view.Links[i].DeviceBID = 1, int64(i+2)
	}
	view.Links[1].DeviceBID = 2 // Parallel physical connection.
	stale := view.Links[0]
	stale.ID, stale.DiscoveryState = 50, "stale"
	view.Links = append(view.Links, stale)
	nameA, nameB := "GE1/0/1", "GigabitEthernet1/0/9"
	view.Evidence.Links[1] = postgres.PhysicalLinkEvidence{A: postgres.LinkEndpointEvidence{IfName: &nameA}, B: postgres.LinkEndpointEvidence{IfName: &nameB}}
	_, handler, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: view}})
	get := func(route string) json.RawMessage {
		t.Helper()
		return decodeAPI(t, callAuth(handler, "GET", route, "", nil, headers)).Data
	}
	var out neighborsV2
	if err := json.Unmarshal(get("/api/v1/devices/1/neighbors?schema_version=2"), &out); err != nil {
		t.Fatal(err)
	}
	if out.SchemaVersion != 2 || out.State != "active" || out.Limit != 20 || out.MatchingLinkCount != 21 ||
		out.ReturnedLinkCount != 20 || len(out.Items) != 20 || out.ReturnedUniqueNeighborCount != 19 || !out.Truncated {
		t.Fatalf("neighbor counts: %+v", out)
	}
	if out.DataQuality.Coverage[0].Status != "gap" || out.DataQuality.Coverage[1].Status != "covered" {
		t.Fatalf("independent coverage: %+v", out.DataQuality.Coverage)
	}
	if err := json.Unmarshal(get("/api/v1/devices/2/neighbors?schema_version=2"), &out); err != nil {
		t.Fatal(err)
	}
	if out.Items[0].Local.DeviceID != "2" || out.Items[0].Local.InterfaceName == nil || *out.Items[0].Local.InterfaceName != nameB ||
		out.Items[0].Remote.DeviceID != "1" || out.DataQuality.Coverage[1].Status != "unknown" {
		t.Fatalf("reverse endpoint: %+v", out)
	}
	var detail deviceV2
	if err := json.Unmarshal(get("/api/v1/devices/1?schema_version=2"), &detail); err != nil || detail.AdjacentLinkCount != 22 || detail.CountDefinition.StateFilter != "all" {
		t.Fatalf("detail count: %+v, %v", detail, err)
	}
	var summary summaryV2
	if err := json.Unmarshal(get("/api/v1/topology/summary?schema_version=2&state=active"), &summary); err != nil || summary.LinkCount != 21 ||
		summary.CountDefinitions["link_count"].StateFilter != "active" || summary.CountDefinitions["pending_neighbor_count"].Unit != "pending_neighbor_entry" {
		t.Fatalf("summary count: %+v, %v", summary, err)
	}
	for _, route := range []string{"/api/v1/devices/1", "/api/v1/devices/1/neighbors", "/api/v1/topology/summary"} {
		if strings.Contains(string(get(route)), `"schema_version"`) {
			t.Fatalf("v1 changed: %s", route)
		}
		for _, query := range []string{"schema_version=", "schema_version=5", "schema_version=2&schema_version=2"} {
			if w := callAuth(handler, "GET", route+"?"+query, "", nil, headers); w.Code != 400 || !strings.Contains(w.Body.String(), "INVALID_ARGUMENT") {
				t.Fatalf("%s?%s got %d", route, query, w.Code)
			}
		}
	}
	long := strings.Repeat("口", 1300)
	view.Evidence.Links[1] = postgres.PhysicalLinkEvidence{A: postgres.LinkEndpointEvidence{IfAlias: &long}, B: postgres.LinkEndpointEvidence{IfAlias: &long}}
	view.Evidence.Links[2] = view.Evidence.Links[1]
	response := decodeAPI(t, callAuth(handler, "GET", "/api/v1/devices/1/neighbors?schema_version=2", "", nil, headers))
	if err := json.Unmarshal(response.Data, &out); err != nil || out.ReturnedLinkCount != 1 || out.ReturnedUniqueNeighborCount != 1 ||
		!out.Truncated || !response.Meta.ResponseTruncated || out.DataQuality.Coverage[1].Status != "covered" {
		t.Fatalf("budget/coverage: %+v, %+v, %v", out, response.Meta, err)
	}
}

func TestTopologyV2StaleAndClock(t *testing.T) {
	view := pathChain(2)
	finished := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	view.LatestScanFinishedAt = &finished
	for _, check := range []struct {
		seconds int64
		stale   bool
	}{{259199, false}, {259200, true}, {259201, true}, {260507, true}} {
		quality := topologyQuality(view, finished.Add(time.Duration(check.seconds)*time.Second), defaultTopologyStaleAfter).DataQuality
		if quality.DataAgeSeconds == nil || *quality.DataAgeSeconds != check.seconds || quality.Stale == nil || *quality.Stale != check.stale {
			t.Fatalf("age at %d: %+v", check.seconds, quality)
		}
	}
	quality := topologyQuality(view, finished.Add(-time.Second), defaultTopologyStaleAfter).DataQuality
	if quality.DataAgeSeconds != nil || quality.Stale != nil || len(quality.DiagnosticCodes) != 1 || quality.DiagnosticCodes[0] != "snapshot_time_in_future" {
		t.Fatalf("future timestamp: %+v", quality)
	}
	view.LatestScanFinishedAt = nil
	quality = topologyQuality(view, finished, defaultTopologyStaleAfter).DataQuality
	if quality.DataAgeSeconds != nil || quality.SnapshotAt != nil || quality.Stale != nil {
		t.Fatalf("missing timestamp: %+v", quality)
	}
	if stale, err := parseTopologyStaleAfter("36h"); err != nil || stale != 36*time.Hour {
		t.Fatalf("configured threshold: %v, %v", stale, err)
	}
	for _, input := range []string{"0s", "1.5s", "-1s", "invalid"} {
		if _, err := parseTopologyStaleAfter(input); err == nil {
			t.Fatalf("invalid threshold accepted: %q", input)
		}
	}
}
