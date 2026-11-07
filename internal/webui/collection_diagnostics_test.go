package webui

import (
	"encoding/json"
	"net/url"
	"slices"
	"strings"
	"testing"

	"gonet/internal/model"
	"gonet/internal/store/postgres"
	"gonet/internal/topology"
)

func TestCollectionCoverageEvidenceAndBranches(t *testing.T) {
	view := pathChain(4)
	view.LatestScanStatus = "partial"
	view.CoreIDs = []int64{3}
	view.Evidence = &postgres.TopologyEvidence{DeviceCoverage: map[int64]postgres.DeviceScanCoverage{}, Collection: &postgres.ScanCollection{ViewVerified: true}}
	for _, id := range []int64{1, 2, 3} {
		view.Evidence.DeviceCoverage[id] = postgres.DeviceScanCoverage{Outcome: "success", AbsenceEligible: true}
	}
	// Device 4 lies beyond the terminal core; its unrelated gap must not poison this query.
	view.Evidence.DeviceCoverage[4] = postgres.DeviceScanCoverage{Outcome: "failed"}
	coverage := deviceCoreCoverage(view, 1, 16, map[int64]bool{3: true})
	if coverage.Status != "covered" || coverage.EvaluatedDeviceCount != 3 || networkCoverage(view).Status != "gap" {
		t.Fatalf("independent query scope: %+v", coverage)
	}
	view.Evidence.DeviceCoverage[2] = postgres.DeviceScanCoverage{Outcome: "success", CollectionComplete: true, SnapshotStable: true}
	coverage = deviceCoreCoverage(view, 1, 16, map[int64]bool{3: true})
	if coverage.Status != "unknown" || !slices.Contains(coverage.ReasonCodes, "absence_evidence_unverified") || !slices.Contains(coverage.AffectedDeviceIDs, "2") {
		t.Fatalf("transit evidence ignored: %+v", coverage)
	}
	view.Evidence.DeviceCoverage[2] = postgres.DeviceScanCoverage{Outcome: "partial", Components: map[string]model.ComponentStatus{"lldp_rem": {Supported: true, WalkComplete: false, DecodeComplete: true}}}
	coverage = deviceCoreCoverage(view, 1, 16, map[int64]bool{3: true})
	if coverage.Status != "gap" || !slices.Contains(coverage.ReasonCodes, "lldp_rem_incomplete") {
		t.Fatalf("missing component: %+v", coverage)
	}
	// A shorter query does not inspect a branch outside the hop bound.
	coverage = deviceCoreCoverage(view, 1, 1, map[int64]bool{3: true})
	if coverage.EvaluatedDeviceCount != 2 {
		t.Fatalf("bound ignored: %+v", coverage)
	}
	view.Evidence.DeviceCoverage[2] = postgres.DeviceScanCoverage{Outcome: "success", AbsenceEligible: true}
	view.CandidateLinks = []topology.PendingLink{{LocalDevice: 2, RemoteKey: "unresolved"}}
	if coverage = deviceCoreCoverage(view, 1, 16, map[int64]bool{3: true}); coverage.Status != "gap" || !slices.Contains(coverage.ReasonCodes, "unresolved_observations") {
		t.Fatalf("unresolved branch ignored: %+v", coverage)
	}
	view.CandidateLinks = nil
	old := view.LatestScanID - 1
	view.Links[0].LastSeenScanID = &old
	if coverage = deviceCoreCoverage(view, 1, 16, map[int64]bool{3: true}); coverage.Status != "gap" || !slices.Contains(coverage.ReasonCodes, "branch_link_not_observed_in_snapshot") {
		t.Fatalf("historical edge accepted: %+v", coverage)
	}
	if coverage = deviceNeighborCoverage(view, 4, "active"); coverage.Status != "gap" || !slices.Contains(coverage.ReasonCodes, "device_collection_failed") {
		t.Fatal(coverage)
	}
	if coverage = deviceNeighborCoverage(view, 99, "active"); coverage.Status != "unknown" || !slices.Contains(coverage.ReasonCodes, "device_not_recorded_in_snapshot") {
		t.Fatal(coverage)
	}
}

func TestCollectionReportPagingAuthAndSnapshot(t *testing.T) {
	view := pathChain(4)
	view.Evidence = &postgres.TopologyEvidence{DeviceCoverage: map[int64]postgres.DeviceScanCoverage{
		1: {Outcome: "success", CollectionComplete: true, SnapshotStable: true},
		2: {Outcome: "partial", Components: map[string]model.ComponentStatus{"lldp_rem": {}}},
		3: {Outcome: "failed", Issues: []model.Issue{{Code: "TIMEOUT", Message: "secret raw error"}}},
	}, Collection: &postgres.ScanCollection{Counts: map[string]int{"devices_collected": 2, "devices_failed": 1}, Issues: []model.Issue{{Code: "TIMEOUT", Message: "secret raw error"}}, TerminationReasons: []string{"errors_retained"}}}
	_, handler, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: view}})
	base := "/api/v1/topology/collection?schema_version=2&limit=1"
	if response := callAuth(handler, "GET", base, "", nil, nil); response.Code != 401 {
		t.Fatal("anonymous collection allowed")
	}
	var page struct {
		DataQuality dataQualityV2    `json:"data_quality"`
		Items       []collectionItem `json:"items"`
		Total       int              `json:"total"`
		NextCursor  *string          `json:"next_cursor"`
	}
	keys := map[string]bool{}
	route := base
	for {
		response := callAuth(handler, "GET", route, "", nil, headers)
		if response.Body.Len() > maxCompactAPIBytes || strings.Contains(response.Body.String(), "secret raw error") {
			t.Fatal("budget or raw diagnostic leaked")
		}
		if err := json.Unmarshal(decodeAPI(t, response).Data, &page); err != nil {
			t.Fatal(err)
		}
		if page.Total != 4 || len(page.Items) != 1 || page.DataQuality.Collection == nil || page.DataQuality.Collection.RecordedOutcomes["not_recorded"] != 1 {
			t.Fatalf("report: %+v", page)
		}
		if keys[page.Items[0].Key] {
			t.Fatal("duplicate page")
		}
		keys[page.Items[0].Key] = true
		if page.NextCursor == nil {
			break
		}
		route = base + "&cursor=" + url.QueryEscape(*page.NextCursor)
	}
	if len(keys) != 4 {
		t.Fatal("incomplete pagination")
	}
	if response := callAuth(handler, "GET", base+"&snapshot_id=99999", "", nil, headers); response.Code != 409 {
		t.Fatal("snapshot mismatch accepted")
	}
	first := callAuth(handler, "GET", base, "", nil, headers)
	json.Unmarshal(decodeAPI(t, first).Data, &page)
	cursor := *page.NextCursor
	view.LatestScanID++
	if response := callAuth(handler, "GET", base+"&cursor="+url.QueryEscape(cursor), "", nil, headers); response.Code != 409 {
		t.Fatal("stale cursor accepted")
	}
	if response := callAuth(handler, "GET", base+"&device_id=2", "", nil, headers); response.Code != 200 || !strings.Contains(response.Body.String(), "lldp_rem") {
		t.Fatal("device diagnostics missing")
	}
	for _, query := range []string{"limit=0", "schema_version=4", "limit=1&limit=2", "unknown=true"} {
		if response := callAuth(handler, "GET", "/api/v1/topology/collection?"+query, "", nil, headers); response.Code != 400 {
			t.Fatalf("accepted %s: %d", query, response.Code)
		}
	}
}
