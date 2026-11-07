package webui

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"gonet/internal/control"
	"gonet/internal/store/postgres"
)

func int32Pointer(value int32) *int32    { return &value }
func stringPointer(value string) *string { return &value }

func TestUplinkV2SinglePathAndMembers(t *testing.T) {
	view := preciseContractView()
	view.CoreIDs = []int64{3}
	_, handler, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: view}})
	get := func(route string) uplinkDataV2 {
		t.Helper()
		var data uplinkDataV2
		if err := json.Unmarshal(decodeAPI(t, callAuth(handler, "GET", route, "", nil, headers)).Data, &data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	route := "/api/v1/devices/1/uplink-path?schema_version=2"
	first := get(route)
	if first.SchemaVersion != 2 || first.PathStatus != "found" || first.Path == nil || !validUplinkPath(first.Path, "1") ||
		first.Path.HopCount != 2 || len(first.Path.Nodes) != 3 || first.Path.Edges[0].Kind != "aggregate" ||
		first.Path.Edges[0].Aggregation.MemberDataStatus != "complete" || len(first.Path.Edges[0].Aggregation.MemberLinks) != 2 ||
		first.Path.Edges[0].From.InterfaceName == nil || *first.Path.Edges[0].From.InterfaceName != "Bridge-Aggregation1" {
		t.Fatalf("single LAG path: %+v", first)
	}
	slices.Reverse(view.Links)
	second := get(route + "&include_unverified=true")
	if !reflect.DeepEqual(first.Path, second.Path) || second.CandidateLinks == nil || len(*second.CandidateLinks) != 1 {
		t.Fatalf("candidate/order changed main path: %+v", second)
	}
	view.CoreIDs = []int64{1}
	reverse := get("/api/v1/devices/3/uplink-path?schema_version=2")
	if !validUplinkPath(reverse.Path, "3") || reverse.Path.Edges[1].From.DeviceID != "2" ||
		reverse.Path.Edges[1].Aggregation.MemberLinks[0].From.DeviceID != "2" || reverse.Path.Edges[1].Aggregation.MemberLinks[0].To.DeviceID != "1" {
		t.Fatalf("reverse LAG path: %+v", reverse)
	}
	zero := get(route)
	if zero.PathStatus != "found" || zero.Path.HopCount != 0 || len(zero.Path.Nodes) != 1 || zero.Path.Nodes[0].Role != "source_core" {
		t.Fatalf("zero hop: %+v", zero)
	}
	view.CoreIDs = []int64{3}
	bounded := get(route + "&max_hops=1")
	if bounded.PathStatus != "not_found" || bounded.Path != nil || bounded.Reason != "no_confirmed_path_within_bound" {
		t.Fatalf("bounded search: %+v", bounded)
	}
	view.Links = nil
	noPath := get(route + "&include_unverified=true")
	if noPath.PathStatus != "not_found" || noPath.Path != nil {
		t.Fatal("candidates supplied a path")
	}
	view.CoreIDs = nil
	if got := get(route); got.Reason != "no_visible_core" || got.Path != nil {
		t.Fatalf("invisible cores: %+v", got)
	}
	for _, query := range []string{"&max_paths=2", "&max_paths=3", "&max_hops=17", "&schema_version=2"} {
		if w := callAuth(handler, "GET", route+query, "", nil, headers); w.Code != 400 {
			t.Fatalf("accepted invalid query %s: %d", query, w.Code)
		}
	}
}

func TestUplinkV2BoundsAndValidation(t *testing.T) {
	view := pathChain(17)
	view.Evidence = &postgres.TopologyEvidence{Links: map[int64]postgres.PhysicalLinkEvidence{}}
	_, handler, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: view}})
	route := "/api/v1/devices/1/uplink-path?schema_version=2"
	w := callAuth(handler, "GET", route, "", nil, headers)
	var data uplinkDataV2
	if err := json.Unmarshal(decodeAPI(t, w).Data, &data); err != nil || data.Path.HopCount != 16 || w.Body.Len() > maxCompactAPIBytes {
		t.Fatalf("16 hops: %d bytes, %v", w.Body.Len(), err)
	}
	t.Logf("16-hop v2 path: %d bytes", w.Body.Len())
	data.Path.Edges[0].To.DeviceID = "broken"
	if validUplinkPath(data.Path, "1") {
		t.Fatal("accepted disconnected path")
	}
	long := strings.Repeat("端", maxCompactAPIBytes)
	view.Evidence.Links[1] = postgres.PhysicalLinkEvidence{A: postgres.LinkEndpointEvidence{IfName: &long}}
	if w := callAuth(handler, "GET", route, "", nil, headers); w.Code != 422 || !strings.Contains(w.Body.String(), "RESULT_TOO_LARGE") {
		t.Fatalf("oversized required path: %d", w.Code)
	}
	view.Evidence.Links = nil
	view.Devices[1].IdentityState = "conflict"
	if body := callAuth(handler, "GET", route, "", nil, headers); !strings.Contains(body.Body.String(), `"path_status":"not_found"`) {
		t.Fatal("conflicted identity entered the path")
	}
	view.Devices = append(view.Devices, control.Device{ExportDevice: postgres.ExportDevice{ID: 99}, Name: "Unreachable"})
	view.CoreIDs = []int64{99}
	view.Links = nil
	for a := int64(1); a <= 12; a++ {
		for b := a + 1; b <= 12; b++ {
			view.Links = append(view.Links, postgres.ExportLink{ID: int64(len(view.Links) + 1), DeviceAID: a, DeviceBID: b,
				DiscoveryState: "active", LastSeenScanID: &view.LatestScanID})
		}
	}
	if w := callAuth(handler, "GET", route, "", nil, headers); w.Code != 422 || !strings.Contains(w.Body.String(), "SEARCH_BUDGET_EXCEEDED") {
		t.Fatalf("budget response %d: %s", w.Code, w.Body.String())
	}
}

func TestUplinkV2StableCoreRanking(t *testing.T) {
	view := pathChain(4)
	view.CoreIDs = []int64{2, 4}
	view.Links = append(view.Links, postgres.ExportLink{ID: 10, DeviceAID: 1, DeviceBID: 4, Confidence: "single_sided", DiscoveryState: "active", LastSeenScanID: &view.LatestScanID})
	_, handler, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: view}})
	for i := 0; i < 3; i++ {
		body := callAuth(handler, "GET", "/api/v1/devices/1/uplink-path?schema_version=2", "", nil, headers)
		if body.Code != 200 || !strings.Contains(body.Body.String(), `"target_core_device_id":"2"`) {
			t.Fatalf("ranking iteration %d: %s", i, body.Body.String())
		}
		slices.Reverse(view.Links)
	}
}

type noConfiguredCoreBackend struct{ *apiBackend }

func (*noConfiguredCoreBackend) Settings() control.Settings { return control.Settings{} }

func TestUplinkV2CandidateStatesAndAggregationCoverage(t *testing.T) {
	view := preciseContractView()
	_, handler, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: view}})
	route := "/api/v1/devices/1/uplink-path?schema_version=2&include_unverified=true"
	get := func() uplinkDataV2 {
		t.Helper()
		var data uplinkDataV2
		if err := json.Unmarshal(decodeAPI(t, callAuth(handler, "GET", route, "", nil, headers)).Data, &data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	facts := view.Evidence.LAG[1]
	facts.Complete = false
	view.Evidence.LAG[1] = facts
	partial := get()
	if partial.Path.Edges[0].Aggregation.MemberDataStatus != "partial" {
		t.Fatal("unproven member total reported complete")
	}
	facts.Members[0].Status = "conflict"
	view.Evidence.LAG[1] = facts
	conflict := get()
	if conflict.Path.Edges[0].Kind != "physical" || conflict.Path.Edges[0].Aggregation != nil {
		t.Fatal("conflicting member formed an aggregate")
	}
	view.CandidateLinks = nil
	empty := get()
	if empty.CandidateLinks == nil || *empty.CandidateLinks == nil || len(*empty.CandidateLinks) != 0 {
		t.Fatalf("queried-empty candidates: %+v", empty)
	}
	view.Evidence = nil
	unavailable := get()
	if unavailable.CandidateLinks != nil || unavailable.CandidateDataReason != "candidate_data_unavailable" {
		t.Fatalf("unavailable candidates: %+v", unavailable)
	}
	if body := callAuth(handler, "GET", route, "", nil, headers); !strings.Contains(body.Body.String(), `"candidate_links":null`) {
		t.Fatal("unavailable candidates were omitted")
	}
	view.CoreIDs = nil
	_, emptyHandler, emptyHeaders := newAPITest(t, &noConfiguredCoreBackend{&apiBackend{countingBackend: countingBackend{view: view}}})
	response := callAuth(emptyHandler, "GET", route, "", nil, emptyHeaders)
	if response.Code != 200 || !strings.Contains(response.Body.String(), `"path_status":"no_core_configured"`) || !strings.Contains(response.Body.String(), `"path":null`) {
		t.Fatalf("no configured core: %s", response.Body.String())
	}
}
