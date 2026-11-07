package webui

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"gonet/internal/control"
	"gonet/internal/model"
	"gonet/internal/store/postgres"
	"gonet/internal/topology"
)

func TestUplinkPathRouteAndBatch(t *testing.T) {
	view := pathChain(3)
	view.LatestScanStatus = "partial"
	view.CoreIDs = []int64{1, 999}
	oldScan := view.LatestScanID - 1
	view.Links = append(view.Links, postgres.ExportLink{ID: 8, DeviceAID: 1, DeviceBID: 3, LastSeenScanID: &oldScan, DiscoveryState: "active"})
	view.Links = append(view.Links, postgres.ExportLink{ID: 9, DeviceAID: 1, DeviceBID: 999, LastSeenScanID: &view.LatestScanID, DiscoveryState: "active"})
	view.CandidateLinks = []topology.PendingLink{
		{LocalDevice: 3, LocalPortNum: 10, ObservationID: 1, OriginalPort: &model.TypedID{Subtype: 7, Raw: []byte("raw-port")}},
		{LocalDevice: 3, RemoteDevice: 999, ObservationID: 2},
		{LocalDevice: 2, ObservationID: 3},
	}
	b := &apiBackend{countingBackend: countingBackend{view: view}}
	_, handler, headers := newAPITest(t, b)
	path := "/api/v1/devices/3/uplink-path"
	for _, suffix := range []string{"?max_paths=4", "?max_hops=17", "?include_unverified=1", "?target=switch", "?state=active", "?target=core&target=core"} {
		if w := callAuth(handler, "GET", path+suffix, "", nil, headers); w.Code != 400 {
			t.Fatalf("%s got %d", suffix, w.Code)
		}
	}
	if b.reads.Load() != 0 {
		t.Fatal("invalid path query hit the backend")
	}
	if w := callAuth(handler, "GET", "/api/v1/devices/999/uplink-path", "", nil, headers); w.Code != 404 {
		t.Fatal("invisible device exposed")
	}
	resp := decodeAPI(t, callAuth(handler, "GET", path+"?include_unverified=true", "", nil, headers))
	got := decodePathData(t, resp.Data)
	if !resp.Meta.CoverageGap || resp.Meta.SearchTruncated == nil || *resp.Meta.SearchTruncated ||
		!got.PathFound || len(got.Paths) != 1 || got.Paths[0].HopCount != 2 {
		t.Fatalf("path: %s", resp.Data)
	}
	first := got.Paths[0].Links[0]
	if first.EndpointA.DeviceID != "3" || first.EndpointB.DeviceID != "2" || first.MemberLinks[0].AInterface != view.Links[1].PortBName ||
		got.Paths[0].Nodes[2].Role != "core" || got.CandidateLinks == nil || len(*got.CandidateLinks) != 2 ||
		string((*got.CandidateLinks)[1].RemotePortID.Raw) != "raw-port" {
		t.Fatalf("direction or candidates: %s", resp.Data)
	}
	got = decodePathData(t, decodeAPI(t, callAuth(handler, "GET", path+"?max_hops=1&include_unverified=true", "", nil, headers)).Data)
	if got.PathFound || got.Reason != "no_confirmed_path_to_core" || len(*got.CandidateLinks) != 1 {
		t.Fatalf("unexpected bounded result: %+v", got)
	}
	got = decodePathData(t, decodeAPI(t, callAuth(handler, "GET", "/api/v1/devices/1/uplink-path", "", nil, headers)).Data)
	if !got.PathFound || len(got.Paths) != 1 || got.Paths[0].HopCount != 0 || got.CandidateLinks != nil {
		t.Fatalf("zero-hop: %+v", got)
	}
	view.CoreIDs = []int64{999}
	got = decodePathData(t, decodeAPI(t, callAuth(handler, "GET", path, "", nil, headers)).Data)
	if got.Reason != "no_visible_core" {
		t.Fatalf("no visible core: %+v", got)
	}
	view.LatestScanID = 0
	got = decodePathData(t, decodeAPI(t, callAuth(handler, "GET", path, "", nil, headers)).Data)
	if got.Reason != "no_scan_data" {
		t.Fatalf("empty scan: %+v", got)
	}
}

func TestUplinkPathResponseSize(t *testing.T) {
	view := pathChain(17)
	_, handler, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: view}})
	route := "/api/v1/devices/1/uplink-path"
	w := callAuth(handler, "GET", route, "", nil, headers)
	if w.Code != 200 {
		t.Fatalf("16-hop path status=%d body=%s", w.Code, w.Body.String())
	}
	got := decodePathData(t, decodeAPI(t, w).Data)
	if len(got.Paths) != 1 || got.Paths[0].HopCount != 16 || w.Body.Len() > maxCompactAPIBytes {
		t.Fatalf("16-hop response: paths=%d bytes=%d", len(got.Paths), w.Body.Len())
	}
	t.Logf("16-hop physical response: %d bytes", w.Body.Len())
	parallel := view.Links[0]
	parallel.ID = 100
	view.Links = append(view.Links, parallel)
	w = callAuth(handler, "GET", route, "", nil, headers)
	resp := decodeAPI(t, w)
	got = decodePathData(t, resp.Data)
	if !resp.Meta.ResponseTruncated || len(got.Paths) != 1 || len(got.Paths[0].Links) != 16 || w.Body.Len() > maxCompactAPIBytes {
		t.Fatalf("path should trim complete paths: %d bytes, %+v", w.Body.Len(), resp.Meta)
	}
	view.Links[0].PortAName = strings.Repeat("口", 5000)
	view.Links[len(view.Links)-1].PortAName = view.Links[0].PortAName
	if w := callAuth(handler, "GET", route, "", nil, headers); w.Code != 422 {
		t.Fatalf("oversized first path status=%d", w.Code)
	}
}

func TestUplinkPathLAGMembers(t *testing.T) {
	view := pathChain(2)
	view.CoreIDs = []int64{1}
	view.Evidence = &postgres.TopologyEvidence{
		Links: map[int64]postgres.PhysicalLinkEvidence{},
		LAG:   map[int64]postgres.DeviceLAGEvidence{1: {Complete: true}, 2: {Complete: true}},
	}
	template := view.Links[0]
	view.Links = nil
	for id := int64(1); id <= 8; id++ {
		link := template
		link.ID, link.PortAID, link.PortBID = id, 10+id, 20+id
		link.PortAName, link.PortBName = fmt.Sprintf("Ten-GigabitEthernet1/0/%d", 10+id), fmt.Sprintf("Ten-GigabitEthernet1/0/%d", 20+id)
		a, b := int32(10+id), int32(20+id)
		view.Links = append(view.Links, link)
		view.Evidence.Links[id] = postgres.PhysicalLinkEvidence{A: postgres.LinkEndpointEvidence{IfIndex: &a}, B: postgres.LinkEndpointEvidence{IfIndex: &b}}
		for dev, index := range map[int64]int32{1: a, 2: b} {
			facts := view.Evidence.LAG[dev]
			facts.Members = append(facts.Members, postgres.LAGMemberEvidence{LAGMember: model.LAGMember{
				AggregateIfIndex: int32(100 + dev), MemberIfIndex: index, Status: "confirmed", Mode: "lacp",
			}, AggregateName: fmt.Sprintf("Bridge-Aggregation%d", dev)})
			view.Evidence.LAG[dev] = facts
		}
	}
	_, handler, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: view}})
	w := callAuth(handler, "GET", "/api/v1/devices/2/uplink-path", "", nil, headers)
	got := decodePathData(t, decodeAPI(t, w).Data)
	if len(got.Paths) != 1 || got.Paths[0].HopCount != 1 {
		t.Fatalf("LAG not folded: %+v", got)
	}
	hop := got.Paths[0].Links[0]
	if hop.ConnectionType != "lag" || hop.LAGMode != "lacp" || hop.MemberCoverage != "complete" ||
		hop.EndpointA.LogicalInterface.Name != "Bridge-Aggregation2" || len(hop.MemberLinks) != 8 ||
		hop.MemberLinks[0].AIfIndex == nil || *hop.MemberLinks[0].AIfIndex != 21 ||
		hop.MemberLinks[0].BIfIndex == nil || *hop.MemberLinks[0].BIfIndex != 11 {
		t.Fatalf("LAG direction or evidence: %+v", hop)
	}
	t.Logf("one LAG hop with eight members: %d bytes", w.Body.Len())
	w = callAuth(handler, "GET", "/api/v1/devices/2/uplink-path?schema_version=2", "", nil, headers)
	var v2 uplinkDataV2
	if err := json.Unmarshal(decodeAPI(t, w).Data, &v2); err != nil || v2.Path == nil || v2.Path.HopCount != 1 ||
		v2.Path.Edges[0].Aggregation == nil || len(v2.Path.Edges[0].Aggregation.MemberLinks) != 8 ||
		v2.Path.Edges[0].Aggregation.MemberLinks[0].From.IfIndex == nil || *v2.Path.Edges[0].Aggregation.MemberLinks[0].From.IfIndex != 21 {
		t.Fatalf("v2 eight-member aggregate: %+v, %v", v2, err)
	}
	t.Logf("v2 one LAG hop with eight members: %d bytes", w.Body.Len())
}

func pathChain(nodes int) *control.View {
	view := &control.View{LatestScanID: 30, LatestScanStatus: "completed", Fresh: true, CoreIDs: []int64{int64(nodes)}}
	at := time.Date(2026, 11, 4, 5, 0, 0, 0, time.UTC)
	for i := int64(1); i <= int64(nodes); i++ {
		view.Devices = append(view.Devices, control.Device{
			ExportDevice: postgres.ExportDevice{ID: i, Kind: "switch", AccessAddresses: []string{fmt.Sprintf("192.0.2.%d", i)}},
			Name:         fmt.Sprintf("Building-Access-Switch-%02d", i),
		})
		if i < int64(nodes) {
			view.Links = append(view.Links, postgres.ExportLink{ID: i, DeviceAID: i, DeviceBID: i + 1, PortAID: 2 * i, PortBID: 2*i + 1,
				PortAName: "Ten-GigabitEthernet1/0/27", PortBName: "Ten-GigabitEthernet1/0/3", Confidence: "bidirectional",
				DiscoveryState: "active", LastSeenScanID: &view.LatestScanID, FirstSeenAt: at, LastSeenAt: at})
		}
	}
	return view
}

func decodePathData(t *testing.T, raw json.RawMessage) corePathData {
	t.Helper()
	var got corePathData
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	return got
}
