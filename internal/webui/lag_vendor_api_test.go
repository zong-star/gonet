package webui

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gonet/internal/control"
	"gonet/internal/model"
	"gonet/internal/store/postgres"
)

// Captured device-local indices and member pairings; the scan and graph are
// deliberately synthetic. No network or database is contacted by these tests.
func vendorLAGView() *control.View {
	v := &control.View{LatestScanID: 1001, CoreIDs: []int64{1}, LatestScanStatus: "partial", Evidence: &postgres.TopologyEvidence{Links: map[int64]postgres.PhysicalLinkEvidence{}, LAG: map[int64]postgres.DeviceLAGEvidence{}}}
	for _, id := range []int64{1, 74, 77, 84} {
		v.Devices = append(v.Devices, control.Device{ExportDevice: postgres.ExportDevice{ID: id, IdentityState: "verified"}, Name: fmt.Sprint(id)})
	}
	for _, p := range []struct {
		id, a, b int64
		ai, bi   int32
		an, bn   string
	}{{65, 74, 77, 23, 16, "GigabitEthernet1/0/23", "GigabitEthernet0/0/11"}, {66, 74, 77, 24, 17, "GigabitEthernet1/0/24", "GigabitEthernet0/0/12"}, {240, 1, 74, 78, 27, "ge1_1_29", "Ten-GigabitEthernet1/0/27"}, {253, 1, 74, 113, 28, "ge2_1_29", "Ten-GigabitEthernet1/0/28"}, {417, 77, 84, 14, 9, "GigabitEthernet0/0/9", "GigabitEthernet1/0/9"}} {
		v.Links = append(v.Links, postgres.ExportLink{ID: p.id, DeviceAID: p.a, DeviceBID: p.b, DiscoveryState: "active", Confidence: "bidirectional", LastSeenScanID: &v.LatestScanID})
		a, b, an, bn := p.ai, p.bi, p.an, p.bn
		v.Evidence.Links[p.id] = postgres.PhysicalLinkEvidence{A: postgres.LinkEndpointEvidence{IfIndex: &a, IfName: &an}, B: postgres.LinkEndpointEvidence{IfIndex: &b, IfName: &bn}}
	}
	for _, p := range []struct {
		device             int64
		agg, member        int32
		name, source, mode string
	}{{74, 637, 23, "Bridge-Aggregation2", "ieee_lag", "static"}, {74, 637, 24, "Bridge-Aggregation2", "ieee_lag", "static"}, {74, 639, 27, "Bridge-Aggregation1", "ieee_lag", "static"}, {74, 639, 28, "Bridge-Aggregation1", "ieee_lag", "static"}, {77, 19, 16, "Eth-Trunk1", "huawei_private", "unknown"}, {77, 19, 17, "Eth-Trunk1", "huawei_private", "unknown"}} {
		x, n := p.agg, p.name
		r := v.Evidence.LAG[p.device]
		r.Members = append(r.Members, postgres.LAGMemberEvidence{LAGMember: model.LAGMember{AggregateIfIndex: p.agg, MemberIfIndex: p.member, Source: p.source, Mode: p.mode, Status: "confirmed"}, Endpoint: postgres.LinkEndpointEvidence{IfIndex: &x, IfName: &n}})
		v.Evidence.LAG[p.device] = r
	}
	return v
}

func TestLAGV3ContractSamples(t *testing.T) {
	output := os.Getenv("GONET_LAG_ACCEPTANCE_OUTPUT")
	if output == "" {
		t.Skip("contract output not requested")
	}
	v := vendorLAGView()
	_, h, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: v}})
	var samples []map[string]any
	for _, route := range []string{"/api/v1/devices/84/uplink-path?schema_version=3", "/api/v1/devices/84/uplink-path?schema_version=2", "/api/v1/devices/77/neighbors?schema_version=3", "/api/v1/devices/74/neighbors?schema_version=2&neighbor_device_id=77"} {
		w := callAuth(h, "GET", route, "", nil, headers)
		if w.Code != 200 {
			t.Fatalf("capture %d %s", w.Code, w.Body.String())
		}
		samples = append(samples, map[string]any{"path": route, "status": w.Code, "body": json.RawMessage(w.Body.Bytes())})
	}
	if err := os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(samples, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(output, "http-samples.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
}
func TestVendorLAGV3PathAndPartialMembers(t *testing.T) {
	v := vendorLAGView()
	_, h, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: v}})
	get := func(route string) uplinkDataV2 {
		t.Helper()
		w := callAuth(h, "GET", route, "", nil, headers)
		if w.Code != 200 {
			t.Fatalf("HTTP %d %s", w.Code, w.Body.String())
		}
		var out uplinkDataV2
		if err := json.Unmarshal(decodeAPI(t, w).Data, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	p := get("/api/v1/devices/84/uplink-path?schema_version=3")
	if p.SchemaVersion != 3 || p.Path.HopCount != 3 {
		t.Fatalf("path %+v", p)
	}
	unknown, aggregate, partial := p.Path.Edges[0], p.Path.Edges[1], p.Path.Edges[2]
	if unknown.LinkID == nil || *unknown.LinkID != "417" || unknown.Aggregation.Status != "unknown" || unknown.Aggregation.MemberLinks != nil {
		t.Fatal("single uplink was invented or unknown lost")
	}
	if aggregate.Kind != "aggregate" || aggregate.Aggregation.Status != "confirmed" || len(aggregate.Aggregation.MemberLinks) != 2 || aggregate.From.IfIndex == nil || *aggregate.From.IfIndex != 19 {
		t.Fatalf("Huawei pair %+v", aggregate)
	}
	if partial.Kind != "physical" || partial.Aggregation.Status != "partial" || partial.Aggregation.AggregateID != "" || len(partial.Aggregation.MemberLinks) != 2 || partial.Aggregation.LocalGroup == nil || partial.Aggregation.RemoteGroup != nil {
		t.Fatalf("core partial %+v", partial)
	}
	for _, m := range partial.Aggregation.MemberLinks {
		if m.MembershipStatus != "local_only" || m.From.DeviceID != "74" || m.To.DeviceID != "1" {
			t.Fatal("partial direction or membership wrong")
		}
	}
	old := get("/api/v1/devices/84/uplink-path?schema_version=2")
	if old.Path.Edges[2].Aggregation != nil || old.Path.Edges[2].AggregationStatus != "partial" || len(old.Path.Edges[2].AggregationDiagnostics.MemberLinks) != 2 {
		t.Fatal("v2 compatibility/diagnostics")
	}
	v.CoreIDs = []int64{84}
	rev := get("/api/v1/devices/1/uplink-path?schema_version=3")
	for _, m := range rev.Path.Edges[1].Aggregation.MemberLinks {
		if m.From.DeviceID != "74" || m.To.DeviceID != "77" {
			t.Fatal("member endpoints not reversed")
		}
	}
}

func TestVendorLAGConflictsAndCompleteness(t *testing.T) {
	v := vendorLAGView()
	devices := map[int64]control.Device{}
	for _, d := range v.Devices {
		devices[d.ID] = d
	}
	a := v.Evidence.LAG[74]
	a.Complete = true
	v.Evidence.LAG[74] = a
	b := v.Evidence.LAG[77]
	b.Complete = true
	v.Evidence.LAG[77] = b
	find := func() topologyConnection {
		t.Helper()
		for _, c := range topologyConnections(v, devices) {
			if c.members[0].ID == 65 {
				return c
			}
		}
		t.Fatal("missing connection")
		return topologyConnection{}
	}
	if c := find(); c.coverage != "complete" || len(c.members) != 2 {
		t.Fatalf("complete group %+v", c)
	}
	// Missing physical observation of a configured member remains partial.
	v.Links = v.Links[1:]
	var c topologyConnection
	for _, x := range topologyConnections(v, devices) {
		if x.members[0].ID == 66 {
			c = x
		}
	}
	d := connectionDiagnostics(v, c, 77)
	if d.MemberDataStatus != "partial" || len(d.UnpairedMembers) != 2 {
		t.Fatalf("unpaired not shown %+v", d)
	}
	v = vendorLAGView()
	b = v.Evidence.LAG[77]
	b.Members[0].Status = "conflict"
	v.Evidence.LAG[77] = b
	for _, x := range topologyConnections(v, devices) {
		if x.members[0].ID == 65 || x.members[0].ID == 66 {
			if x.status != "conflict" || len(x.members) != 1 {
				t.Fatal("conflict allowed a group to fold")
			}
		}
	}
	x, y := uint32(10), uint32(20)
	p, q := uint32(20), uint32(10)
	if lacpConflict(&model.LACPPort{Stable: true, ActorKey: &x, PartnerKey: &y}, &model.LACPPort{Stable: true, ActorKey: &p, PartnerKey: &q}) {
		t.Fatal("different local keys incorrectly rejected")
	}
	q = 99
	if !lacpConflict(&model.LACPPort{Stable: true, ActorKey: &x}, &model.LACPPort{Stable: true, PartnerKey: &q}) {
		t.Fatal("crossed protocol contradiction missed")
	}
}

func TestNeighborCursorAllLinksAndBinding(t *testing.T) {
	v := vendorLAGView()
	v.Links = nil
	for n := int64(1); n <= 45; n++ {
		v.Links = append(v.Links, postgres.ExportLink{ID: n, DeviceAID: 74, DeviceBID: 77, DiscoveryState: "active", Confidence: "bidirectional", LastSeenScanID: &v.LatestScanID})
	}
	_, h, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: v}})
	firstRoute := "/api/v1/devices/74/neighbors?schema_version=3&neighbor_device_id=77"
	get := func(route string) neighborsV2 {
		t.Helper()
		w := callAuth(h, "GET", route, "", nil, headers)
		if w.Code != 200 {
			t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
		}
		var d neighborsV2
		if e := json.Unmarshal(decodeAPI(t, w).Data, &d); e != nil {
			t.Fatal(e)
		}
		return d
	}
	d := get(firstRoute)
	if !d.HasMore || d.NextCursor == nil || d.MatchingLinkCount != 45 || d.Truncated {
		t.Fatalf("initial page %+v", d)
	}
	firstCursor := *d.NextCursor
	seen := map[string]bool{}
	for {
		for _, l := range d.Items {
			if seen[l.LinkID] {
				t.Fatal("duplicate member")
			}
			seen[l.LinkID] = true
		}
		if !d.HasMore {
			break
		}
		d = get(firstRoute + "&cursor=" + url.QueryEscape(*d.NextCursor))
	}
	if len(seen) != 45 {
		t.Fatalf("missing links: %d", len(seen))
	}
	for _, route := range []string{firstRoute + "&cursor=" + url.QueryEscape(firstCursor+"bad"), firstRoute + "&cursor=bad"} {
		if w := callAuth(h, "GET", route, "", nil, headers); w.Code != 400 {
			t.Fatal("tampered cursor accepted")
		}
	}
	v.LatestScanID++
	if w := callAuth(h, "GET", firstRoute+"&cursor="+url.QueryEscape(firstCursor), "", nil, headers); w.Code != 409 || !strings.Contains(w.Body.String(), "CURSOR_STALE") {
		t.Fatal("mixed snapshots allowed")
	}
}

func TestLAGAdvertisementOnlyDoesNotInventMembers(t *testing.T) {
	v := vendorLAGView()
	v.CoreIDs = []int64{77}
	v.Evidence.LAG = map[int64]postgres.DeviceLAGEvidence{}
	ev := v.Evidence.Links[65]
	ev.Advertisements = []postgres.LAGAdvertisementEvidence{{ObserverID: 74, Advertisement: model.LAGAdvertisement{Direction: "remote", AggregateID: 27, Enabled: true}}}
	v.Evidence.Links[65] = ev
	_, h, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: v}})
	w := callAuth(h, "GET", "/api/v1/devices/74/uplink-path?schema_version=3", "", nil, headers)
	if w.Code != 200 {
		t.Fatalf("HTTP %d %s", w.Code, w.Body.String())
	}
	var d uplinkDataV2
	if err := json.Unmarshal(decodeAPI(t, w).Data, &d); err != nil {
		t.Fatal(err)
	}
	a := d.Path.Edges[0].Aggregation
	if a.Status != "partial" || a.MemberDataStatus != "unknown" || a.MemberLinks != nil || a.LocalGroup != nil || a.RemoteGroup != nil || len(a.Advertisements) != 1 {
		t.Fatalf("advertisement promoted to membership %+v", a)
	}
}
