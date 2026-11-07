package webui

import (
	"encoding/json"
	"testing"

	"gonet/internal/control"
	"gonet/internal/model"
	"gonet/internal/store/postgres"
)

func TestCompactNeighborsAndLAGGrouping(t *testing.T) {
	view := &control.View{LatestScanID: 30, LatestScanStatus: "partial"}
	for _, id := range []int64{1, 2, 3} {
		view.Devices = append(view.Devices, control.Device{ExportDevice: postgres.ExportDevice{ID: id}, Name: idString(id)})
	}
	view.Evidence = &postgres.TopologyEvidence{
		Links: map[int64]postgres.PhysicalLinkEvidence{},
		LAG:   map[int64]postgres.DeviceLAGEvidence{1: {Complete: true}, 2: {Complete: true}},
	}
	for i := int64(1); i <= 5; i++ {
		view.Links = append(view.Links, postgres.ExportLink{ID: i, DeviceAID: 1, DeviceBID: 2,
			PortAID: 10 + i, PortBID: 20 + i, PortAName: "A", PortBName: "B", Confidence: "bidirectional",
			DiscoveryState: "active", LastSeenScanID: &view.LatestScanID})
		a, b := int32(10+i), int32(20+i)
		view.Evidence.Links[i] = postgres.PhysicalLinkEvidence{
			A: postgres.LinkEndpointEvidence{IfIndex: &a}, B: postgres.LinkEndpointEvidence{IfIndex: &b},
			Observations: []postgres.ObservationRef{{ID: i, ObserverID: 2}},
		}
		for _, dev := range []int64{1, 2} {
			if i > 2 && (i != 3 || dev == 2) {
				continue
			}
			facts := view.Evidence.LAG[dev]
			index := a
			if dev == 2 {
				index = b
			}
			aggregate := int32(100)
			if i == 3 {
				aggregate = 200
			}
			facts.Members = append(facts.Members, postgres.LAGMemberEvidence{LAGMember: model.LAGMember{
				AggregateIfIndex: aggregate, MemberIfIndex: index, Status: "confirmed", Mode: "static",
			}, AggregateName: "LAG"})
			view.Evidence.LAG[dev] = facts
		}
	}
	oldScan := int64(29)
	view.Links[4].LastSeenScanID = &oldScan
	devices := map[int64]control.Device{1: view.Devices[0], 2: view.Devices[1], 3: view.Devices[2]}
	connections := topologyConnections(view, devices)
	if len(connections) != 3 || len(connections[0].members) != 2 || connections[0].mode != "static" ||
		connections[0].coverage != "complete" || connections[1].status != "conflict" || connections[2].status != "not_member" {
		t.Fatalf("connections: %+v", connections)
	}
	_, handler, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: view}})
	path := "/api/v1/devices/2/neighbors"
	legacy := decodeAPI(t, callAuth(handler, "GET", path, "", nil, headers))
	var legacyFields map[string]json.RawMessage
	if err := json.Unmarshal(legacy.Data, &legacyFields); err != nil || len(legacyFields) != 4 {
		t.Fatalf("legacy response: %s", legacy.Data)
	}
	response := decodeAPI(t, callAuth(handler, "GET", path+"?limit=2", "", nil, headers))
	var got compactNeighborsData
	if err := json.Unmarshal(response.Data, &got); err != nil {
		t.Fatal(err)
	}
	if !response.Meta.CoverageGap || response.Meta.State != "active" || got.NeighborCount != 1 ||
		got.LinkCount != 5 || len(got.Items) != 2 || !got.Truncated || got.ReturnedLinkCount != 2 {
		t.Fatalf("response: %s", response.Data)
	}
	if item := got.Items[0]; item.Link.ID != "1" || item.Local.DeviceID != "2" || item.Remote.DeviceID != "1" ||
		item.Local.Interface.IfIndex == nil || *item.Local.Interface.IfIndex != 21 ||
		len(item.Observations) != 1 || item.Observations[0].ObserverID != "2" {
		t.Fatalf("reversed evidence: %+v", item)
	}
}
