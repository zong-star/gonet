package webui

import (
	"encoding/json"
	"gonet/internal/model"
	"gonet/internal/store/postgres"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDeviceInterfacesAndStatusAPI(t *testing.T) {
	v := peerLAGView()
	now := time.Now().UTC()
	v.Devices[0].Interfaces = []model.Interface{{IfIndex: 78, Name: "ge1_1_29", Type: 6, InterfaceStatus: model.InterfaceStatus{AdminStatus: "up", OperStatus: "down", StatusCollectedAt: &now, StatusCollectionState: "success"}}}
	a := model.InterfaceStatus{AdminStatus: "up", OperStatus: "up", StatusCollectedAt: &now, StatusCollectionState: "success"}
	b := a
	b.OperStatus = "down"
	for i := range v.Links {
		v.Links[i].LinkInterfaceStatus = model.LinkStatus(a, b, now, 12*time.Minute)
	}
	_, h, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: v}})
	samples := []map[string]any{}
	for _, route := range []string{"/api/v1/devices/1/interfaces", "/api/v1/topology", "/api/v1/devices/1/neighbors?schema_version=4", "/api/v1/devices/1", "/api/v1/topology/summary"} {
		w := callAuth(h, "GET", route, "", nil, headers)
		if w.Code != 200 {
			t.Fatalf("%s %d %s", route, w.Code, w.Body.String())
		}
		samples = append(samples, map[string]any{"path": route, "status": w.Code, "body": json.RawMessage(w.Body.Bytes())})
		if route == "/api/v1/devices/1/interfaces" {
			var d struct {
				Interfaces []model.Interface `json:"interfaces"`
			}
			if e := json.Unmarshal(decodeAPI(t, w).Data, &d); e != nil || len(d.Interfaces) != 1 || d.Interfaces[0].OperStatus != "down" {
				t.Fatal(d, e)
			}
		}
		if route == "/api/v1/topology" {
			var d topologyData
			if e := json.Unmarshal(decodeAPI(t, w).Data, &d); e != nil || len(d.Links) != 5 || d.Links[0].LinkOperStatus != "degraded" {
				t.Fatal(d, e)
			}
		}
	}
	if dir := os.Getenv("GONET_INTERFACE_STATUS_OUTPUT"); dir != "" {
		if e := os.MkdirAll(dir, 0700); e != nil {
			t.Fatal(e)
		}
		b, _ := json.MarshalIndent(samples, "", "  ")
		if e := os.WriteFile(filepath.Join(dir, "http-samples.json"), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	for _, tt := range []struct {
		route string
		want  int
	}{{"/api/v1/devices/999/interfaces", 404}, {"/api/v1/devices/1/interfaces?x=1", 400}, {"/api/v1/devices/0/interfaces", 400}} {
		if w := callAuth(h, "GET", tt.route, "", nil, headers); w.Code != tt.want {
			t.Fatalf("%s: %d", tt.route, w.Code)
		}
	}
	if w := callAuth(h, "GET", "/api/v1/devices/1/interfaces", "", nil, nil); w.Code != 401 {
		t.Fatal("anonymous interface read", w.Code)
	}
	for _, d := range v.Devices {
		if d.ID == 1 {
			a := orientedLinkStatus(postgres.ExportLink{DeviceAID: 1, DeviceBID: 2, LinkInterfaceStatus: model.LinkStatus(a, b, now, time.Minute)}, 2)
			if a.SourceOperStatus != "down" || a.TargetOperStatus != "up" {
				t.Fatal(a)
			}
		}
	}
}
func TestPeerInferenceExpiresWithoutRemovingPhysicalLinks(t *testing.T) {
	v := peerLAGView()
	old := time.Now().Add(-73 * time.Hour)
	v.LatestScanFinishedAt = &old
	groups := graphAggregationsV4(v)
	found := false
	for _, c := range groups {
		for _, g := range []*model.AggregationGroup{c.GroupA, c.GroupB} {
			if g != nil && g.AggregationSource == "peer_inferred" {
				found = true
				if g.InferenceStatus != "stale" || c.Status == "inferred" || g.InferredAt == nil || len(g.EvidenceLinkIDs) != 2 {
					t.Fatal(c)
				}
			}
		}
	}
	if !found || len(v.Links) != 5 {
		t.Fatal("evidence discarded")
	}
}
