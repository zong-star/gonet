package webui

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gonet/internal/control"
	"gonet/internal/store/postgres"
)

func peerLAGView() *control.View {
	v := vendorLAGView()
	for id, facts := range v.Evidence.LAG {
		facts.Complete = true
		v.Evidence.LAG[id] = facts
	}
	now := time.Now()
	v.LatestScanFinishedAt = &now
	for i := range v.Devices {
		d := &v.Devices[i]
		d.Kind = "switch"
		d.Status = "collected"
		switch d.ID {
		case 1:
			d.SysObjectID = "1.3.6.1.4.1.45577"
			d.ClassificationRule = "sundray_ts7914_chassis38_20251010"
		case 74:
			d.SysObjectID = "1.3.6.1.4.1.25506.1.1460"
		case 77:
			d.SysObjectID = "1.3.6.1.4.1.2011.2.23.967"
		}
	}
	for i := range v.Links {
		l := &v.Links[i]
		l.PortAID = l.ID*10 + 1
		l.PortBID = l.ID*10 + 2
		l.Fresh = true
	}
	return v
}
func TestPeerLAGV4PathNeighborsAndCompatibility(t *testing.T) {
	v := peerLAGView()
	_, h, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: v}})
	var samples []map[string]any
	for _, route := range []string{"/api/v1/devices/84/uplink-path?schema_version=4", "/api/v1/devices/1/neighbors?schema_version=4&neighbor_device_id=74&limit=1", "/api/v1/topology?schema_version=4"} {
		w := callAuth(h, "GET", route, "", nil, headers)
		if w.Code != 200 {
			t.Fatalf("%s HTTP %d %s", route, w.Code, w.Body.String())
		}
		var data map[string]any
		if e := json.Unmarshal(decodeAPI(t, w).Data, &data); e != nil {
			t.Fatal(e)
		}
		if data["schema_version"] != float64(4) || data["inference_policy_version"] != "peer-lag-v2" {
			t.Fatalf("version: %+v", data)
		}
		if strings.Contains(route, "uplink-path") {
			p := data["path"].(map[string]any)
			if p["hop_count"] != float64(3) {
				t.Fatal("hops changed")
			}
			edge := p["edges"].([]any)[2].(map[string]any)
			a := edge["aggregation"].(map[string]any)
			if edge["kind"] != "aggregate" || a["status"] != "inferred" || len(a["member_links"].([]any)) != 2 || a["mode"] != "unknown" {
				t.Fatalf("missing inferred pair: %+v", a)
			}
			g := a["remote_group"].(map[string]any)
			if g["aggregate_if_index"] != nil || g["interface_name"] != nil {
				t.Fatal("invented sundray interface")
			}
		}
		if strings.Contains(route, "neighbors") {
			if data["matching_link_count"] != float64(2) || data["returned_link_count"] != float64(1) || data["has_more"] != true {
				t.Fatal("physical page counts")
			}
			item := data["items"].([]any)[0].(map[string]any)
			agg := item["aggregation"].(map[string]any)
			cursor := data["next_cursor"].(string)
			second := callAuth(h, "GET", route+"&cursor="+url.QueryEscape(cursor), "", nil, headers)
			var next neighborsV2
			if e := json.Unmarshal(decodeAPI(t, second).Data, &next); e != nil {
				t.Fatal(e)
			}
			if len(next.Items) != 1 || next.Items[0].LinkID == item["link_id"] || *next.Items[0].Aggregation.AggregateID != agg["aggregate_id"] {
				t.Fatal("group split across page")
			}
			facts := v.Evidence.LAG[74]
			facts.Members[2].Status = "conflict"
			v.Evidence.LAG[74] = facts
			if changed := callAuth(h, "GET", route+"&cursor="+url.QueryEscape(cursor), "", nil, headers); changed.Code != 409 {
				t.Fatal("membership mutation did not stale cursor")
			}
			facts.Members[2].Status = "confirmed"
			v.Evidence.LAG[74] = facts
		}
		if strings.Contains(route, "/topology?") && (len(data["links"].([]any)) != 5 || len(data["aggregate_connections"].([]any)) != 2) {
			t.Fatal("full graph lost links or groups")
		}
		samples = append(samples, map[string]any{"path": route, "status": w.Code, "body": json.RawMessage(w.Body.Bytes())})
	}
	old := callAuth(h, "GET", "/api/v1/devices/84/uplink-path?schema_version=3", "", nil, headers)
	var d uplinkDataV2
	if e := json.Unmarshal(decodeAPI(t, old).Data, &d); e != nil {
		t.Fatal(e)
	}
	if d.Path.Edges[2].Kind != "physical" || d.Path.Edges[2].Aggregation.Status != "partial" {
		t.Fatal("legacy policy changed")
	}
	if output := os.Getenv("GONET_PEER_LAG_OUTPUT"); output != "" {
		if e := os.MkdirAll(output, 0700); e != nil {
			t.Fatal(e)
		}
		b, _ := json.MarshalIndent(samples, "", "  ")
		if e := os.WriteFile(filepath.Join(output, "http-samples.json"), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
}
func TestPeerLAGV4DirectionSingleEvidenceAndOldScan(t *testing.T) {
	v := peerLAGView()
	for i := range v.Links {
		v.Links[i].Confidence = "unidirectional"
	}
	devices := visibleAggregationDevices(v)
	cs := topologyConnectionsV4(v, devices)
	var c topologyConnection
	for _, x := range cs {
		if x.status == "inferred" {
			c = x
		}
	}
	if len(c.members) != 2 || !c.weak {
		t.Fatal("unidirectional evidence rejected")
	}
	a, b := projectUplinkV4(v, c, 1, 1), projectUplinkV4(v, c, 74, 1)
	if a.EdgeID != b.EdgeID || a.From.DeviceID != "1" || b.From.DeviceID != "74" || a.Aggregation.MemberLinks[0].From.DeviceID != "1" {
		t.Fatal("reverse projection")
	}
	oldScan := v.LatestScanID
	for i := range v.Links {
		v.Links[i].LastSeenScanID = &oldScan
	}
	v.LatestScanID++
	if r := graphAggregationsV4(v); len(r) != 0 {
		t.Fatal("old memberships joined to new links")
	}
	// No base membership and no ifIndex cannot create physical pairs from ads.
	v = peerLAGView()
	v.Evidence.LAG = map[int64]postgres.DeviceLAGEvidence{}
	if r := graphAggregationsV4(v); len(r) != 0 {
		t.Fatal("created groups without membership")
	}
}
