package webui

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"gonet/internal/control"
	"gonet/internal/store/postgres"
)

func TestDeviceSearchRoute(t *testing.T) {
	view := &control.View{LatestScanStatus: "partial"}
	for _, id := range []int64{9, 8, 7, 6, 5, 4, 3} {
		device := control.Device{
			ExportDevice: postgres.ExportDevice{ID: id, SysName: "edge"},
			Name:         "Edge", Vendor: "H3C", Model: "S5130",
		}
		view.Devices = append(view.Devices, device)
	}
	view.Devices[0].AccessAddresses = []string{"192.0.2.9", "2001:db8::9"}
	view.Devices[0].Vendor = "Huawei"
	view.Devices[0].Model = "S5735"
	view.Devices[1].Name = "Building-08"
	view.Devices[1].SysName = "switch-08"
	b := &apiBackend{countingBackend: countingBackend{view: view}}
	_, h, headers := newAPITest(t, b)
	base := "/api/v1/devices"
	for _, query := range []string{"", "?query=+", "?query=a&query=b", "?query=a&limit=6", "?query=a&limit=0", "?query=%FF", "?query=a&state=all"} {
		if w := callAuth(h, "GET", base+query, "", nil, headers); w.Code != 400 {
			t.Fatalf("%s got %d", query, w.Code)
		}
	}
	if b.reads.Load() != 0 {
		t.Fatal("invalid arguments reached backend")
	}
	if w := callAuth(h, "HEAD", base+"?query=edge", "", nil, headers); w.Code != 405 || w.Header().Get("Allow") != "GET" {
		t.Fatal("search must be GET only")
	}
	if w := callAuth(h, "GET", base+"?query=edge", "", nil, nil); w.Code != 401 {
		t.Fatal("search bypassed authentication")
	}
	for _, tc := range []struct {
		query, firstID, ip, match string
		total, returned           int
		ambiguous                 bool
	}{
		{"query=+EDGE+&limit=1", "3", "", "name", 6, 1, true},
		{"query=edge", "3", "", "name", 6, 5, true},
		{"query=edge&vendor=huawei&model=s5735", "9", "192.0.2.9", "name", 1, 1, false},
		{"query=ITCH-08", "8", "", "sys_name", 1, 1, false},
		{"query=192.0.2.9", "9", "192.0.2.9", "management_ip", 1, 1, false},
		{"query=" + url.QueryEscape("2001:0db8:0:0::9"), "9", "2001:db8::9", "management_ip", 1, 1, false},
		{"query=192.0.2.99", "", "", "", 0, 0, false},
	} {
		t.Run(tc.query, func(t *testing.T) {
			response := decodeAPI(t, callAuth(h, "GET", base+"?"+tc.query, "", nil, headers))
			var got deviceSearchData
			if err := json.Unmarshal(response.Data, &got); err != nil {
				t.Fatal(err)
			}
			if !response.Meta.CoverageGap || got.Items == nil || got.Total != tc.total || len(got.Items) != tc.returned || got.Ambiguous != tc.ambiguous {
				t.Fatalf("response: %s", response.Data)
			}
			if len(got.Items) > 0 {
				item := got.Items[0]
				ip := ""
				if item.ManagementIP != nil {
					ip = *item.ManagementIP
				}
				if item.DeviceID != tc.firstID || ip != tc.ip || item.MatchType != tc.match {
					t.Fatalf("response: %s", response.Data)
				}
			}
		})
	}
}

func TestDeviceSearchResponseBudget(t *testing.T) {
	view := &control.View{}
	for id := int64(1); id <= 3; id++ {
		view.Devices = append(view.Devices, control.Device{
			ExportDevice: postgres.ExportDevice{ID: id},
			Name:         "edge" + strings.Repeat("设", 2400),
		})
	}
	_, h, headers := newAPITest(t, &apiBackend{countingBackend: countingBackend{view: view}})
	w := callAuth(h, "GET", "/api/v1/devices?query=edge", "", nil, headers)
	response := decodeAPI(t, w)
	var got deviceSearchData
	if err := json.Unmarshal(response.Data, &got); err != nil {
		t.Fatal(err)
	}
	if !response.Meta.ResponseTruncated || w.Body.Len() > maxCompactAPIBytes || got.Total != 3 || len(got.Items) != 1 {
		t.Fatalf("size=%d, total=%d, returned=%d", w.Body.Len(), got.Total, len(got.Items))
	}
}
