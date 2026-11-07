package webui

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"

	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gonet/internal/auth"
	"gonet/internal/control"

	"gonet/internal/store/postgres"
	"gonet/internal/topology"
)

type apiBackend struct {
	countingBackend
	err  error
	read func(context.Context) (*control.View, error)
}

func (b *apiBackend) Read(ctx context.Context) (*control.View, error) {
	b.reads.Add(1)
	if b.read != nil {
		return b.read(ctx)
	}
	return b.view, b.err
}
func newAPITest(t *testing.T, b Backend) (*Server, http.Handler, map[string]string) {
	t.Helper()
	s := newTestServer(t, b)
	token, _, err := auth.GenerateAgentToken()
	if err != nil {
		t.Fatal(err)
	}
	seedTestKey(t, s, token)
	t.Cleanup(s.Close)
	return s, s.Handler(testHost), map[string]string{"Authorization": "Bearer " + token}
}
func decodeAPI(t *testing.T, w *httptest.ResponseRecorder) *struct {
	Data json.RawMessage `json:"data"`
	Meta apiMeta         `json:"meta"`
} {
	t.Helper()
	var result struct {
		Data json.RawMessage `json:"data"`
		Meta apiMeta         `json:"meta"`
	}
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Meta.SchemaVersion != "1.0" || result.Meta.RequestID == "" || result.Meta.GeneratedAt.Location() != time.UTC || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("metadata contract")
	}
	return &result
}
func apiFixture() *control.View {
	v := authFixtureView()
	v.Devices[3].DiscoveryDepth = nil
	v.Devices[3].Status = "historical"
	v.Devices[3].LastSeenAt = time.Time{}
	v.Links[3].DiscoveryState = "suspect_stale"
	v.Links[3].Fresh = false
	v.Links[3].CoverageGap = true
	v.Links[3].MissedCompleteScans = 1
	v.Links[4].DiscoveryState = "stale"
	v.Links[4].FirstSeenAt = time.Time{}
	v.Links[4].LastSeenScanID = nil
	v.Links[4].Confidence = "single_sided"
	v.Candidates = []control.Candidate{{Key: "observed-z", Name: "<script>untrusted tool text</script>", ObserverIDs: []int64{2, 1, 999}, Status: "unverified"}, {Key: "observed-a", Name: "unknown", ObserverIDs: []int64{1}}}
	v.CoreIDs = []int64{999, 1, 1}
	return v
}
func TestTopologyMethodsAndAuthentication(t *testing.T) {
	b := &apiBackend{countingBackend: countingBackend{view: apiFixture()}}
	paths := []string{"/api/v1/topology", "/api/v1/topology/summary", "/api/v1/devices/1", "/api/v1/devices/1/neighbors"}
	s2, h2, headers := newAPITest(t, b)
	cookie2, _ := testSession(t, s2)
	for _, p := range paths {
		for _, method := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
			w := callAuth(h2, method, p, "{}", nil, nil)
			if w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
				t.Fatal("method/CSRF order violated")
			}
		}
		for _, bad := range []map[string]string{nil, {"Authorization": ""}, {"Authorization": "Bearer invalid"}, {"Authorization": "Basic invalid"}} {
			w := callAuth(h2, "GET", p, "", nil, bad)
			if w.Code != 401 || w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal("invalid auth response")
			}
		}
		if w := callAuth(h2, "GET", p, "", cookie2, map[string]string{"Authorization": "Bearer invalid"}); w.Code != 401 {
			t.Fatal("bad bearer fell back to cookie")
		}
	}
	if b.reads.Load() != 0 || b.writes.Load() != 0 || b.scans.Load() != 0 {
		t.Fatal("unauthorized request reached business backend")
	}
	if w := callAuth(h2, "GET", paths[0], "", cookie2, nil); w.Code != 200 {
		t.Fatal("session cannot read")
	}
	before := b.reads.Load()
	for _, p := range []string{"/api/v1/auth/me", "/api/state", "/api/devices.csv"} {
		if w := callAuth(h2, "GET", p, "", nil, headers); w.Code != 401 {
			t.Fatal("bearer acquired console privilege")
		}
	}
	for _, p := range []string{"/api/settings", "/api/scan", "/api/cancel", "/api/v1/auth/logout"} {
		if w := callAuth(h2, "POST", p, "{}", nil, headers); w.Code != 401 {
			t.Fatal("bearer acquired write privilege")
		}
	}
	if w := callAuth(h2, "POST", "/api/v1/auth/login", "{}", nil, headers); w.Code == 200 {
		t.Fatal("bearer logged in")
	}
	if b.reads.Load() != before || b.writes.Load() != 0 || b.scans.Load() != 0 {
		t.Fatal("token leaked business capability")
	}
	for _, p := range paths {
		w := callAuth(h2, "HEAD", p, "", nil, headers)
		if w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") == "" {
			t.Fatal("HEAD contract")
		}
	}
}
func TestTopologyDTOStateSummaryNeighborsAndNoMutation(t *testing.T) {
	view := apiFixture()
	snapshot, _ := json.Marshal(view)
	before := sha256.Sum256(snapshot)
	b := &apiBackend{countingBackend: countingBackend{view: view}}
	_, h, headers := newAPITest(t, b)
	get := func(path string) *struct {
		Data json.RawMessage `json:"data"`
		Meta apiMeta         `json:"meta"`
	} {
		before := b.reads.Load()
		w := callAuth(h, "GET", path, "", nil, headers)
		result := decodeAPI(t, w)
		if b.reads.Load() != before+1 {
			t.Fatal("request did not read exactly once")
		}
		return result
	}
	full := get("/api/v1/topology")
	var all topologyData
	json.Unmarshal(full.Data, &all)
	if len(all.Devices) != 4 || len(all.Links) != 5 || all.Summary.CollectedDeviceCount != 3 || all.Summary.HistoricalDeviceCount != 1 || all.Summary.PendingNeighborCount != 2 || !slices.Equal(all.CoreIDs, []string{"1"}) {
		t.Fatal("full graph summary")
	}
	if all.Devices[3].DiscoveryDepth != nil || all.Devices[3].LastSeenAt != nil || all.Devices[0].LinkCount != 3 || all.Links[0].PortAID == "" {
		t.Fatal("device DTO semantics")
	}
	if all.Candidates[0].Key != "observed-a" || all.Candidates[0].ObservedAt != nil || all.Candidates[0].DeviceKind != "" || !slices.Equal(all.Candidates[1].ObservedByIDs, []string{"1", "2"}) {
		t.Fatal("candidate fields/scope")
	}
	for _, sensitive := range []string{"csrf_token", "password", "system_description", "identity_keys", "classification_rule", "probe_pool", "settings", "verification", "port_a_key"} {
		if strings.Contains(string(full.Data), `"`+sensitive+`"`) {
			t.Fatal("sensitive/internal field in DTO")
		}
	}
	if !strings.Contains(string(full.Data), "untrusted tool text") {
		t.Fatal("observed text was interpreted/dropped")
	}
	active := get("/api/v1/topology?state=active&include_pending=false")
	var filtered topologyData
	json.Unmarshal(active.Data, &filtered)
	if len(filtered.Devices) != 4 || len(filtered.Links) != 3 || len(filtered.Candidates) != 0 || filtered.Summary.PendingNeighborCount != 2 || filtered.Devices[3].LinkCount != 0 {
		t.Fatal("active/pending state contract")
	}
	var summary summaryDTO
	json.Unmarshal(get("/api/v1/topology/summary?state=active").Data, &summary)
	if summary.DeviceCount != 4 || summary.LinkCount != 3 || summary.DeviceKinds["switch"] != 4 {
		t.Fatal("summary mismatch")
	}
	var device struct {
		Device deviceDTO `json:"device"`
	}
	json.Unmarshal(get("/api/v1/devices/4?state=active").Data, &device)
	if device.Device.ID != "4" || device.Device.CollectionStatus != "historical" || device.Device.LinkCount != 0 {
		t.Fatal("historical device hidden")
	}
	var neighbors neighborsData
	json.Unmarshal(get("/api/v1/devices/1/neighbors").Data, &neighbors)
	if neighbors.NeighborCount != 2 || neighbors.LinkCount != 3 || len(neighbors.Items) != 3 {
		t.Fatal("parallel physical links merged")
	}
	if full.Meta.LatestScanID == nil || *full.Meta.LatestScanID != "30" || full.Meta.LatestScanStatus != "partial" || !full.Meta.Fresh || !full.Meta.CoverageGap || full.Meta.DataAgeSeconds == nil {
		t.Fatal("scan facts changed")
	}
	after, _ := json.Marshal(view)
	if sha256.Sum256(after) != before || b.writes.Load() != 0 || b.scans.Load() != 0 {
		t.Fatal("query mutated source or started a task")
	}
}
func TestTopologyStrictArgumentsAndInvisibleDevices(t *testing.T) {
	b := &apiBackend{countingBackend: countingBackend{view: apiFixture()}}
	_, h, headers := newAPITest(t, b)
	for _, path := range []string{"/api/v1/topology?refresh=true", "/api/v1/topology?state=", "/api/v1/topology?state=all&state=active", "/api/v1/topology?state=online", "/api/v1/topology?include_pending=1", "/api/v1/topology?include_pending=", "/api/v1/topology?include_pending=true&include_pending=true", "/api/v1/topology?state=%XX", "/api/v1/topology?state=all;refresh=true", "/api/v1/topology/summary?include_pending=false", "/api/v1/devices/1?include_pending=true", "/api/v1/devices/0", "/api/v1/devices/01", "/api/v1/devices/-1", "/api/v1/devices/1.2", "/api/v1/devices/9223372036854775808", "/api/v1/devices/192.0.2.1"} {
		w := callAuth(h, "GET", path, "", nil, headers)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "INVALID_ARGUMENT") {
			t.Errorf("invalid path accepted: %s (%d)", path, w.Code)
		}
	}
	if b.reads.Load() != 0 {
		t.Fatal("invalid argument read backend")
	}
	for _, p := range []string{"/api/v1/devices/999", "/api/v1/devices/999/neighbors"} {
		if w := callAuth(h, "GET", p, "", nil, headers); w.Code != 404 || !strings.Contains(w.Body.String(), "DEVICE_NOT_FOUND") {
			t.Fatal("missing device contract")
		}
	}
}
func TestTopologyScopeProjectionAndPrecision(t *testing.T) {
	bigID := int64(9007199254740993)
	depth := 0
	exported := &postgres.TopologyExport{Devices: []postgres.ExportDevice{{ID: bigID, Kind: "switch", DiscoveryDepth: &depth, AccessAddresses: []string{"192.0.2.1"}, IdentityKeys: []string{"chassis:4:010203040506"}}, {ID: 2, Kind: "switch", AccessAddresses: []string{"198.51.100.2"}}}, Links: []postgres.ExportLink{{ID: math.MaxInt64, DeviceAID: bigID, DeviceBID: 2, PortAID: math.MaxInt64, PortBID: 2}}, PendingNodes: []topology.PendingNode{{Key: "outside-observation", SystemName: "outside"}}, PendingLinks: []topology.PendingLink{{LocalDevice: uint64(2), RemoteKey: "outside-observation"}}}
	scope := control.Scope{Settings: control.Settings{AllowedCIDRs: []string{"192.0.2.0/24"}, Seeds: []string{"192.0.2.1"}}}
	exported.Devices = append(exported.Devices, postgres.ExportDevice{ID: 3, Kind: "switch", AccessAddresses: []string{"192.0.2.3"}})
	scope.Settings.ExcludedCIDRs = []string{"192.0.2.3/32"}
	view := control.Project(exported, scope)
	b := &apiBackend{countingBackend: countingBackend{view: view}}
	_, h, headers := newAPITest(t, b)
	w := callAuth(h, "GET", "/api/v1/topology", "", nil, headers)
	result := decodeAPI(t, w)
	var graph topologyData
	json.Unmarshal(result.Data, &graph)
	if len(graph.Devices) != 1 || graph.Devices[0].ID != "9007199254740993" || len(graph.Links) != 0 || len(graph.Candidates) != 0 || !slices.Equal(graph.CoreIDs, []string{"9007199254740993"}) {
		t.Fatal("projection/precision failed")
	}
	if w := callAuth(h, "GET", "/api/v1/devices/2", "", nil, headers); w.Code != 404 {
		t.Fatal("outside scope device visible")
	}
	if w := callAuth(h, "GET", "/api/v1/devices/3", "", nil, headers); w.Code != 404 {
		t.Fatal("excluded device visible")
	}
	view.Links = []postgres.ExportLink{{ID: math.MaxInt64, DeviceAID: bigID, DeviceBID: bigID, PortAID: math.MaxInt64, PortBID: math.MaxInt64 - 1, DiscoveryState: "active"}}
	view.LatestScanID = math.MaxInt64
	w = callAuth(h, "GET", "/api/v1/topology", "", nil, headers)
	result = decodeAPI(t, w)
	json.Unmarshal(result.Data, &graph)
	if graph.Links[0].ID != "9223372036854775807" || graph.Links[0].PortAID != "9223372036854775807" || *result.Meta.LatestScanID != "9223372036854775807" {
		t.Fatal("int64 precision lost")
	}
}
func TestTopologyEmptyDatabaseErrorsTimeoutAndCancellation(t *testing.T) {
	b := &apiBackend{countingBackend: countingBackend{view: &control.View{}}}
	s, h, headers := newAPITest(t, b)
	result := decodeAPI(t, callAuth(h, "GET", "/api/v1/topology", "", nil, headers))
	var graph topologyData
	json.Unmarshal(result.Data, &graph)
	if graph.Devices == nil || graph.Links == nil || graph.Candidates == nil || graph.CoreIDs == nil || graph.Summary.DeviceCount != 0 || result.Meta.LatestScanID != nil || result.Meta.LatestScanFinishedAt != nil || result.Meta.DataAgeSeconds != nil {
		t.Fatal("empty/null facts fabricated")
	}
	b.err = errors.New("sensitive DSN, SQL and path")
	w := callAuth(h, "GET", "/api/v1/topology", "", nil, headers)
	if w.Code != 503 || strings.Contains(w.Body.String(), "sensitive") {
		t.Fatal("database error contract")
	}
	b.err = nil
	b.view = nil
	if w := callAuth(h, "GET", "/api/v1/topology", "", nil, headers); w.Code != 503 {
		t.Fatal("nil view became empty success")
	}
	s.apiReadTimeout = time.Millisecond
	b.read = func(ctx context.Context) (*control.View, error) { <-ctx.Done(); return nil, ctx.Err() }
	if w := callAuth(h, "GET", "/api/v1/topology", "", nil, headers); w.Code != 504 {
		t.Fatal("read timeout")
	}
	observed := false
	b.read = func(ctx context.Context) (*control.View, error) {
		observed = errors.Is(ctx.Err(), context.Canceled)
		return nil, ctx.Err()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("GET", "/api/v1/topology", nil).WithContext(ctx)
	r.Host = testHost
	r.Header.Set("Authorization", headers["Authorization"])
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !observed {
		t.Fatal("request cancel not forwarded")
	}
}
func TestTopologyCapacityAndNoKeyRateLimit(t *testing.T) {
	view := apiFixture()
	view.Devices = []control.Device{}
	for i := 0; i < 2001; i++ {
		view.Devices = append(view.Devices, control.Device{ExportDevice: postgres.ExportDevice{ID: int64(i + 1), Kind: "switch"}})
	}
	b := &apiBackend{countingBackend: countingBackend{view: view}}
	_, h, headers := newAPITest(t, b)
	if w := callAuth(h, "GET", "/api/v1/topology", "", nil, headers); w.Code != 422 {
		t.Fatal("device cap not enforced")
	}
	for _, p := range []string{"/api/v1/topology/summary", "/api/v1/devices/1", "/api/v1/devices/1/neighbors"} {
		if w := callAuth(h, "GET", p, "", nil, headers); w.Code != 200 {
			t.Fatal("full-graph cap applied to smaller query")
		}
	}
	view.Devices = view.Devices[:2]
	view.Links = []postgres.ExportLink{}
	for i := 0; i < 10001; i++ {
		view.Links = append(view.Links, postgres.ExportLink{ID: int64(i + 1), DeviceAID: 1, DeviceBID: 2, DiscoveryState: "active"})
	}
	if w := callAuth(h, "GET", "/api/v1/topology", "", nil, headers); w.Code != 422 {
		t.Fatal("link cap not enforced")
	}
	view.Links = nil
	view.Devices[0].Name = strings.Repeat("x", maxAPIBytes)
	if w := callAuth(h, "GET", "/api/v1/devices/1", "", nil, headers); w.Code != 422 {
		t.Fatal("byte limit not enforced")
	}
	view.Devices[0].Name = "ok"
	for range 65 {
		if w := callAuth(h, "GET", "/api/v1/topology/summary", "", nil, headers); w.Code != 200 {
			t.Fatal("old per-key limit is still enforced")
		}
	}
}
func TestTopologyConcurrentStableSnapshotAndSort(t *testing.T) {
	v := apiFixture()
	slices.Reverse(v.Devices)
	slices.Reverse(v.Links)
	slices.Reverse(v.Candidates)
	before, _ := json.Marshal(v)
	b := &apiBackend{countingBackend: countingBackend{view: v}}
	_, h, headers := newAPITest(t, b)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := callAuth(h, "GET", "/api/v1/topology", "", nil, headers)
			if w.Code != 200 {
				t.Error("concurrent query failed")
				return
			}
			var result struct {
				Data topologyData `json:"data"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Error(err)
				return
			}
			if result.Data.Devices[0].ID != "1" || result.Data.Candidates[0].Key != "observed-a" || result.Data.Summary.LinkCount != 5 {
				t.Error("unstable sort/snapshot")
			}
		}()
	}
	wg.Wait()
	after, _ := json.Marshal(v)
	if string(before) != string(after) || b.reads.Load() != 20 || b.writes.Load() != 0 || b.scans.Load() != 0 {
		t.Fatal("concurrent query changed shared source")
	}
}

func TestTopologyEachRequestUsesOneChangingSnapshot(t *testing.T) {
	first, second := authFixtureView(), &control.View{Devices: []control.Device{{ExportDevice: postgres.ExportDevice{ID: 77, Kind: "switch"}, Status: "historical"}}}
	var sequence atomic.Int64
	b := &apiBackend{}
	b.read = func(ctx context.Context) (*control.View, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 10*time.Second {
			t.Error("missing 10s read deadline")
		}
		if sequence.Add(1)%2 == 0 {
			return first, nil
		}
		return second, nil
	}
	_, h, headers := newAPITest(t, b)
	for range 10 {
		w := callAuth(h, "GET", "/api/v1/topology", "", nil, headers)
		result := decodeAPI(t, w)
		var graph topologyData
		json.Unmarshal(result.Data, &graph)
		if graph.Summary.DeviceCount != len(graph.Devices) || graph.Summary.LinkCount != len(graph.Links) {
			t.Fatal("mixed snapshots")
		}
		if len(graph.Devices) == 1 && (graph.Devices[0].ID != "77" || len(graph.Links) != 0) {
			t.Fatal("mixed device snapshot")
		}
		if len(graph.Devices) == 4 && len(graph.Links) != 5 {
			t.Fatal("mixed graph snapshot")
		}
	}
	if sequence.Load() != 10 || b.reads.Load() != 10 || b.writes.Load() != 0 || b.scans.Load() != 0 {
		t.Fatal("not exactly one read per response")
	}
}
