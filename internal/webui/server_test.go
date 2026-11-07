package webui

import (
	"context"
	"encoding/csv"
	"gonet/internal/control"
	"gonet/internal/store/postgres"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLANListenerRejectsUnspecifiedPublicAndUnrestrictedAddresses(t *testing.T) {
	for _, address := range []string{":8787", "0.0.0.0:8787", "203.0.113.1:8787", "10.201.109.246:8787"} {
		listener, err := ListenAddress(address, nil, false)
		if err == nil {
			listener.Close()
			t.Fatalf("accepted unsafe listen address %s", address)
		}
	}
	if listener, err := ListenAddress("10.201.109.246:8787", []netip.Prefix{netip.MustParsePrefix("10.201.108.70/32")}, false); err == nil {
		listener.Close()
		t.Fatal("accepted a plaintext LAN listener")
	}
}

func TestLANConsoleChecksSocketSource(t *testing.T) {
	app := newTestServer(t, &fakeBackend{})
	defer app.Close()
	app.authConfig.AllowedSources = []netip.Prefix{
		netip.MustParsePrefix("10.201.108.70/32"),
		netip.MustParsePrefix("10.201.108.71/32"),
	}
	h := app.Handler("10.201.109.246:8787")
	for peer, want := range map[string]int{"10.201.108.70:1000": 200, "10.201.108.71:1000": 200, "10.201.108.72:1000": 403} {
		req := httptest.NewRequest("GET", "https://10.201.109.246:8787/health", nil)
		req.RemoteAddr = peer
		req.Header.Set("Origin", "https://10.201.109.246:8787")
		req.Header.Set("X-Forwarded-For", "10.201.108.70")
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != want {
			t.Errorf("peer %s: got %d, want %d", peer, res.Code, want)
		}
	}
}

type fakeBackend struct {
	mu      sync.Mutex
	s       control.Settings
	started chan struct{}
	view    *control.View
}

func (b *fakeBackend) Read(context.Context) (*control.View, error) {
	if b.view != nil {
		return b.view, nil
	}
	return &control.View{Devices: []control.Device{}, Candidates: []control.Candidate{}}, nil
}

func TestServedAssetsAreAllowListed(t *testing.T) {
	const host = "127.0.0.1:8787"
	s := newTestServer(t, &fakeBackend{})
	defer s.Close()
	h := s.Handler(host)
	cookie, _ := testSession(t, s)
	get := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r.Host = host
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for path := range servedAssets {
		if path == "/login" {
			continue
		}
		w := get(path)
		if w.Code != 200 {
			t.Fatalf("allow-listed asset %s returned %d", path, w.Code)
		}
		if w.Body.Len() == 0 {
			t.Fatalf("allow-listed asset %s is empty", path)
		}
	}
	for _, path := range []string{"/assets/app.js", "/tokens.css.bak", "/ui-topology.js", "/index.html", "/control/policy.go"} {
		if w := get(path); w.Code != 404 {
			t.Fatalf("unexpected asset %s returned %d, want 404", path, w.Code)
		}
	}
	// traversal attempts are normalised by the mux into a redirect; what matters is
	// that the redirected target is itself allow-listed and never a source file
	for _, path := range []string{"/../control/policy.go", "/%2e%2e/control/policy.go", "/../../go.mod"} {
		w := get(path)
		if w.Code == 200 || strings.Contains(w.Body.String(), "package control") {
			t.Fatalf("path traversal %s reached a source file (%d)", path, w.Code)
		}
	}
	if !strings.Contains(get("/").Body.String(), "/tokens.css") {
		t.Fatal("index must load the design tokens before the main stylesheet")
	}
	index := get("/").Body.String()
	pagerAt := strings.Index(index, "/ui-pagination.js")
	appAt := strings.Index(index, "/app.js")
	if pagerAt < 0 || appAt < 0 || pagerAt > appAt {
		t.Fatalf("index must load the pager script before app.js (pager=%d app=%d)", pagerAt, appAt)
	}
	pagerJS := get("/ui-pagination.js").Body.String()
	for _, want := range []string{"GoNetPager", "module.exports", "parseJump", "paginate"} {
		if !strings.Contains(pagerJS, want) {
			t.Fatalf("pager asset is missing %q", want)
		}
	}
	settingsAt := strings.Index(index, "/ui-settings.js")
	if settingsAt < 0 || settingsAt > appAt {
		t.Fatalf("index must load the settings helper before app.js (settings=%d app=%d)", settingsAt, appAt)
	}
	settingsJS := get("/ui-settings.js").Body.String()
	for _, want := range []string{"GoNetSettings", "module.exports", "fromSettings", "toSettings", "retiredBootstrap"} {
		if !strings.Contains(settingsJS, want) {
			t.Fatalf("settings asset is missing %q", want)
		}
	}
	if strings.Contains(settingsJS, "BootstrapAddresses") {
		t.Fatal("the frontend must not reimplement address supplementation")
	}
	regionAt := strings.Index(index, "/ui-region.js")
	if regionAt < 0 || regionAt > appAt {
		t.Fatalf("index must load the region helper before app.js (region=%d app=%d)", regionAt, appAt)
	}
	regionJS := get("/ui-region.js").Body.String()
	for _, want := range []string{"GoNetRegion", "module.exports", "signatures", "changed", "planRows", "FIELDS"} {
		if !strings.Contains(regionJS, want) {
			t.Fatalf("region asset is missing %q", want)
		}
	}
	// 判据字段必须覆盖展示字段（A7）：抽查设备改名、探测失败原因、链路置信度
	for _, want := range []string{"inventory_name", "failure_reason", "confidence", "matched_device_id"} {
		if !strings.Contains(regionJS, want) {
			t.Fatalf("region change detection must watch the displayed field %q", want)
		}
	}
}

func TestCSVExportsSelectedVisibleDevicesAndEscapesFormulas(t *testing.T) {
	b := &fakeBackend{view: &control.View{Devices: []control.Device{
		{ExportDevice: postgres.ExportDevice{ID: 1}, Name: "other"},
		{ExportDevice: postgres.ExportDevice{ID: 2, Kind: "wireless_controller", AccessAddresses: []string{"192.0.2.2"}}, Name: " =HYPERLINK(\"bad\")", Status: "collected"},
	}}}
	s := newTestServer(t, b)
	defer s.Close()
	h := s.Handler("127.0.0.1:8787")
	cookie, csrf := testSession(t, s)
	_ = csrf
	for _, tc := range []struct {
		query string
		rows  int
	}{{"?ids=2", 2}, {"?ids=999", 1}, {"?ids=", 1}, {"", 3}} {
		r := httptest.NewRequest("GET", "/api/devices.csv"+tc.query, nil)
		r.Host = "127.0.0.1:8787"
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(w.Body.String(), "\ufeff"))).ReadAll()
		if w.Code != 200 || err != nil || len(rows) != tc.rows || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment;") {
			t.Fatalf("CSV %s: code=%d rows=%v err=%v", tc.query, w.Code, rows, err)
		}
		if tc.query == "?ids=2" && (rows[1][0] != "' =HYPERLINK(\"bad\")" || rows[1][4] != "192.0.2.2" || rows[1][8] != "无线 AC") {
			t.Fatalf("unsafe or wrong row: %v", rows[1])
		}
	}
}
func (b *fakeBackend) Settings() control.Settings { b.mu.Lock(); defer b.mu.Unlock(); return b.s }
func (b *fakeBackend) SaveSettings(s control.Settings) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.s = s
	return nil
}
func (b *fakeBackend) Scan(ctx context.Context, _ bool, p func(Progress)) (RunResult, error) {
	close(b.started)
	p(Progress{Stage: "scanning", Scheduled: 1})
	<-ctx.Done()
	return RunResult{Status: "aborted"}, nil
}
func TestConsoleOriginTokenAndSingleJob(t *testing.T) {
	b := &fakeBackend{started: make(chan struct{})}
	s := newTestServer(t, b)
	defer s.Close()
	h := s.Handler("127.0.0.1:8787")
	cookie, csrf := testSession(t, s)
	_ = csrf
	call := func(method, path, body, token, origin, host string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Host = host
		r.AddCookie(cookie)
		r.Header.Set("X-GoNet-Token", token)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct{ token, origin, host string }{{"", "", "127.0.0.1:8787"}, {csrf, "http://evil.invalid", "127.0.0.1:8787"}, {csrf, "", "evil.invalid"}} {
		if w := call("POST", "/api/scan", "{}", tc.token, tc.origin, tc.host); w.Code != http.StatusForbidden {
			t.Fatalf("hostile request accepted %d", w.Code)
		}
	}
	if w := call("POST", "/api/scan", "{}", csrf, "http://127.0.0.1:8787", "127.0.0.1:8787"); w.Code != 202 {
		t.Fatal(w.Code)
	}
	<-b.started
	if w := call("POST", "/api/scan", "{}", csrf, "", "127.0.0.1:8787"); w.Code != 409 {
		t.Fatal("concurrent scan accepted")
	}
	if w := call("PUT", "/api/settings", "{}", csrf, "", "127.0.0.1:8787"); w.Code != 409 {
		t.Fatal("settings changed during scan")
	}
	if w := call("POST", "/api/cancel", "{}", csrf, "", "127.0.0.1:8787"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	deadline := time.Now().Add(time.Second)
	for {
		s.mu.Lock()
		running := s.job.Running
		s.mu.Unlock()
		if !running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancel did not finish job")
		}
		time.Sleep(time.Millisecond)
	}
	if w := call("GET", "/", "", csrf, "", "127.0.0.1:8787"); w.Code != 200 || !strings.Contains(w.Body.String(), "更新拓扑") {
		t.Fatal("embedded interface missing")
	}
}
