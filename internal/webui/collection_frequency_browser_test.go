package webui

import (
	"context"
	"gonet/internal/config"
	"gonet/internal/control"
	"gonet/internal/topology"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type frequencyBrowserBackend struct {
	fakeBackend
	configPath, scopePath string
}

func (b *frequencyBrowserBackend) SaveSettings(s control.Settings) error {
	scope := control.Scope{Version: 1, Mode: "lldp", Settings: s}
	if e := control.SavePolicy(b.configPath, b.scopePath, &scope); e != nil {
		return e
	}
	return b.fakeBackend.SaveSettings(s)
}
func TestCollectionFrequencyBrowser(t *testing.T) {
	output := os.Getenv("GONET_FREQUENCY_BROWSER_OUTPUT")
	if output == "" {
		t.Skip("frequency browser acceptance is opt-in")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw, e := os.ReadFile("../../config/config.example.yaml")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	view := peerLAGView()
	view.Candidates = []control.Candidate{}
	view.PendingNodes = []topology.PendingNode{}
	view.PendingLinks = []topology.PendingLink{}
	view.Inventory = []control.InventoryStatus{}
	view.ProbePool = []control.Probe{}
	b := &frequencyBrowserBackend{fakeBackend: fakeBackend{s: control.Settings{Seeds: []string{"192.0.2.1"}, AllowedCIDRs: []string{"192.0.2.0/24"}, ReadManagement: true, CollectionInterval: &control.CollectionInterval{Value: 4, Unit: "minute"}}, view: view}, configPath: path, scopePath: filepath.Join(dir, "scope.json")}
	app := newTestServer(t, b)
	defer app.Close()
	cookie, _ := testSession(t, app)
	server := httptest.NewUnstartedServer(nil)
	server.Config.Handler = app.Handler(server.Listener.Addr().String())
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	script, e := filepath.Abs("../../docs/acceptance/collection-frequency-2026-11-06/verify-browser.cjs")
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.CommandContext(ctx, "node", script)
	cmd.Env = append(os.Environ(), "GONET_FREQUENCY_TEST_URL="+server.URL, "GONET_FREQUENCY_TEST_COOKIE="+cookie.Name+"="+cookie.Value)
	result, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("%v\n%s", e, result)
	}
	t.Log(string(result))
	cfg, e := config.Load(path)
	if e != nil || cfg.InterfaceStatus.Interval.Duration != 7*time.Minute || cfg.InterfaceStatus.StaleAfter.Duration != 21*time.Minute {
		t.Fatal("UI value not persisted to effective polling configuration", e)
	}
}

func TestTopologyScheduleBrowser(t *testing.T) {
	output := os.Getenv("GONET_TOPOLOGY_SCHEDULE_BROWSER_OUTPUT")
	if output == "" {
		t.Skip("frequency browser acceptance is opt-in")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw, e := os.ReadFile("../../config/config.example.yaml")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	view := peerLAGView()
	view.Candidates = []control.Candidate{}
	view.PendingNodes = []topology.PendingNode{}
	view.PendingLinks = []topology.PendingLink{}
	view.Inventory = []control.InventoryStatus{}
	view.ProbePool = []control.Probe{}
	b := &frequencyBrowserBackend{fakeBackend: fakeBackend{s: control.Settings{Seeds: []string{"192.0.2.1"}, AllowedCIDRs: []string{"192.0.2.0/24"}, ReadManagement: true, CollectionInterval: &control.CollectionInterval{Value: 4, Unit: "minute"}}, view: view}, configPath: path, scopePath: filepath.Join(dir, "scope.json")}
	app := newTestServer(t, b)
	defer app.Close()
	cookie, _ := testSession(t, app)
	server := httptest.NewUnstartedServer(nil)
	server.Config.Handler = app.Handler(server.Listener.Addr().String())
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	script, e := filepath.Abs("../../docs/acceptance/topology-schedule-2026-11-06/verify-browser.cjs")
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.CommandContext(ctx, "node", script)
	cmd.Env = append(os.Environ(), "GONET_FREQUENCY_TEST_URL="+server.URL, "GONET_FREQUENCY_TEST_COOKIE="+cookie.Name+"="+cookie.Value)
	result, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("%v\n%s", e, result)
	}
	t.Log(string(result))
	cfg, e := config.Load(path)
	if e != nil || cfg.InterfaceStatus.Interval.Duration != 4*time.Minute || cfg.TopologyScan.Interval.Duration != 0 {
		t.Fatal("UI value not persisted to effective polling configuration", e)
	}
}
