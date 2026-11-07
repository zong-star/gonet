package webui

import (
	"context"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"gonet/internal/config"
	"gonet/internal/control"
	"gonet/internal/preprobe"
	"gonet/internal/topology"
)

type snmpSettingsBrowserBackend struct {
	fakeBackend
	configPath, scopePath string
}

func (b *snmpSettingsBrowserBackend) Settings() control.Settings {
	s := b.fakeBackend.Settings()
	if cfg, err := config.Load(b.configPath); err == nil {
		control.SyncSNMPSettings(&s, cfg)
	}
	return s
}

func (b *snmpSettingsBrowserBackend) SaveSettings(s control.Settings) error {
	scope := control.Scope{Version: 1, Mode: "lldp", Settings: s}
	if err := control.SavePolicy(b.configPath, b.scopePath, &scope); err != nil {
		return err
	}
	if scope.Settings.SNMP != nil {
		public := *scope.Settings.SNMP
		public.Community = ""
		scope.Settings.SNMP = &public
	}
	return b.fakeBackend.SaveSettings(scope.Settings)
}

func (b *snmpSettingsBrowserBackend) Scan(_ context.Context, _ bool, progress func(Progress)) (RunResult, error) {
	progress(Progress{Stage: "preprobe", Completed: 764, Scheduled: 764, Probe: &preprobe.Summary{Enabled: true, FullRange: true, RangeHosts: 764, Completed: 764, Termination: "range_complete"}})
	return RunResult{ScanID: 1, Status: "completed"}, nil
}

func TestSNMPSettingsBrowser(t *testing.T) {
	if os.Getenv("GONET_SNMP_SETTINGS_BROWSER_OUTPUT") == "" {
		t.Skip("SNMP browser acceptance is opt-in")
	}
	t.Setenv("GONET_SNMP_COMMUNITY", "fixture-snmp-before")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw, err := os.ReadFile("../../config/config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	view := peerLAGView()
	view.Candidates = []control.Candidate{}
	view.PendingNodes = []topology.PendingNode{}
	view.PendingLinks = []topology.PendingLink{}
	view.Inventory = []control.InventoryStatus{}
	view.ProbePool = []control.Probe{}
	view.ProbeSummary = preprobe.Summary{Enabled: true, FullRange: true, RangeHosts: 764, Completed: 764, Termination: "range_complete"}
	b := &snmpSettingsBrowserBackend{fakeBackend: fakeBackend{s: control.Settings{Seeds: []string{"192.0.2.1"}, AllowedCIDRs: []string{"192.0.2.0/24"}, ReadManagement: true, CollectionInterval: &control.CollectionInterval{Value: 4, Unit: "minute"}}, view: view}, configPath: path, scopePath: filepath.Join(dir, "scope.json")}
	app := newTestServer(t, b)
	defer app.Close()
	cookie, _ := testSession(t, app)
	server := httptest.NewUnstartedServer(nil)
	server.Config.Handler = app.Handler(server.Listener.Addr().String())
	server.StartTLS()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	script, err := filepath.Abs("../../docs/acceptance/full-probe-snmp-settings-2026-11-07/verify-browser.cjs")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "node", script)
	cmd.Env = append(os.Environ(), "GONET_SNMP_TEST_URL="+server.URL, "GONET_SNMP_TEST_COOKIE="+cookie.Name+"="+cookie.Value)
	result, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, result)
	}
	t.Log(string(result))
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := cfg.ResolveProfile(cfg.SNMP.DefaultProfile)
	if err != nil || p.Community != "fixture-snmp-after-2026" {
		t.Fatal("browser credential did not persist", err)
	}
}
