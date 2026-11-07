package control

import (
	"bytes"
	"encoding/json"
	"gonet/internal/config"
	"gonet/internal/identity"
	"gonet/internal/store/postgres"
	"gonet/internal/topology"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// effectiveSet renders the addresses that the settings actually allow, bounded
// per allow range, so two settings can be compared as sets rather than by count.
func effectiveSet(s Settings, perRange int) string {
	out := []string{}
	for _, raw := range s.AllowedCIDRs {
		p, err := prefix(raw)
		if err != nil {
			continue
		}
		seen := 0
		for a := p.Addr(); p.Contains(a) && seen < perRange; a = a.Next() {
			seen++
			if s.Allows(a) {
				out = append(out, a.String())
			}
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestScopeExclusionAndBoundedSupplement(t *testing.T) {
	s := Settings{Seeds: []string{"192.0.2.1"}, AllowedCIDRs: []string{"192.0.2.0/24"}, ExcludedCIDRs: []string{"192.0.2.2/32"}, BootstrapCIDRs: []string{"192.0.2.0/29"}}
	if e := s.Validate(20); e != nil {
		t.Fatal(e)
	}
	as, e := s.BootstrapAddresses(20)
	if e != nil || len(as) != 5 {
		t.Fatalf("hosts=%v err=%v", as, e)
	}
	for _, a := range as {
		if a == netip.MustParseAddr("192.0.2.2") {
			t.Fatal("excluded address admitted")
		}
	}
	if _, err := s.BootstrapAddresses(0); err == nil {
		t.Fatal("exhausted budget accepted address probes")
	}
	s.BootstrapCIDRs = []string{"192.0.2.0/16"}
	if s.Validate(20) == nil {
		t.Fatal("unbounded supplement accepted")
	}
	s.BootstrapCIDRs = []string{"198.51.100.0/29"}
	if s.Validate(20) == nil {
		t.Fatal("supplement escaped allowed ranges")
	}
	s.BootstrapCIDRs = nil
	s.Seeds = []string{"192.0.2.2"}
	if s.Validate(20) == nil {
		t.Fatal("excluded seed accepted")
	}
}

func TestVerifiedRuleLabelsNewDevicesWithoutInventory(t *testing.T) {
	v := &View{Devices: []Device{{ExportDevice: postgres.ExportDevice{ID: 1, ClassificationRule: "legacy"}, Source: "lldp", Model: "待补充"}, {ExportDevice: postgres.ExportDevice{ID: 2, ClassificationRule: "legacy"}, Source: "inventory", Model: "operator label"}}}
	LabelModels(v, []identity.Rule{{ID: "legacy", Vendor: "Huawei", Model: "S2700-9TP-EI-AC"}})
	if v.Devices[0].Model != "S2700-9TP-EI-AC" || v.Devices[0].Vendor != "Huawei" || v.Devices[1].Model != "operator label" {
		t.Fatal("model metadata missing or inventory changed")
	}
}

func TestDeviceKindsAndPendingControllerCountSeparately(t *testing.T) {
	scope := Scope{Version: 1, Mode: "lldp", Settings: Settings{Seeds: []string{"192.0.2.1"}, AllowedCIDRs: []string{"192.0.2.0/24"}}}
	exp := &postgres.TopologyExport{Devices: []postgres.ExportDevice{{ID: 1, Kind: "switch", AccessAddresses: []string{"192.0.2.1"}}, {ID: 2, Kind: "router", AccessAddresses: []string{"192.0.2.2"}}}, PendingNodes: []topology.PendingNode{{Key: "lldp:4:020000000003", SystemName: "AC", SystemDescription: "Lab AC"}}, PendingLinks: []topology.PendingLink{{LocalDevice: 1, RemoteKey: "lldp:4:020000000003"}}}
	v := Project(exp, scope)
	LabelModels(v, []identity.Rule{{ID: "ac", SysObjectIDPrefix: "1.3.6.1.4.1.99999.1", DescriptionRegex: "^Lab AC$", Action: "wireless_controller", Model: "Lab AC"}})
	if v.Counts.Confirmed != 2 || v.Counts.Switches != 1 || v.Counts.Routers != 1 || v.Counts.Controllers != 0 || v.Counts.PendingControllers != 1 || len(v.Candidates[0].ObserverIDs) != 1 {
		t.Fatalf("pending AC was counted as confirmed or switch: %+v", v.Counts)
	}
}

func TestSavePolicyPreservesConfigAndRollsBackOnScopeFailure(t *testing.T) {
	original, err := os.ReadFile("../../config/config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	s := Scope{Version: 1, Settings: Settings{Seeds: []string{"10.201.109.2"}, AllowedCIDRs: []string{"10.201.109.0/24"}, ExcludedCIDRs: []string{"10.201.109.99"}, ReadManagement: true}}
	scopePath := filepath.Join(dir, "scope.json")
	if err = SavePolicy(path, scopePath, &s); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Discovery.Seeds) != 1 || cfg.Discovery.Seeds[0] != "10.201.109.2" || cfg.InManagementScope(netip.MustParseAddr("10.201.109.99")) || cfg.SNMP.Profiles["lab_v2c"].CommunityEnv != "GONET_SNMP_COMMUNITY" || !cfg.SNMP.CollectManagementAddresses {
		t.Fatal("saved configuration lost scope or credential references")
	}
	backup, err := os.ReadFile(filepath.Join(dir, "outputs", "backups", "config-before-ui.yaml"))
	if err != nil || !bytes.Equal(backup, original) {
		t.Fatal("original backup was not preserved")
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Settings.Seeds = []string{"10.201.109.3"}
	// A directory cannot be replaced with the JSON file: config must roll back.
	if err = SavePolicy(path, dir, &s); err == nil {
		t.Fatal("scope write unexpectedly succeeded")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, saved) {
		t.Fatal("failed policy save changed config")
	}
	stored, err := LoadScope(scopePath)
	if err != nil || stored.Settings.Seeds[0] != "10.201.109.2" {
		t.Fatal("failed save changed persisted scope")
	}
}

// The deprecated address-supplement field must be retired at the console
// normalization entry without touching anything else the user configured.
func TestRetireBootstrapOnlyClearsDeprecatedSupplement(t *testing.T) {
	s := Settings{
		Seeds:          []string{"192.0.2.1"},
		AllowedCIDRs:   []string{"192.0.2.0/24", "198.51.100.0/24"},
		ExcludedCIDRs:  []string{"192.0.2.9/32", "192.0.2.10/32"},
		BootstrapCIDRs: []string{"192.0.2.0/29", "198.51.100.4/32"},
		ReadManagement: true,
	}
	effectiveBefore := effectiveSet(s, 32)
	retired := RetireBootstrap(&s)
	if len(retired) != 2 || retired[0] != "192.0.2.0/29" || retired[1] != "198.51.100.4/32" {
		t.Fatalf("retired entries not reported in order: %v", retired)
	}
	if len(s.BootstrapCIDRs) != 0 {
		t.Fatalf("deprecated field not cleared: %v", s.BootstrapCIDRs)
	}
	if !s.ReadManagement || len(s.Seeds) != 1 || len(s.AllowedCIDRs) != 2 || len(s.ExcludedCIDRs) != 2 {
		t.Fatalf("retirement changed retained values: %+v", s)
	}
	if got := effectiveSet(s, 32); got != effectiveBefore {
		t.Fatalf("retirement changed the effective access set: %q -> %q", effectiveBefore, got)
	}
	if again := RetireBootstrap(&s); again != nil {
		t.Fatalf("retirement is not idempotent: %v", again)
	}
	if nilSettings := RetireBootstrap(nil); nilSettings != nil {
		t.Fatal("nil settings must be tolerated")
	}
}

// A legacy supplement range can make Validate fail, which used to block saving
// from the console with a field that is no longer visible anywhere.
func TestRetireBootstrapUnblocksLegacySupplementThatFailsValidation(t *testing.T) {
	s := Settings{
		Seeds:          []string{"192.0.2.1"},
		AllowedCIDRs:   []string{"192.0.2.0/24"},
		ExcludedCIDRs:  []string{},
		BootstrapCIDRs: []string{"192.0.2.0/8"},
		ReadManagement: true,
	}
	if err := s.Validate(64); err == nil {
		t.Fatal("expected the oversized legacy supplement to be rejected")
	}
	RetireBootstrap(&s)
	if err := s.Validate(64); err != nil {
		t.Fatalf("retired settings must validate: %v", err)
	}
}

// SavePolicy must keep the first pre-console copy of the scope JSON, next to the
// YAML backup, because it carries the effective range, exclusions and seeds.
func TestSavePolicyBacksUpScopeBeforeFirstOverwrite(t *testing.T) {
	original, err := os.ReadFile("../../config/config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	scopePath := filepath.Join(dir, "scope.json")
	first := Scope{Version: 1, Mode: "lldp", Settings: Settings{Seeds: []string{"192.0.2.1"}, AllowedCIDRs: []string{"192.0.2.0/24"}, ExcludedCIDRs: []string{}, ReadManagement: true}}
	if err = SavePolicy(path, scopePath, &first); err != nil {
		t.Fatal(err)
	}
	scopeBackup := filepath.Join(dir, "outputs", "backups", "scope-before-ui.json")
	if _, err = os.Stat(scopeBackup); !os.IsNotExist(err) {
		t.Fatal("no scope existed yet, so no scope backup should be written")
	}
	second := first
	second.Settings.ExcludedCIDRs = []string{"192.0.2.9/32"}
	if err = SavePolicy(path, scopePath, &second); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(scopeBackup)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := json.MarshalIndent(first, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backup, append(pre, '\n')) {
		t.Fatal("scope backup does not match the pre-save scope")
	}
	if err = SavePolicy(path, scopePath, &second); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(scopeBackup)
	if err != nil || !bytes.Equal(again, backup) {
		t.Fatal("scope backup must keep the first copy")
	}
}

func TestMigrationUsesCoreAndKeepsAccessRanges(t *testing.T) {
	scope := Scope{Version: 1, Rows: []InventoryRow{{Included: true, Address: "192.0.2.1", IdentityKeys: []string{"manual:ts7914-core-stack-01"}}, {Included: false, Address: "192.0.2.99"}}}
	cfg := &config.Config{Discovery: config.DiscoveryConfig{Seeds: []string{"192.0.2.1", "192.0.2.2"}, ManagementCIDRs: []string{"192.0.2.0/24"}}}
	scope.Migrate(cfg)
	if len(scope.Settings.Seeds) != 1 || scope.Settings.Seeds[0] != "192.0.2.1" || scope.Settings.Allows(netip.MustParseAddr("192.0.2.99")) {
		t.Fatal("migration changed seed/exclusion semantics")
	}
}
func TestNewVerifiedDeviceAppearsWithoutInventoryRow(t *testing.T) {
	depth := 1
	s := Scope{Version: 1, Mode: "lldp", Settings: Settings{Seeds: []string{"192.0.2.1"}, AllowedCIDRs: []string{"192.0.2.0/24"}, ExcludedCIDRs: []string{"192.0.2.3/32"}}, Rows: []InventoryRow{{Row: 2, Included: true, Name: "core", Address: "192.0.2.1", IdentityKeys: []string{"lldp:4:020000000001"}}}}
	exp := &postgres.TopologyExport{Devices: []postgres.ExportDevice{
		{ID: 1, IdentityKeys: []string{"lldp:4:020000000001"}, AccessAddresses: []string{"192.0.2.1"}, DiscoveryDepth: &depth},
		{ID: 2, SysName: "new", IdentityKeys: []string{"lldp:4:020000000002"}, AccessAddresses: []string{"192.0.2.2"}, DiscoveryDepth: &depth},
		{ID: 3, IdentityKeys: []string{"lldp:4:020000000003"}, AccessAddresses: []string{"192.0.2.3"}, DiscoveryDepth: &depth},
	}, Links: []postgres.ExportLink{{ID: 1, DeviceAID: 1, DeviceBID: 2}, {ID: 2, DeviceAID: 1, DeviceBID: 3}}, PendingNodes: []topology.PendingNode{{Key: "lldp:4:020000000004", SystemName: "unknown"}}, PendingLinks: []topology.PendingLink{{LocalDevice: 1, RemoteKey: "lldp:4:020000000004"}}}
	v := Project(exp, s)
	if len(v.Devices) != 2 || len(v.Links) != 1 || v.Devices[1].Name != "new" || v.Counts.Collected != 2 || v.Counts.Neighbors != 1 {
		t.Fatalf("new device lost or scope escaped: %+v", v)
	}
}
