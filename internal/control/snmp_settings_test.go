package control

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gonet/internal/config"
)

func snmpPolicyFixture(t *testing.T) (string, string, *Scope) {
	t.Helper()
	dir := t.TempDir()
	raw, err := os.ReadFile("../../config/config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	scope := &Scope{Version: 1, Settings: Settings{Seeds: []string{"192.0.2.1"}, AllowedCIDRs: []string{"192.0.2.0/24"}, ReadManagement: true}}
	return path, filepath.Join(dir, "scope.json"), scope
}

func TestSNMPCommunityPersistsWithoutPublicLeakAndBlankKeepsIt(t *testing.T) {
	path, scopePath, s := snmpPolicyFixture(t)
	const secret = "fixture-private-community-2026"
	var wire Settings
	if err := json.Unmarshal([]byte(`{"snmp":{"version":"2c","community":"`+secret+`"}}`), &wire); err != nil {
		t.Fatal(err)
	}
	s.Settings.SNMP = wire.SNMP
	if err := SavePolicy(path, scopePath, s); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := cfg.ResolveProfile(cfg.SNMP.DefaultProfile)
	if err != nil || p.Community != secret || !cfg.Discovery.Preprobe.Enabled {
		t.Fatal("new credential not active", err)
	}
	for _, file := range []string{path, scopePath} {
		raw, err := os.ReadFile(file)
		if err != nil || bytes.Contains(raw, []byte(secret)) {
			t.Fatal("secret leaked to public configuration", file, err)
		}
	}
	public, _ := json.Marshal(s.Settings)
	summary, _ := json.Marshal(cfg.SanitizedSummary())
	if bytes.Contains(public, []byte(secret)) || bytes.Contains(summary, []byte(secret)) {
		t.Fatal("secret leaked to state/scan summary")
	}
	s.Settings.SNMP = &SNMPSettings{Version: "2c"}
	if err = SavePolicy(path, scopePath, s); err != nil {
		t.Fatal(err)
	}
	cfg, _ = config.Load(path)
	p, err = cfg.ResolveProfile(cfg.SNMP.DefaultProfile)
	if err != nil || p.Community != secret {
		t.Fatal("blank field erased stored credential", err)
	}
	SyncSNMPSettings(&s.Settings, cfg)
	if !s.Settings.SNMP.CommunityConfigured || s.Settings.SNMP.Community != "" {
		t.Fatal("public state does not mask credential")
	}
}

func TestSNMPFailedScopeSaveRestoresCredentialAndConfiguration(t *testing.T) {
	path, scopePath, s := snmpPolicyFixture(t)
	s.Settings.SNMP = &SNMPSettings{Version: "2c", Community: "fixture-original"}
	if err := SavePolicy(path, scopePath, s); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	s.Settings.SNMP = &SNMPSettings{Version: "2c", Community: "fixture-replacement"}
	if err := SavePolicy(path, filepath.Dir(path), s); err == nil {
		t.Fatal("invalid scope path accepted")
	}
	after, _ := os.ReadFile(path)
	cfg, _ := config.Load(path)
	p, err := cfg.ResolveProfile(cfg.SNMP.DefaultProfile)
	if !bytes.Equal(before, after) || err != nil || p.Community != "fixture-original" {
		t.Fatal("partial settings save changed working credential", err)
	}
}

func TestSNMPSettingsValidationAndLegacyRequests(t *testing.T) {
	for _, input := range []string{`{"version":"3"}`, `{"version":"2c","community":"x\ny"}`, `{"version":"2c","extra":true}`} {
		var s SNMPSettings
		err := json.Unmarshal([]byte(input), &s)
		if err == nil {
			err = s.Validate()
		}
		if err == nil {
			t.Fatal("invalid SNMP setting accepted", input)
		}
	}
	if err := (SNMPSettings{Version: "2c", Community: strings.Repeat("x", 256)}).Validate(); err == nil {
		t.Fatal("oversized community accepted")
	}
	path, scopePath, s := snmpPolicyFixture(t)
	if err := SavePolicy(path, scopePath, s); err != nil {
		t.Fatal("legacy settings request now requires SNMP fields", err)
	}
}
