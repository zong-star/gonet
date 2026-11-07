package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad addr %q: %v", s, err)
	}
	return a
}

const validYAML = `
version: 1
database:
  dsn_env: GONET_DATABASE_URL
  statement_timeout: 30s
discovery:
  seeds: [10.201.109.1]
  management_cidrs: [10.201.109.0/24]
  max_depth: 8
  max_devices: 200
  max_targets: 600
  workers: 8
  run_timeout: 15m
  max_addresses_per_device: 3
snmp:
  port: 161
  default_profile: lab_v2c
  timeout: 3s
  retries: 1
  device_timeout: 45s
  max_repetitions: 20
  max_pdus_per_device: 500
  max_neighbors_per_device: 4096
  consistency_retries: 1
  startup_grace: 180s
  view_verified: false
  profiles:
    lab_v2c:
      version: 2c
      community_env: GONET_SNMP_COMMUNITY
  profile_rules: []
identity:
  allow_network_address_chassis: false
  overrides: []
  address_overrides: []
classification:
  rules_file: config/device_rules.yaml
ports:
  rules_file: config/port_rules.yaml
  overrides: []
logging:
  level: info
  format: json
`

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	c, err := Load(writeTemp(t, validYAML))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if c.SNMP.Timeout.Duration.String() != "3s" {
		t.Errorf("timeout = %v, want 3s", c.SNMP.Timeout.Duration)
	}
	if c.SNMP.DefaultProfile != "lab_v2c" {
		t.Errorf("default_profile = %q", c.SNMP.DefaultProfile)
	}
	if c.Discovery.Workers != 8 {
		t.Errorf("workers = %d", c.Discovery.Workers)
	}
	if c.History.KeepScans != 500 {
		t.Fatal("default history limit must be 500")
	}
}

func TestHistoryRetentionValidationAndDigest(t *testing.T) {
	c, err := Load(writeTemp(t, validYAML))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := c.ConfigDigest()
	c.History.KeepScans = 300
	if err = c.Validate(); err != nil {
		t.Fatal(err)
	}
	after, _ := c.ConfigDigest()
	if before == after {
		t.Fatal("retention policy was missing from config digest")
	}
	for _, n := range []int{-1, 1, 100001} {
		c.History.KeepScans = n
		if c.Validate() == nil {
			t.Fatal("invalid history limit accepted", n)
		}
	}
}

func TestExcludedCIDRsOverrideAllowAndAffectDigest(t *testing.T) {
	c, e := Load(writeTemp(t, validYAML))
	if e != nil {
		t.Fatal(e)
	}
	before, _ := c.ConfigDigest()
	c.Discovery.ExcludedCIDRs = []string{"10.201.109.10/32"}
	if e = c.Validate(); e != nil {
		t.Fatal(e)
	}
	after, _ := c.ConfigDigest()
	if c.InManagementScope(mustAddr(t, "10.201.109.10")) || !c.InManagementScope(mustAddr(t, "10.201.109.11")) || before == after {
		t.Fatal("exclusion ignored by scope or digest")
	}
}

func TestLoadUnknownFieldFails(t *testing.T) {
	bad := strings.Replace(validYAML, "max_depth: 8", "max_depth: 8\n  bogus_field: 1", 1)
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("Load() with unknown field: expected error, got nil")
	}
}

func TestLoadWrongVersionFails(t *testing.T) {
	bad := strings.Replace(validYAML, "version: 1", "version: 2", 1)
	if _, err := Load(writeTemp(t, bad)); err == nil {
		t.Fatal("Load() with version 2: expected error, got nil")
	}
}

func TestResolveProfileMissingSecret(t *testing.T) {
	t.Setenv("GONET_SNMP_COMMUNITY", "")
	c, err := Load(writeTemp(t, validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ResolveProfile("lab_v2c"); err == nil || !strings.Contains(err.Error(), "SECRET_MISSING") {
		t.Fatalf("ResolveProfile() = %v, want SECRET_MISSING", err)
	}
}

func TestResolveProfileSecret(t *testing.T) {
	t.Setenv("GONET_SNMP_COMMUNITY", "s3cret")
	c, err := Load(writeTemp(t, validYAML))
	if err != nil {
		t.Fatal(err)
	}
	p, err := c.ResolveProfile("lab_v2c")
	if err != nil {
		t.Fatalf("ResolveProfile() error = %v", err)
	}
	if p.Community != "s3cret" {
		t.Errorf("community = %q", p.Community)
	}
}

func TestResolveProfileForAddr(t *testing.T) {
	y := strings.Replace(validYAML,
		"profile_rules: []",
		"profile_rules:\n    - cidr: 10.201.109.0/24\n      profile: lab_v2c", 1)
	c, err := Load(writeTemp(t, y))
	if err != nil {
		t.Fatal(err)
	}
	name, err := c.ResolveProfileForAddr(mustAddr(t, "10.201.109.5"))
	if err != nil {
		t.Fatal(err)
	}
	if name != "lab_v2c" {
		t.Errorf("profile = %q, want lab_v2c", name)
	}
}

func TestInManagementScope(t *testing.T) {
	c, err := Load(writeTemp(t, validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if !c.InManagementScope(mustAddr(t, "10.201.109.1")) {
		t.Error("InManagementScope(10.201.109.1) = false, want true")
	}
	if c.InManagementScope(mustAddr(t, "192.0.2.1")) {
		t.Error("InManagementScope(192.0.2.1) = true, want false")
	}
}

func TestRejectMultipleYAMLDocuments(t *testing.T) {
	if _, err := Load(writeTemp(t, validYAML+"\n---\nversion: 2\n")); err == nil {
		t.Fatal("second YAML document ignored")
	}
}

func TestRejectConflictingProfileRulesAtLoad(t *testing.T) {
	y := strings.Replace(validYAML, "profile_rules: []", "profile_rules:\n    - {cidr: 192.0.2.0/24, profile: lab_v2c}\n    - {cidr: 192.0.2.1/24, profile: other}", 1)
	y = strings.Replace(y, "profiles:", "profiles:\n    other: {version: 2c, community_env: OTHER}", 1)
	if _, err := Load(writeTemp(t, y)); err == nil {
		t.Fatal("equal-prefix conflict ignored")
	}
}

func TestDigestIncludesRuleContentAndOverrides(t *testing.T) {
	c, err := Load(writeTemp(t, validYAML))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "rules.yaml")
	c.Classification.RulesFile = path
	c.Ports.RulesFile = ""
	if err := os.WriteFile(path, []byte("version: 1\nrules: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	first, _ := c.ConfigDigest()
	if err := os.WriteFile(path, []byte("version: 1\nrules: []\n# new rule version\n"), 0600); err != nil {
		t.Fatal(err)
	}
	second, _ := c.ConfigDigest()
	c.Identity.AllowNetworkAddressChassis = true
	third, _ := c.ConfigDigest()
	if first == second || second == third {
		t.Fatal("digest omitted rules or identity configuration")
	}
	t.Setenv("GONET_SNMP_COMMUNITY", "rotated-secret")
	fourth, _ := c.ConfigDigest()
	if third != fourth {
		t.Fatal("digest included secret values")
	}
}
