package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gonet/internal/model"
)

func writeCollectConfig(t *testing.T, port int) string {
	t.Helper()
	yaml := fmt.Sprintf(`version: 1
discovery:
  seeds: [127.0.0.1]
  management_cidrs: [127.0.0.1/32]
  max_depth: 0
  max_devices: 10
  max_targets: 10
  workers: 1
  run_timeout: 1m
  max_addresses_per_device: 1
snmp:
  port: %d
  default_profile: lab
  timeout: 100ms
  retries: 0
  device_timeout: 2s
  max_repetitions: 20
  max_pdus_per_device: 100
  max_neighbors_per_device: 100
  consistency_retries: 0
  startup_grace: 0s
  view_verified: false
  profiles:
    lab:
      version: 2c
      community_env: GONET_TEST_COMMUNITY
  profile_rules: []
identity:
  allow_network_address_chassis: false
logging:
  level: error
  format: json
`, port)
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCollectMissingFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := Run([]string{"collect"}, &out, &errOut); code != ExitUsage {
		t.Errorf("exit = %d, want %d", code, ExitUsage)
	}
}

func TestCollectTargetOutOfScope(t *testing.T) {
	t.Setenv("GONET_TEST_COMMUNITY", "x")
	cfg := writeCollectConfig(t, 161)
	var out, errOut bytes.Buffer
	code := Run([]string{"collect", "--config", cfg, "--target", "192.0.2.1", "--output", "-"}, &out, &errOut)
	if code != ExitUsage {
		t.Errorf("exit = %d, want %d (out of scope)", code, ExitUsage)
	}
	if !strings.Contains(errOut.String(), "management_cidrs") {
		t.Errorf("stderr = %q, want management_cidrs mention", errOut.String())
	}
}

func TestCollectUnreachable(t *testing.T) {
	t.Setenv("GONET_TEST_COMMUNITY", "x")
	cfg := writeCollectConfig(t, 60999) // closed local UDP port
	var out, errOut bytes.Buffer
	code := Run([]string{"collect", "--config", cfg, "--target", "127.0.0.1", "--output", "-"}, &out, &errOut)
	if code != ExitNoResult {
		t.Errorf("exit = %d, want %d (no usable snapshot)", code, ExitNoResult)
	}
}

func TestCollectExitCode(t *testing.T) {
	if code := collectExitCode(nil); code != ExitNoResult {
		t.Errorf("nil snapshot = %d, want %d", code, ExitNoResult)
	}
	complete := &model.DeviceSnapshot{CollectionComplete: true, SnapshotStable: true}
	if code := collectExitCode(complete); code != ExitOK {
		t.Errorf("complete snapshot = %d, want %d", code, ExitOK)
	}
	partial := &model.DeviceSnapshot{CollectionComplete: false}
	if code := collectExitCode(partial); code != ExitPartial {
		t.Errorf("partial snapshot = %d, want %d", code, ExitPartial)
	}
	if code := collectExitCode(&model.DeviceSnapshot{CollectionComplete: true, SnapshotStable: false}); code != ExitPartial {
		t.Fatal("unstable snapshot must report partial")
	}
}

func TestWriteJSONStdout(t *testing.T) {
	var buf bytes.Buffer
	if err := writeJSON("-", false, map[string]int{"a": 1}, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"a": 1`) {
		t.Errorf("stdout = %q", buf.String())
	}
}

func TestWriteJSONRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "snap.json")
	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(p, false, map[string]int{"a": 1}, nil); err == nil {
		t.Fatal("expected refusal to overwrite existing file")
	}
	if data, _ := os.ReadFile(p); string(data) != "old" {
		t.Errorf("file changed despite refusal: %q", string(data))
	}
}

func TestWriteJSONOverwrite(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "snap.json")
	if err := os.WriteFile(p, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(p, true, map[string]int{"a": 1}, nil); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	if !strings.Contains(string(data), `"a": 1`) {
		t.Errorf("file = %q, want new content", string(data))
	}
}
