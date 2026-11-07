package control

import (
	"gonet/internal/config"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTopologyScanFrequencyPersistence(t *testing.T) {
	raw, e := os.ReadFile("../../config/config.example.yaml")
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	scope := Scope{Version: 1, Mode: "lldp", Settings: Settings{Seeds: []string{"192.0.2.1"}, AllowedCIDRs: []string{"192.0.2.0/24"}, ReadManagement: true}}
	for _, interval := range []CollectionInterval{{0, "minute"}, {5, "minute"}, {2, "hour"}, {3, "day"}, {0, "day"}} {
		scope.Settings.TopologyScanInterval = &interval
		if e = SavePolicy(path, filepath.Join(dir, "scope.json"), &scope); e != nil {
			t.Fatal(e)
		}
		cfg, e := config.Load(path)
		if e != nil {
			t.Fatal(e)
		}
		want, _ := interval.TopologyDuration()
		if cfg.TopologyScan.Interval.Duration != want || cfg.InterfaceStatus.Interval.Duration != 4*time.Minute {
			t.Fatal("scan frequency changed the interface poll", cfg.TopologyScan)
		}
		loaded, e := LoadScope(filepath.Join(dir, "scope.json"))
		if e != nil || *loaded.Settings.TopologyScanInterval != interval {
			t.Fatal("topology unit not persisted", e)
		}
	}
	scope.Settings.TopologyScanInterval = &CollectionInterval{2, "hour"}
	if e = SavePolicy(path, filepath.Join(dir, "scope.json"), &scope); e != nil {
		t.Fatal(e)
	}
	scope.Settings.TopologyScanInterval = nil
	if e = SavePolicy(path, filepath.Join(dir, "scope.json"), &scope); e != nil {
		t.Fatal(e)
	}
	cfg, _ := config.Load(path)
	if cfg.TopologyScan.Interval.Duration != 2*time.Hour {
		t.Fatal("old settings payload disabled schedule")
	}
	before, _ := os.ReadFile(path)
	for _, invalid := range []CollectionInterval{{-1, "minute"}, {0, "second"}, {1 << 62, "day"}} {
		scope.Settings.TopologyScanInterval = &invalid
		if e = SavePolicy(path, filepath.Join(dir, "scope.json"), &scope); e == nil {
			t.Fatal("invalid scan frequency saved")
		}
		after, _ := os.ReadFile(path)
		if string(after) != string(before) {
			t.Fatal("invalid update changed config")
		}
	}
}
