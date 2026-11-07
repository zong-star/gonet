package control

import (
	"gonet/internal/config"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectionFrequencyPersistence(t *testing.T) {
	original, e := os.ReadFile("../../config/config.example.yaml")
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	scopePath := filepath.Join(dir, "scope.json")
	if e = os.WriteFile(path, original, 0600); e != nil {
		t.Fatal(e)
	}
	s := Scope{Version: 1, Settings: Settings{Seeds: []string{"192.0.2.1"}, AllowedCIDRs: []string{"192.0.2.0/24"}, ReadManagement: true}}
	for _, i := range []CollectionInterval{{7, "minute"}, {2, "hour"}, {3, "day"}, {4, "minute"}} {
		s.Settings.CollectionInterval = &i
		if e = SavePolicy(path, scopePath, &s); e != nil {
			t.Fatal(e)
		}
		cfg, e := config.Load(path)
		if e != nil {
			t.Fatal(e)
		}
		want, _ := i.Duration()
		if cfg.InterfaceStatus.Interval.Duration != want || cfg.InterfaceStatus.StaleAfter.Duration != 3*want {
			t.Fatalf("wrong effective frequency: %+v", cfg.InterfaceStatus)
		}
		loaded, e := LoadScope(scopePath)
		if e != nil || *loaded.Settings.CollectionInterval != i {
			t.Fatal("unit not persisted", e)
		}
	}
	// Omitting the new property from an old client must preserve its configuration.
	s.Settings.CollectionInterval = nil
	if e = SavePolicy(path, scopePath, &s); e != nil {
		t.Fatal(e)
	}
	cfg, _ := config.Load(path)
	if cfg.InterfaceStatus.Interval.Duration != 4*time.Minute {
		t.Fatal("old payload reset frequency")
	}
	before, _ := os.ReadFile(path)
	for _, i := range []CollectionInterval{{0, "minute"}, {-1, "hour"}, {1, "second"}, {1 << 62, "day"}} {
		s.Settings.CollectionInterval = &i
		if e = SavePolicy(path, scopePath, &s); e == nil {
			t.Fatal("invalid frequency saved", i)
		}
		after, _ := os.ReadFile(path)
		if string(before) != string(after) {
			t.Fatal("invalid save changed configuration")
		}
	}
	s.Settings.CollectionInterval = &CollectionInterval{Value: 120, Unit: "minute"}
	SyncCollectionInterval(&s.Settings, 2*time.Hour)
	if s.Settings.CollectionInterval.Unit != "minute" {
		t.Fatal("operator unit lost")
	}
	SyncCollectionInterval(&s.Settings, 24*time.Hour)
	if s.Settings.CollectionInterval.Unit != "day" || s.Settings.CollectionInterval.Value != 1 {
		t.Fatal("effective config not reflected")
	}
}
