package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"gonet/internal/config"
	"gonet/internal/model"
)

// T404: a freshly migrated database can commit a full round and export the
// topology, with fresh/coverage fields and active/all filtering.
func TestE2EExportCoverage(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	commitRound(t, s, sampleResult())

	exp, err := ExportTopology(ctx, s.Conn(), "active")
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(exp.Devices) != 2 {
		t.Errorf("devices = %d, want 2", len(exp.Devices))
	}
	if len(exp.Links) != 1 {
		t.Fatalf("links = %d, want 1", len(exp.Links))
	}
	if !exp.Fresh || exp.CoverageGap {
		t.Errorf("export fresh/coverage_gap = %v/%v, want true/false", exp.Fresh, exp.CoverageGap)
	}
	if exp.LatestScanID == 0 {
		t.Error("latest_scan_id = 0, want a committed scan id")
	}
	l := exp.Links[0]
	if !l.Fresh || l.CoverageGap {
		t.Errorf("link fresh/coverage_gap = %v/%v, want true/false", l.Fresh, l.CoverageGap)
	}
	if l.Confidence != "bidirectional" || l.DiscoveryState != "active" {
		t.Errorf("link confidence/state = %s/%s", l.Confidence, l.DiscoveryState)
	}

	// Age the link to stale over three eligible absence rounds.
	devs, ports := twoDevices()
	for i := 1; i <= 3; i++ {
		now := lifeT0.Add(time.Duration(i) * time.Minute)
		commitRound(t, s, lifeResult("completed", devs, ports,
			[]model.ScanOutcome{
				lifeoutcome(1, "192.0.2.1", 0, true, now),
				lifeoutcome(2, "192.0.2.2", 1, true, now),
			}, nil, nil))
	}

	active, err := ExportTopology(ctx, s.Conn(), "active")
	if err != nil {
		t.Fatal(err)
	}
	if len(active.Links) != 0 {
		t.Errorf("active export links = %d, want 0 (stale excluded)", len(active.Links))
	}

	all, err := ExportTopology(ctx, s.Conn(), "all")
	if err != nil {
		t.Fatal(err)
	}
	if len(all.Links) != 1 {
		t.Fatalf("all export links = %d, want 1", len(all.Links))
	}
	sl := all.Links[0]
	if sl.DiscoveryState != "stale" || sl.MissedCompleteScans != 3 {
		t.Errorf("stale link = state %s miss %d, want stale/3", sl.DiscoveryState, sl.MissedCompleteScans)
	}
	if sl.Fresh || !sl.CoverageGap {
		t.Errorf("stale link fresh/coverage_gap = %v/%v, want false/true", sl.Fresh, sl.CoverageGap)
	}
	if sl.LastSeenScanID != nil && *sl.LastSeenScanID == all.LatestScanID {
		t.Error("stale link last_seen_scan_id should differ from the latest scan")
	}
}

// P06: the stored config summary and the export never contain secrets.
func TestP06NoSecretsInSummaryAndExport(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()

	secret := "SECRET-COMMUNITY-9f3a"
	t.Setenv("GONET_P06_COMMUNITY", secret)
	cfg := &config.Config{
		Version: 1,
		Discovery: config.DiscoveryConfig{
			Seeds:           []string{"192.0.2.1"},
			ManagementCIDRs: []string{"192.0.2.0/24"},
			MaxDepth:        8, MaxDevices: 200, MaxTargets: 600, Workers: 4,
		},
		SNMP: config.SNMPConfig{
			DefaultProfile: "p",
			Profiles: map[string]config.ProfileConfig{
				"p": {Version: "2c", CommunityEnv: "GONET_P06_COMMUNITY"},
			},
		},
	}
	summary, err := json.Marshal(cfg.SanitizedSummary())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(summary, []byte(secret)) {
		t.Fatal("sanitized config summary leaked the community secret")
	}

	scanID, err := s.BeginScan(ctx, ScanInput{
		Seeds:         []netip.Addr{netip.MustParseAddr("192.0.2.1")},
		ConfigDigest:  "digest",
		ConfigSummary: summary,
	})
	if err != nil {
		t.Fatalf("begin scan: %v", err)
	}
	if err := s.CommitResult(ctx, scanID, sampleResult()); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var stored []byte
	if err := s.Conn().QueryRow(ctx, "SELECT config_summary FROM scan_runs WHERE id=$1", scanID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte(secret)) {
		t.Error("stored config_summary leaked the community secret")
	}

	exp, err := ExportTopology(ctx, s.Conn(), "all")
	if err != nil {
		t.Fatal(err)
	}
	exported, err := json.Marshal(exp)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{secret, "GONET_P06_COMMUNITY"} {
		if bytes.Contains(exported, []byte(leak)) {
			t.Errorf("export leaked %q", leak)
		}
	}
}
