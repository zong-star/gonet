package postgres

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"testing"
	"time"

	"gonet/internal/discovery"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/topology"
)

func ptr32(v int32) *int32 { return &v }

func sampleResult() *discovery.Result {
	now := time.Unix(1700000000, 0).UTC()
	dA := &identity.Device{
		Ref: 1, State: identity.StateVerified, StrongKey: "lldp:4:000000000001",
		Chassis:        model.TypedID{Subtype: 4, Raw: []byte{0, 0, 0, 0, 0, 1}},
		SysName:        "A",
		Classification: identity.Classification{Result: "switch", RuleID: "r", Reason: "r"},
		Addresses:      []identity.Address{{Addr: netip.MustParseAddr("192.0.2.1"), State: identity.AddrVerified, Source: "seed"}},
		FirstSeen:      now, LastSeen: now,
	}
	dB := &identity.Device{
		Ref: 2, State: identity.StateVerified, StrongKey: "lldp:4:000000000002",
		Chassis:        model.TypedID{Subtype: 4, Raw: []byte{0, 0, 0, 0, 0, 2}},
		SysName:        "B",
		Classification: identity.Classification{Result: "switch", RuleID: "r", Reason: "r"},
		Addresses:      []identity.Address{{Addr: netip.MustParseAddr("192.0.2.2"), State: identity.AddrVerified, Source: "lldp"}},
		FirstSeen:      now, LastSeen: now,
	}
	portA := &topology.Port{
		Ref: 1, Device: 1, Key: "lldp:5:aa", Subtype: 5, RawID: []byte{0xaa}, DisplayName: "P1",
		IfIndex: ptr32(101), Resolution: topology.PortVerified, Physical: true, MappingRule: "ifname-exact",
		FirstSeen: now, LastSeen: now,
	}
	portB := &topology.Port{
		Ref: 2, Device: 2, Key: "lldp:5:bb", Subtype: 5, RawID: []byte{0xbb}, DisplayName: "P1",
		IfIndex: ptr32(201), Resolution: topology.PortVerified, Physical: true, MappingRule: "ifname-exact",
		FirstSeen: now, LastSeen: now,
	}
	link := model.LinkEvidence{
		Key:       model.LinkKey{A: 1, PA: 1, B: 2, PB: 2},
		SeenFromA: true, SeenFromB: true, FirstAt: now, LastAt: now,
	}
	obs := model.LinkObservation{
		Observer: 1, LocalPort: 1, Remote: 2, RemotePort: 2,
		Row: model.NeighborIndex{TimeMark: 1, LocalPortNum: 1, RemoteIndex: 1},
		At:  now,
		Raw: model.LLDPNeighbor{
			Index:   model.NeighborIndex{TimeMark: 1, LocalPortNum: 1, RemoteIndex: 1},
			Chassis: model.TypedID{Subtype: 4, Raw: []byte{0, 0, 0, 0, 0, 2}},
			Port:    model.TypedID{Subtype: 5, Raw: []byte{0xbb}},
		},
	}
	return &discovery.Result{
		Status:  "completed",
		Devices: []*identity.Device{dA, dB},
		Ports:   []*topology.Port{portA, portB},
		Outcomes: []model.ScanOutcome{
			{Device: 1, Target: model.DiscoveryTarget{Address: netip.MustParseAddr("192.0.2.1"), Depth: 0},
				Snapshot: &model.DeviceSnapshot{CollectionComplete: true, SnapshotStable: true, CollectedAt: now}},
			{Device: 2, Target: model.DiscoveryTarget{Address: netip.MustParseAddr("192.0.2.2"), Depth: 1},
				Snapshot: &model.DeviceSnapshot{CollectionComplete: true, SnapshotStable: true, CollectedAt: now}},
		},
		Links:        []model.LinkEvidence{link},
		Observations: []model.LinkObservation{obs},
		Counts:       discovery.Counts{DevicesCollected: 2, LinksObserved: 1},
	}
}

func countRows(t *testing.T, s *Store, table string) int {
	t.Helper()
	var n int
	if err := s.Conn().QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// P03: a mid-transaction failure rolls back every device/port/link write, and
// the scan row can be marked failed explicitly.
func TestP03CommitRollback(t *testing.T) {
	dsn := os.Getenv("GONET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("GONET_TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close(ctx)
	resetDB(t, s.Conn())
	if _, err := Migrate(ctx, s.Conn()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	scanID, err := s.BeginScan(ctx, ScanInput{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ConfigDigest: "d"})
	if err != nil {
		t.Fatalf("begin scan: %v", err)
	}

	bad := sampleResult()
	bad.Ports[0].Subtype = 99 // violates CHECK (subtype BETWEEN 1 AND 7) mid-transaction
	if err := s.CommitResult(ctx, scanID, bad); err == nil {
		t.Fatal("CommitResult succeeded with an invalid port subtype")
	}
	for _, tbl := range []string{"devices", "device_identities", "device_addresses", "ports", "links", "observations"} {
		if n := countRows(t, s, tbl); n != 0 {
			t.Errorf("%s = %d after rollback, want 0", tbl, n)
		}
	}
	if err := s.MarkFailed(ctx, scanID, "DB_COMMIT_FAILED", "injected failure"); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	var status string
	if err := s.Conn().QueryRow(ctx, "SELECT status FROM scan_runs WHERE id=$1", scanID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "failed" {
		t.Errorf("scan status = %q, want failed", status)
	}
}

// P04: a second concurrent scan cannot take the lock; re-submitting the same
// scan id is an idempotent no-op; closing the first store releases the lock.
func TestP04IdempotentAndLock(t *testing.T) {
	dsn := os.Getenv("GONET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("GONET_TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	ctx := context.Background()
	s1, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open s1: %v", err)
	}
	s2, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open s2: %v", err)
	}
	defer s2.Close(ctx)

	resetDB(t, s1.Conn())
	if _, err := Migrate(ctx, s1.Conn()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	scanID, err := s1.BeginScan(ctx, ScanInput{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ConfigDigest: "d"})
	if err != nil {
		t.Fatalf("begin s1: %v", err)
	}

	if _, err := s2.BeginScan(ctx, ScanInput{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.2")}, ConfigDigest: "d"}); !errors.Is(err, ErrLocked) {
		t.Fatalf("second BeginScan = %v, want ErrLocked", err)
	}

	res := sampleResult()
	if err := s1.CommitResult(ctx, scanID, res); err != nil {
		t.Fatalf("commit: %v", err)
	}
	counts := map[string]int{}
	for _, tbl := range []string{"devices", "ports", "links", "observations", "scan_devices"} {
		counts[tbl] = countRows(t, s1, tbl)
	}

	if err := s1.CommitResult(ctx, scanID, res); err != nil {
		t.Fatalf("re-commit: %v", err)
	}
	for tbl, before := range counts {
		if after := countRows(t, s1, tbl); after != before {
			t.Errorf("%s changed on re-commit: %d -> %d", tbl, before, after)
		}
	}

	var status string
	if err := s1.Conn().QueryRow(ctx, "SELECT status FROM scan_runs WHERE id=$1", scanID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "completed" {
		t.Errorf("scan status = %q, want completed", status)
	}

	if err := s1.Close(ctx); err != nil {
		t.Fatalf("close s1: %v", err)
	}
	if _, err := s2.BeginScan(ctx, ScanInput{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.2")}, ConfigDigest: "d"}); err != nil {
		t.Fatalf("second scan after release: %v", err)
	}
}
