package postgres

import (
	"context"
	"encoding/hex"
	"net/netip"
	"os"
	"testing"
	"time"

	"gonet/internal/discovery"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/topology"
)

var (
	lifeMAC1 = []byte{0, 0, 0, 0, 0, 1}
	lifeMAC2 = []byte{0, 0, 0, 0, 0, 2}
	lifeMAC3 = []byte{0, 0, 0, 0, 0, 3}
	lifeT0   = time.Unix(1700000000, 0).UTC()
)

func lifedev(ref model.DevRef, mac []byte, addr, name string) *identity.Device {
	return &identity.Device{
		Ref: ref, State: identity.StateVerified,
		StrongKey:      "lldp:4:" + hex.EncodeToString(mac),
		Chassis:        model.TypedID{Subtype: 4, Raw: mac},
		SysName:        name,
		Classification: identity.Classification{Result: "switch", RuleID: "r", Reason: "r"},
		Addresses:      []identity.Address{{Addr: netip.MustParseAddr(addr), State: identity.AddrVerified, Source: "seed"}},
		FirstSeen:      lifeT0, LastSeen: lifeT0,
	}
}

func lifeport(ref model.PortRef, dev model.DevRef, key string, ifIndex int32) *topology.Port {
	i := ifIndex
	return &topology.Port{
		Ref: ref, Device: dev, Key: topology.PortKey(key), Subtype: 5, RawID: []byte(key),
		DisplayName: key, IfIndex: &i, Resolution: topology.PortVerified, Physical: true,
		MappingRule: "ifname-exact", FirstSeen: lifeT0, LastSeen: lifeT0,
	}
}

func lifeoutcome(dev model.DevRef, addr string, depth int, eligible bool, now time.Time) model.ScanOutcome {
	return model.ScanOutcome{
		Device: dev,
		Target: model.DiscoveryTarget{Address: netip.MustParseAddr(addr), Depth: depth},
		Snapshot: &model.DeviceSnapshot{
			CollectionComplete: true, SnapshotStable: true, AbsenceEligible: eligible, CollectedAt: now,
		},
	}
}

func lifeobs(observer model.DevRef, local model.PortRef, remote model.DevRef, remotePort model.PortRef, now time.Time) model.LinkObservation {
	return model.LinkObservation{
		Observer: observer, LocalPort: local, Remote: remote, RemotePort: remotePort,
		Row: model.NeighborIndex{TimeMark: 1, LocalPortNum: uint32(local), RemoteIndex: 1},
		At:  now,
	}
}

func lifelink(a model.DevRef, pa model.PortRef, b model.DevRef, pb model.PortRef, both bool, now time.Time) model.LinkEvidence {
	return model.LinkEvidence{
		Key:       model.LinkKey{A: a, PA: pa, B: b, PB: pb},
		SeenFromA: true, SeenFromB: both, FirstAt: now, LastAt: now,
	}
}

func lifeResult(status string, devs []*identity.Device, ports []*topology.Port,
	outcomes []model.ScanOutcome, links []model.LinkEvidence, obs []model.LinkObservation) *discovery.Result {
	return &discovery.Result{
		Status: status, Devices: devs, Ports: ports, Outcomes: outcomes, Links: links, Observations: obs,
	}
}

func setupStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("GONET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("GONET_TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	resetDB(t, s.Conn())
	if _, err := Migrate(ctx, s.Conn()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { _ = s.Close(ctx) })
	return s
}

func commitRound(t *testing.T, s *Store, r *discovery.Result) int64 {
	t.Helper()
	ctx := context.Background()
	scanID, err := s.BeginScan(ctx, ScanInput{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ConfigDigest: "d"})
	if err != nil {
		t.Fatalf("begin scan: %v", err)
	}
	if err := s.CommitResult(ctx, scanID, r); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return scanID
}

type linkRow struct {
	ID            int64
	Miss          int
	State         string
	Confidence    string
	LastSeenScan  int64
	LastEvaluated int64
	LastSeenAt    time.Time
}

func readLink(t *testing.T, s *Store) linkRow {
	t.Helper()
	var l linkRow
	err := s.Conn().QueryRow(context.Background(), `SELECT id, missed_complete_scans, discovery_state,
		confidence, last_seen_scan_id, last_evaluated_scan_id, last_seen_at FROM links`).
		Scan(&l.ID, &l.Miss, &l.State, &l.Confidence, &l.LastSeenScan, &l.LastEvaluated, &l.LastSeenAt)
	if err != nil {
		t.Fatalf("read link: %v", err)
	}
	return l
}

func assertLink(t *testing.T, s *Store, wantMiss int, wantState string) linkRow {
	t.Helper()
	l := readLink(t, s)
	if l.Miss != wantMiss || l.State != wantState {
		t.Fatalf("link miss/state = %d/%s, want %d/%s", l.Miss, l.State, wantMiss, wantState)
	}
	return l
}

func twoDevices() ([]*identity.Device, []*topology.Port) {
	return []*identity.Device{
		lifedev(1, lifeMAC1, "192.0.2.1", "A"),
		lifedev(2, lifeMAC2, "192.0.2.2", "B"),
	}, []*topology.Port{
		lifeport(1, 1, "P1", 101),
		lifeport(2, 2, "P1", 201),
	}
}

// S01: three eligible miss rounds -> miss 1/2/3, suspect/suspect/stale.
func TestS01MissAccumulation(t *testing.T) {
	s := setupStore(t)
	devs, ports := twoDevices()

	r0 := lifeResult("completed", devs, ports,
		[]model.ScanOutcome{lifeoutcome(1, "192.0.2.1", 0, true, lifeT0), lifeoutcome(2, "192.0.2.2", 1, true, lifeT0)},
		[]model.LinkEvidence{lifelink(1, 1, 2, 2, true, lifeT0)},
		[]model.LinkObservation{lifeobs(1, 1, 2, 2, lifeT0), lifeobs(2, 2, 1, 1, lifeT0)})
	commitRound(t, s, r0)
	assertLink(t, s, 0, "active")

	for i := 1; i <= 3; i++ {
		now := lifeT0.Add(time.Duration(i) * time.Minute)
		r := lifeResult("completed", devs, ports,
			[]model.ScanOutcome{lifeoutcome(1, "192.0.2.1", 0, true, now), lifeoutcome(2, "192.0.2.2", 1, true, now)},
			nil, nil)
		commitRound(t, s, r)
		wantState := "suspect_stale"
		if i >= 3 {
			wantState = "stale"
		}
		assertLink(t, s, i, wantState)
	}
}

// S02: one end ineligible freezes miss and state, and does not refresh time.
func TestS02FreezeOnIneligible(t *testing.T) {
	s := setupStore(t)
	devs, ports := twoDevices()

	commitRound(t, s, lifeResult("completed", devs, ports,
		[]model.ScanOutcome{lifeoutcome(1, "192.0.2.1", 0, true, lifeT0), lifeoutcome(2, "192.0.2.2", 1, true, lifeT0)},
		[]model.LinkEvidence{lifelink(1, 1, 2, 2, true, lifeT0)},
		[]model.LinkObservation{lifeobs(1, 1, 2, 2, lifeT0), lifeobs(2, 2, 1, 1, lifeT0)}))
	before := assertLink(t, s, 0, "active")

	commitRound(t, s, lifeResult("completed", devs, ports,
		[]model.ScanOutcome{lifeoutcome(1, "192.0.2.1", 0, true, lifeT0.Add(time.Minute)),
			lifeoutcome(2, "192.0.2.2", 1, false, lifeT0.Add(time.Minute))},
		nil, nil))
	after := readLink(t, s)
	if after.Miss != 0 || after.State != "active" {
		t.Errorf("frozen link miss/state = %d/%s, want 0/active", after.Miss, after.State)
	}
	if !after.LastSeenAt.Equal(before.LastSeenAt) {
		t.Errorf("frozen link last_seen_at changed: %v -> %v", before.LastSeenAt, after.LastSeenAt)
	}
}

// S03: a partial round still ages a link whose both endpoints are eligible,
// while another link with an ineligible endpoint stays frozen.
func TestS03PartialRoundAgesEligibleOnly(t *testing.T) {
	s := setupStore(t)
	devs := []*identity.Device{
		lifedev(1, lifeMAC1, "192.0.2.1", "A"),
		lifedev(2, lifeMAC2, "192.0.2.2", "B"),
		lifedev(3, lifeMAC3, "192.0.2.3", "C"),
	}
	ports := []*topology.Port{
		lifeport(1, 1, "P1", 101),
		lifeport(2, 2, "P1", 201),
		lifeport(3, 3, "P1", 301),
		lifeport(5, 2, "P2", 202),
	}
	commitRound(t, s, lifeResult("completed", devs, ports,
		[]model.ScanOutcome{
			lifeoutcome(1, "192.0.2.1", 0, true, lifeT0),
			lifeoutcome(2, "192.0.2.2", 1, true, lifeT0),
			lifeoutcome(3, "192.0.2.3", 1, true, lifeT0),
		},
		[]model.LinkEvidence{
			lifelink(1, 1, 2, 2, true, lifeT0),
			lifelink(2, 5, 3, 3, true, lifeT0),
		},
		[]model.LinkObservation{
			lifeobs(1, 1, 2, 2, lifeT0), lifeobs(2, 2, 1, 1, lifeT0),
			lifeobs(2, 5, 3, 3, lifeT0), lifeobs(3, 3, 2, 5, lifeT0),
		}))

	// Partial round: A and B eligible, C not eligible.
	commitRound(t, s, lifeResult("partial", devs, ports,
		[]model.ScanOutcome{
			lifeoutcome(1, "192.0.2.1", 0, true, lifeT0.Add(time.Minute)),
			lifeoutcome(2, "192.0.2.2", 1, true, lifeT0.Add(time.Minute)),
			lifeoutcome(3, "192.0.2.3", 1, false, lifeT0.Add(time.Minute)),
		}, nil, nil))

	rows, err := s.Conn().Query(context.Background(),
		`SELECT missed_complete_scans, discovery_state FROM links ORDER BY device_a_id, port_a_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type row struct {
		miss  int
		state string
	}
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.miss, &r.state); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	if len(got) != 2 {
		t.Fatalf("links = %d, want 2", len(got))
	}
	// A-B: both eligible -> miss 1; B-C: C ineligible -> frozen 0.
	if got[0].miss != 1 || got[0].state != "suspect_stale" {
		t.Errorf("A-B = %+v, want miss 1 suspect_stale", got[0])
	}
	if got[1].miss != 0 || got[1].state != "active" {
		t.Errorf("B-C = %+v, want miss 0 active (frozen)", got[1])
	}
}

// S04: a stale link re-observed from only one side becomes active with
// miss=0, single_sided confidence and the same link id.
func TestS04StaleRecoversSingleSided(t *testing.T) {
	s := setupStore(t)
	devs, ports := twoDevices()
	commitRound(t, s, lifeResult("completed", devs, ports,
		[]model.ScanOutcome{lifeoutcome(1, "192.0.2.1", 0, true, lifeT0), lifeoutcome(2, "192.0.2.2", 1, true, lifeT0)},
		[]model.LinkEvidence{lifelink(1, 1, 2, 2, true, lifeT0)},
		[]model.LinkObservation{lifeobs(1, 1, 2, 2, lifeT0), lifeobs(2, 2, 1, 1, lifeT0)}))
	original := readLink(t, s)

	for i := 1; i <= 3; i++ {
		now := lifeT0.Add(time.Duration(i) * time.Minute)
		commitRound(t, s, lifeResult("completed", devs, ports,
			[]model.ScanOutcome{lifeoutcome(1, "192.0.2.1", 0, true, now), lifeoutcome(2, "192.0.2.2", 1, true, now)},
			nil, nil))
	}
	assertLink(t, s, 3, "stale")

	now := lifeT0.Add(4 * time.Minute)
	commitRound(t, s, lifeResult("completed", devs, ports,
		[]model.ScanOutcome{lifeoutcome(1, "192.0.2.1", 0, true, now), lifeoutcome(2, "192.0.2.2", 1, true, now)},
		[]model.LinkEvidence{lifelink(1, 1, 2, 2, false, now)},
		[]model.LinkObservation{lifeobs(1, 1, 2, 2, now)}))

	after := readLink(t, s)
	if after.ID != original.ID {
		t.Errorf("link id changed on recovery: %d -> %d", original.ID, after.ID)
	}
	if after.State != "active" || after.Miss != 0 || after.Confidence != "single_sided" {
		t.Errorf("recovered link = state %s miss %d confidence %s, want active/0/single_sided",
			after.State, after.Miss, after.Confidence)
	}
}

// S05: when the remote device is no longer scanned, its old link is frozen
// rather than aged or re-discovered from the database.
func TestS05UncoveredRemoteFreezes(t *testing.T) {
	s := setupStore(t)
	devs, ports := twoDevices()
	commitRound(t, s, lifeResult("completed", devs, ports,
		[]model.ScanOutcome{lifeoutcome(1, "192.0.2.1", 0, true, lifeT0), lifeoutcome(2, "192.0.2.2", 1, true, lifeT0)},
		[]model.LinkEvidence{lifelink(1, 1, 2, 2, true, lifeT0)},
		[]model.LinkObservation{lifeobs(1, 1, 2, 2, lifeT0), lifeobs(2, 2, 1, 1, lifeT0)}))

	// Only A is scanned this round; B has no scan_device row.
	commitRound(t, s, lifeResult("completed", []*identity.Device{devs[0]}, []*topology.Port{ports[0]},
		[]model.ScanOutcome{lifeoutcome(1, "192.0.2.1", 0, true, lifeT0.Add(time.Minute))},
		nil, nil))

	assertLink(t, s, 0, "active")
}

// P05: a crashed run leaves a running row; the next lock holder aborts it and
// never ages links from it.
func TestP05CrashRecovery(t *testing.T) {
	s := setupStore(t)
	devs, ports := twoDevices()
	commitRound(t, s, lifeResult("completed", devs, ports,
		[]model.ScanOutcome{lifeoutcome(1, "192.0.2.1", 0, true, lifeT0), lifeoutcome(2, "192.0.2.2", 1, true, lifeT0)},
		[]model.LinkEvidence{lifelink(1, 1, 2, 2, true, lifeT0)},
		[]model.LinkObservation{lifeobs(1, 1, 2, 2, lifeT0), lifeobs(2, 2, 1, 1, lifeT0)}))
	assertLink(t, s, 0, "active")

	// Simulate a crash: a running scan row with no commit, then the session ends.
	ctx := context.Background()
	crashID, err := s.BeginScan(ctx, ScanInput{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ConfigDigest: "d"})
	if err != nil {
		t.Fatalf("begin crash scan: %v", err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatalf("close crashed session: %v", err)
	}

	// A new session recovers: it aborts the stale running scan.
	dsn := os.Getenv("GONET_TEST_DATABASE_URL")
	s2, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close(ctx)
	if _, err := s2.BeginScan(ctx, ScanInput{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ConfigDigest: "d"}); err != nil {
		t.Fatalf("recovery begin: %v", err)
	}

	var status string
	if err := s2.Conn().QueryRow(ctx, "SELECT status FROM scan_runs WHERE id=$1", crashID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "aborted" {
		t.Errorf("crashed scan status = %q, want aborted", status)
	}
	l := readLink(t, s2)
	if l.Miss != 0 || l.State != "active" {
		t.Errorf("link aged by aborted run: miss %d state %s, want 0/active", l.Miss, l.State)
	}
}
