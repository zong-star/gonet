package postgres

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5"
	"gonet/internal/model"
	"gonet/internal/topology"
	"net/url"
	"os"
	"testing"
	"time"
)

// This opt-in test uses a fresh private schema in the existing service. It
// never calls resetDB or drops public; ordinary destructive DB tests stay off.
func TestNoIPIsolatedSchemaPersistence(t *testing.T) {
	dsn := os.Getenv("GONET_ISOLATED_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated schema database URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal("database connection failed")
	}
	defer admin.Close(context.Background())
	schema := fmt.Sprintf("gonet_test_noip_%d", time.Now().UnixNano())
	ident := pgx.Identifier{schema}.Sanitize()
	if _, e = admin.Exec(ctx, "CREATE SCHEMA "+ident); e != nil {
		t.Fatal(e)
	}
	defer func() {
		cleanup, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		if _, e := admin.Exec(cleanup, "DROP SCHEMA "+ident+" CASCADE"); e != nil {
			t.Errorf("private test schema cleanup: %v", e)
		}
	}()
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal("URL required")
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	s, e := Open(ctx, u.String())
	if e != nil {
		t.Fatal("isolated store connection failed")
	}
	defer s.Close(context.Background())
	if _, e = Migrate(ctx, s.Conn()); e != nil {
		t.Fatal(e)
	}
	if versions, e := Migrate(ctx, s.Conn()); e != nil || len(versions) != 0 {
		t.Fatal("migration not idempotent")
	}
	r := sampleResult()
	r.Devices[0].IdentityKeys = []string{"lldp:7:000000000001"}
	n := model.LLDPNeighbor{Index: model.NeighborIndex{TimeMark: 0, LocalPortNum: 1, RemoteIndex: 3061629953}, Chassis: model.TypedID{Subtype: 7, Raw: []byte("02:00:00:00:00:88")}, Port: model.TypedID{Subtype: 5, Raw: []byte("Gi0/1")}, SysName: "unknown-no-address"}
	r.Unresolved = []topology.UnresolvedObservation{{Observer: 1, Row: n.Index, Raw: n, Reason: "remote identity unresolved; no access address", At: time.Now()}}
	var lastID int64
	for i := 0; i < 2; i++ {
		id, e := s.BeginScan(ctx, ScanInput{Seeds: nil, ConfigDigest: "no-ip-test"})
		if e != nil {
			t.Fatal(e)
		}
		if e = s.CommitResult(ctx, id, r); e != nil {
			t.Fatal(e)
		}
		lastID = id
	}
	exp, e := ExportTopology(ctx, s.Conn(), "all")
	if e != nil {
		t.Fatal(e)
	}
	if len(exp.Devices) != 2 || len(exp.Links) != 1 || len(exp.PendingNodes) != 1 || len(exp.PendingLinks) != 1 || exp.PendingNodes[0].SystemName != "unknown-no-address" || !exp.CoverageGap {
		t.Fatalf("pending topology persistence lost: %+v", exp)
	}
	var max uint64
	if e = s.Conn().QueryRow(ctx, `SELECT max(remote_index) FROM observations WHERE scan_id=$1`, lastID).Scan(&max); e != nil || max != 3061629953 {
		t.Fatalf("uint32 index lost: %d error=%v", max, e)
	}
	if countRows(t, s, "devices") != 2 || countRows(t, s, "links") != 1 {
		t.Fatal("repeated rounds duplicated physical graph")
	}
	commit := func() {
		id, e := s.BeginScan(ctx, ScanInput{ConfigDigest: "lifecycle-no-ip"})
		if e != nil {
			t.Fatal(e)
		}
		if e = s.CommitResult(ctx, id, r); e != nil {
			t.Fatal(e)
		}
	}
	// Losing one direction retains the same physical link as single-sided.
	r.Links[0].SeenFromB = false
	commit()
	exp, e = ExportTopology(ctx, s.Conn(), "all")
	if e != nil || len(exp.Links) != 1 || exp.Links[0].Confidence != "single_sided" {
		t.Fatal("single-sided evidence was lost")
	}
	// An offline endpoint cannot supply negative evidence; keep the old edge
	// and expose fresh=false instead of deleting it or incrementing misses.
	r.Status = "partial"
	r.Links = nil
	r.Observations = nil
	r.Counts.LinksObserved = 0
	r.Outcomes[1].Snapshot = nil
	commit()
	exp, e = ExportTopology(ctx, s.Conn(), "all")
	if e != nil || len(exp.Links) != 1 || exp.Links[0].Fresh || exp.Links[0].MissedCompleteScans != 0 {
		t.Fatal("offline endpoint aged or deleted a link")
	}
	// Three genuinely complete, qualified absent rounds mark it stale.
	r.Status = "completed"
	r.Unresolved = nil
	for i := range r.Outcomes {
		r.Outcomes[i].Snapshot = &model.DeviceSnapshot{CollectionComplete: true, SnapshotStable: true, AbsenceEligible: true, CollectedAt: time.Now()}
	}
	for i := 0; i < 3; i++ {
		commit()
	}
	exp, e = ExportTopology(ctx, s.Conn(), "all")
	if e != nil || len(exp.Links) != 1 || exp.Links[0].DiscoveryState != "stale" || exp.Links[0].MissedCompleteScans != 3 {
		t.Fatal("qualified stale lifecycle failed")
	}
	id, e := s.BeginScan(ctx, ScanInput{Seeds: nil, ConfigDigest: "context-test"})
	if e != nil {
		t.Fatal(e)
	}
	devices, _, e := s.LoadContext(ctx)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, d := range devices {
		for _, key := range d.IdentityKeys {
			if key == "lldp:7:000000000001" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("normalized alias was not restored")
	}
	if e = s.MarkFailed(ctx, id, "TEST_END", "context read finished"); e != nil {
		t.Fatal(e)
	}
	testVerifiedPlaceholderPromotion(t, s)
	testManagedKindsPersistence(t, s)
	testHistoryRetention(t, s)
}

func testManagedKindsPersistence(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	s.releaseLock(ctx)
	r := sampleResult()
	r.Devices[0].Classification.Result = "router"
	r.Devices[1].Classification.Result = "wireless_controller"
	id, err := s.BeginScan(ctx, ScanInput{ConfigDigest: "managed-kinds"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CommitResult(ctx, id, r); err != nil {
		t.Fatal(err)
	}
	exp, err := ExportTopology(ctx, s.Conn(), "all")
	if err != nil || len(exp.Devices) != 2 || exp.Devices[0].Kind != "router" || exp.Devices[1].Kind != "wireless_controller" || len(exp.Links) != 1 || !exp.Links[0].Fresh {
		t.Fatalf("managed kinds or physical link lost: %+v %v", exp, err)
	}
	id, err = s.BeginScan(ctx, ScanInput{ConfigDigest: "managed-context"})
	if err != nil {
		t.Fatal(err)
	}
	devices, _, err := s.LoadContext(ctx)
	if err != nil || len(devices) != 2 || devices[0].Classification.Result != "router" || devices[1].Classification.Result != "wireless_controller" {
		t.Fatal("restored non-switch kind was converted to switch")
	}
	if err = s.MarkFailed(ctx, id, "TEST_END", "kind context verified"); err != nil {
		t.Fatal(err)
	}
	s.releaseLock(ctx)
}

func testVerifiedPlaceholderPromotion(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	var deviceID, canonicalID int64
	if err := s.Conn().QueryRow(ctx, `SELECT d.id,p.id FROM devices d JOIN ports p ON p.device_id=d.id WHERE p.port_key='lldp:5:aa'`).Scan(&deviceID, &canonicalID); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"verified", "repeat", "scoped", "not-manual", "mapped", "linked"} {
		t.Run("placeholder/"+mode, func(t *testing.T) {
			tx, err := s.Conn().Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			alias := topology.MakePortKey(5, []byte("Gi1/1/17"))
			p := *sampleResult().Ports[0]
			p.Aliases = []topology.PortKey{p.Key, alias}
			p.MappingRule = "manual:paired direct samples"
			p.IfType = 6
			if mode != "repeat" {
				placeholder := &topology.Port{Key: alias, Subtype: 5, RawID: []byte("Gi1/1/17"), DisplayName: "advertised only", Resolution: topology.PortProvisional, MappingRule: "provisional-ifname", FirstSeen: time.Now(), LastSeen: time.Now()}
				if mode == "mapped" {
					placeholder.IfIndex = ptr32(999)
					placeholder.IfType = 6
					placeholder.Physical = true
					placeholder.Resolution = topology.PortVerified
					placeholder.MappingRule = "ifname-exact"
				}
				// First success already bound this alias. Use a fresh alias for
				// the rejection cases, so each tests an independent old record.
				if mode != "verified" {
					aliasName := "Gi1/1/18"
					if mode == "scoped" {
						aliasName = "Gi1/1/19"
					}
					alias = topology.MakePortKey(5, []byte(aliasName))
					placeholder.Key = alias
					placeholder.RawID = []byte(aliasName)
					p.Aliases = []topology.PortKey{p.Key, alias}
				}
				placeholderID, err := upsertPort(ctx, tx, deviceID, placeholder)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "linked" {
					if _, err = tx.Exec(ctx, `UPDATE links SET port_a_id=$1 WHERE device_a_id=$2`, placeholderID, deviceID); err != nil {
						t.Fatal(err)
					}
				}
			}
			if mode == "scoped" {
				p.MappingRule = topology.TS7914AliasRule
			}
			if mode == "not-manual" {
				p.MappingRule = "ifname-exact"
			}
			id, err := upsertPort(ctx, tx, deviceID, &p)
			if mode == "verified" || mode == "repeat" || mode == "scoped" {
				if err != nil || id != canonicalID {
					t.Fatalf("canonical port changed or promotion failed: %d %v", id, err)
				}
				var left int
				if err = tx.QueryRow(ctx, `SELECT count(*) FROM ports WHERE device_id=$1 AND port_key=$2`, deviceID, string(alias)).Scan(&left); err != nil || left != 0 {
					t.Fatal("unused placeholder was not retired")
				}
				if err = tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unverified, mapped or linked alias was merged")
			}
		})
	}
}
