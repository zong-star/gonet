package postgres

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"gonet/internal/collector/snmp"
	"gonet/internal/discovery"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/topology"
)

// A private search_path and generated schema are mandatory. No public schema
// reset, production scan or external SNMP request is performed by this test.
func discoveryTestStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("GONET_ISOLATED_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("GONET_ISOLATED_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("isolated database connection failed")
	}
	schema := fmt.Sprintf("gonet_test_discovery_%d", time.Now().UnixNano())
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
		admin.Close(cleanup)
	})
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid isolated test configuration")
	}
	cfg.RuntimeParams["search_path"] = schema
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatal("isolated store connection failed")
	}
	s := &Store{conn: conn}
	t.Cleanup(func() { s.Close(context.Background()) })
	if _, err = Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	return s
}

type discoveryReplay map[netip.Addr]*model.DeviceSnapshot

func (f discoveryReplay) Collect(_ context.Context, target model.DiscoveryTarget) (*model.DeviceSnapshot, error) {
	if s := f[target.Address]; s != nil {
		return s, nil
	}
	return nil, &snmp.Error{Code: snmp.CodeTimeout, Err: errors.New("simulated timeout")}
}

func TestRediscoveryIsolatedSchemaPersistence(t *testing.T) {
	s := discoveryTestStore(t)
	ctx := context.Background()
	ip := func(s string) netip.Addr { return netip.MustParseAddr(s) }
	mac := func(n byte) []byte { return []byte{2, 0, 0, 0, 0, n} }
	neighbor := func(local uint32, peer byte, port string, addr string) model.LLDPNeighbor {
		return model.LLDPNeighbor{Index: model.NeighborIndex{TimeMark: 7, LocalPortNum: local, RemoteIndex: 1}, Chassis: model.TypedID{Subtype: 4, Raw: mac(peer)}, Port: model.TypedID{Subtype: 5, Raw: []byte(port)}, SysName: fmt.Sprintf("sw-%d", peer), MgmtAddresses: []netip.Addr{ip(addr)}, CapEnabled: []byte{0x20}}
	}
	snapshot := func(addr string, n byte, neighbors ...model.LLDPNeighbor) *model.DeviceSnapshot {
		snap := &model.DeviceSnapshot{Device: model.DeviceInfo{Target: ip(addr), Chassis: model.TypedID{Subtype: 4, Raw: mac(n)}, SysName: fmt.Sprintf("sw-%d", n), SysObjectID: "1.3.6.1.4.1.99999.1", CapEnabled: []byte{0x20}}, Neighbors: neighbors, CollectionComplete: true, SnapshotStable: true, CollectedAt: time.Now().UTC()}
		for p := uint32(1); p <= 3; p++ {
			name := fmt.Sprintf("P%d", p)
			snap.LocalPorts = append(snap.LocalPorts, model.LocalPort{Number: p, ID: model.TypedID{Subtype: 5, Raw: []byte(name)}})
			snap.Interfaces = append(snap.Interfaces, model.Interface{IfIndex: int32(p), Name: name, Type: 6})
		}
		return snap
	}
	core := "192.0.2.1"
	peer := "10.201.109.200"
	child := "10.201.109.201"
	fixture := discoveryReplay{ip(core): snapshot(core, 1, neighbor(1, 2, "P1", "169.254.54.194"), neighbor(2, 2, "P2", "169.254.54.194"))}
	run := func() *discovery.Result {
		t.Helper()
		id, err := s.BeginScan(ctx, ScanInput{ConfigDigest: "rediscovery-fixture"})
		if err != nil {
			t.Fatal(err)
		}
		reg, err := identity.New(identity.Options{Rules: []identity.Rule{{ID: "test", SysObjectIDPrefix: "1.3.6.1.4.1.99999", Action: "switch"}}})
		if err != nil {
			t.Fatal(err)
		}
		c, err := discovery.New(discovery.Options{Seeds: []netip.Addr{ip(core)}, ManagementCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("10.201.109.0/24")}, MaxDepth: 4, Workers: 2, Collector: fixture, Registry: reg, Resolver: topology.NewResolver(nil)})
		if err != nil {
			t.Fatal(err)
		}
		devices, ports, err := s.LoadContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = c.RestoreContext(devices, ports); err != nil {
			t.Fatal(err)
		}
		r := c.Run(ctx)
		if err = s.CommitResult(ctx, id, r); err != nil {
			t.Fatal(err)
		}
		if err = s.CommitResult(ctx, id, r); err != nil {
			t.Fatal("idempotent re-submit:", err)
		}
		return r
	}
	r := run()
	if len(r.PendingNodes) != 1 || countRows(t, s, "discovery_candidates") != 1 || countRows(t, s, "devices") != 1 {
		t.Fatal("duplicate LLDP rows duplicated pending devices")
	}
	var first time.Time
	if err := s.Conn().QueryRow(ctx, `SELECT first_discovered_at FROM discovery_candidates`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	exp, err := ExportTopology(ctx, s.Conn(), "all")
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.PendingNodes) != 1 || exp.PendingNodes[0].Verification.FailureCode != "INVALID_MANAGEMENT_IP" {
		t.Fatal("pending reason missing from API")
	}
	// Exercise an upgrade with real historical pending rows, rather than
	// testing only an empty schema. The downgrade fixture is private to this
	// generated test schema; business tables are never reset.
	var schema string
	if err = s.Conn().QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); err != nil || !strings.HasPrefix(schema, "gonet_test_discovery_") {
		t.Fatal("unsafe migration fixture scope")
	}
	if _, err = s.Conn().Exec(ctx, "DROP TABLE "+pgx.Identifier{schema, "discovery_candidates"}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Conn().Exec(ctx, `DELETE FROM schema_migrations WHERE version=5`); err != nil {
		t.Fatal(err)
	}
	if applied, err := Migrate(ctx, s.Conn()); err != nil || len(applied) != 1 || applied[0] != 5 {
		t.Fatalf("historical upgrade: %v %v", applied, err)
	}
	if countRows(t, s, "discovery_candidates") != 1 || countRows(t, s, "devices") != 1 {
		t.Fatal("migration duplicated candidates or changed existing devices")
	}
	fixture[ip(core)] = snapshot(core, 1, neighbor(1, 2, "P1", peer), neighbor(2, 2, "P2", peer))
	fixture[ip(peer)] = snapshot(peer, 2, neighbor(3, 3, "P1", child))
	fixture[ip(child)] = snapshot(child, 3)
	r = run()
	if len(r.Devices) != 3 || len(r.Links) != 3 || len(r.PendingNodes) != 0 {
		t.Fatalf("new address did not create recursive graph: %+v", r.Counts)
	}
	var id int64
	var selected, status string
	var stillFirst time.Time
	if err = s.Conn().QueryRow(ctx, `SELECT device_id,verification->>'selected_snmp_ip',verification->>'verification_status',first_discovered_at FROM discovery_candidates WHERE candidate_key='lldp:4:020000000002'`).Scan(&id, &selected, &status, &stillFirst); err != nil {
		t.Fatal(err)
	}
	if id == 0 || selected != peer || status != "verified" || !first.Equal(stillFirst) {
		t.Fatal("original pending candidate was not linked in place")
	}
	delete(fixture, ip(peer))
	run()
	if countRows(t, s, "devices") != 3 || countRows(t, s, "links") != 3 {
		t.Fatal("transient failure removed existing graph")
	}
	fixture[ip(peer)] = snapshot(peer, 2, neighbor(3, 3, "P1", child))
	run()
	var afterID int64
	if err = s.Conn().QueryRow(ctx, `SELECT device_id FROM discovery_candidates WHERE candidate_key='lldp:4:020000000002'`).Scan(&afterID); err != nil {
		t.Fatal(err)
	}
	if id != afterID || countRows(t, s, "devices") != 3 || countRows(t, s, "links") != 3 {
		t.Fatal("retry duplicated device or parallel physical links")
	}
	if applied, err := Migrate(ctx, s.Conn()); err != nil || len(applied) != 0 {
		t.Fatal("migration is not idempotent")
	}
}
