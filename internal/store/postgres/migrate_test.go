package postgres

import (
	"context"
	"os"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"gonet/migrations"
)

// testConn connects to the integration test database, or skips when
// GONET_TEST_DATABASE_URL is not configured.
func testConn(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("GONET_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("GONET_TEST_DATABASE_URL not set; skipping PostgreSQL integration test")
	}
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

func resetDB(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	if _, err := conn.Exec(context.Background(), "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
}

// P01: an empty database migrates once, and a second migrate up is a no-op.
func TestP01MigrateIdempotent(t *testing.T) {
	conn := testConn(t)
	resetDB(t, conn)
	ctx := context.Background()

	applied, err := Migrate(ctx, conn)
	if err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if !slices.Equal(applied, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}) {
		t.Fatalf("applied = %v, want migrations 1 through 11", applied)
	}

	applied2, err := Migrate(ctx, conn)
	if err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if len(applied2) != 0 {
		t.Fatalf("second applied = %v, want none (nothing to do)", applied2)
	}

	for _, tbl := range []string{
		"scan_runs", "devices", "device_identities", "device_addresses",
		"ports", "links", "scan_devices", "observations", "discovery_candidates", "agent_api_keys", "agent_api_legacy_import",
		"scan_interface_facts", "scan_lag_members",
	} {
		var exists bool
		if err := conn.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", "public."+tbl).Scan(&exists); err != nil {
			t.Fatalf("to_regclass(%s): %v", tbl, err)
		}
		if !exists {
			t.Errorf("table %s is missing", tbl)
		}
	}

	var version int
	if err := conn.QueryRow(ctx, "SELECT max(version) FROM schema_migrations").Scan(&version); err != nil {
		t.Fatalf("schema_migrations: %v", err)
	}
	if version != 12 {
		t.Errorf("schema_migrations max version = %d, want 12", version)
	}
	down, err := migrations.FS.ReadFile("000010_scan_interface_alias_presence.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, string(down)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "SELECT if_alias FROM scan_interface_facts"); err != nil {
		t.Fatal(err)
	}
}

// P02: swapped endpoints, cross-device ports and duplicate links are rejected
// by the schema, leaving no dirty rows.
func TestP02Constraints(t *testing.T) {
	conn := testConn(t)
	resetDB(t, conn)
	ctx := context.Background()
	if _, err := Migrate(ctx, conn); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var scanID int64
	if err := conn.QueryRow(ctx,
		`INSERT INTO scan_runs(seed_ips, config_digest) VALUES ('{192.0.2.1}', 'digest') RETURNING id`).Scan(&scanID); err != nil {
		t.Fatalf("insert scan_run: %v", err)
	}
	var devA, devB int64
	if err := conn.QueryRow(ctx,
		`INSERT INTO devices(identity_state, classification_rule) VALUES ('verified','r') RETURNING id`).Scan(&devA); err != nil {
		t.Fatalf("insert device A: %v", err)
	}
	if err := conn.QueryRow(ctx,
		`INSERT INTO devices(identity_state, classification_rule) VALUES ('verified','r') RETURNING id`).Scan(&devB); err != nil {
		t.Fatalf("insert device B: %v", err)
	}
	var portA, portB int64
	if err := conn.QueryRow(ctx,
		`INSERT INTO ports(device_id, port_key, subtype, raw_id, display_name, resolution, is_physical, mapping_rule)
		 VALUES ($1,'lldp:5:aa',5,'\xaa','P1','verified',true,'ifname-exact') RETURNING id`, devA).Scan(&portA); err != nil {
		t.Fatalf("insert port A: %v", err)
	}
	if err := conn.QueryRow(ctx,
		`INSERT INTO ports(device_id, port_key, subtype, raw_id, display_name, resolution, is_physical, mapping_rule)
		 VALUES ($1,'lldp:5:aa',5,'\xaa','P1','verified',true,'ifname-exact') RETURNING id`, devB).Scan(&portB); err != nil {
		t.Fatalf("insert port B: %v", err)
	}

	insertLink := `INSERT INTO links(device_a_id, port_a_id, device_b_id, port_b_id, confidence,
		first_seen_at, last_seen_at, last_seen_scan_id, last_evaluated_scan_id)
		VALUES ($1,$2,$3,$4,'bidirectional',now(),now(),$5,$5)`

	// P02-1: device_a_id must be < device_b_id (swapped endpoints rejected).
	if _, err := conn.Exec(ctx, insertLink, devB, portB, devA, portA, scanID); err == nil {
		t.Error("swapped endpoints were accepted; want CHECK violation")
	}

	// P02-2: a port belonging to another device is rejected by the composite FK.
	if _, err := conn.Exec(ctx, insertLink, devA, portB, devB, portA, scanID); err == nil {
		t.Error("cross-device port was accepted; want FK violation")
	}

	// A valid link is accepted once.
	if _, err := conn.Exec(ctx, insertLink, devA, portA, devB, portB, scanID); err != nil {
		t.Fatalf("valid link rejected: %v", err)
	}

	// P02-3: an exact duplicate link is rejected by the unique constraint.
	if _, err := conn.Exec(ctx, insertLink, devA, portA, devB, portB, scanID); err == nil {
		t.Error("duplicate link was accepted; want unique violation")
	}

	var n int
	if err := conn.QueryRow(ctx, "SELECT count(*) FROM links").Scan(&n); err != nil {
		t.Fatalf("count links: %v", err)
	}
	if n != 1 {
		t.Errorf("links = %d, want 1 (no dirty rows)", n)
	}
}
