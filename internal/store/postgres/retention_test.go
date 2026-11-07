package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"testing"
)

// Called only inside TestNoIPIsolatedSchemaPersistence's disposable schema.
func testHistoryRetention(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	s.releaseLock(ctx)
	r := sampleResult()
	commit := func() int64 {
		t.Helper()
		id, err := s.BeginScan(ctx, ScanInput{ConfigDigest: "retention", KeepScans: 3})
		if err != nil {
			t.Fatal(err)
		}
		if err = s.CommitResult(ctx, id, r); err != nil {
			t.Fatal(err)
		}
		return id
	}
	positive := commit()
	before, err := ExportTopology(ctx, s.conn, "all")
	if err != nil || len(before.Links) != 1 {
		t.Fatal("initial graph unavailable", err)
	}
	original := before.Links[0]
	r.Status = "partial"
	r.Links = nil
	r.Observations = nil
	r.Outcomes = nil
	for i := 0; i < 3; i++ {
		commit()
	}
	var n int
	if err = s.conn.QueryRow(ctx, `SELECT count(*) FROM scan_runs WHERE id=$1`, positive).Scan(&n); err != nil || n != 0 {
		t.Fatal("expired positive round was not removed", err)
	}
	after, err := ExportTopology(ctx, s.conn, "all")
	if err != nil || len(after.Links) != 1 {
		t.Fatal("retention removed a physical link", err)
	}
	l := after.Links[0]
	if l.ID != original.ID || l.DeviceAID != original.DeviceAID || l.PortAID != original.PortAID || l.DeviceBID != original.DeviceBID || l.PortBID != original.PortBID || l.LastSeenScanID != nil || l.Fresh || l.MissedCompleteScans != original.MissedCompleteScans || !l.LastSeenAt.Equal(original.LastSeenAt) || l.DiscoveryState != original.DiscoveryState {
		t.Fatalf("retention altered stable graph or fabricated fresh evidence: %+v", l)
	}
	if countRows(t, s, "devices") != 2 || countRows(t, s, "links") != 1 || countRows(t, s, "scan_runs") != 3 {
		t.Fatal("retention deleted inventory or exceeded cap")
	}
	var oldDetails int
	if err = s.conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM observations WHERE scan_id=$1)+(SELECT count(*) FROM scan_devices WHERE scan_id=$1)`, positive).Scan(&oldDetails); err != nil || oldDetails != 0 {
		t.Fatal("old details survived", err)
	}
	r = sampleResult()
	good := commit()
	restored, err := ExportTopology(ctx, s.conn, "all")
	if err != nil || len(restored.Links) != 1 || restored.Links[0].ID != original.ID || !restored.Links[0].Fresh || restored.Links[0].LastSeenScanID == nil || *restored.Links[0].LastSeenScanID != good {
		t.Fatal("new evidence did not restore the same link", err)
	}
	for i := 0; i < 5; i++ {
		id, e := s.BeginScan(ctx, ScanInput{ConfigDigest: "failed-retention", KeepScans: 3})
		if e != nil {
			t.Fatal(e)
		}
		if e = s.MarkFailed(ctx, id, "TEST_FAILURE", "synthetic failure"); e != nil {
			t.Fatal(e)
		}
		s.releaseLock(ctx)
	}
	exp, err := ExportTopology(ctx, s.conn, "all")
	if err != nil || exp.LatestScanID != good || countRows(t, s, "scan_runs") != 3 {
		t.Fatal("failed rounds evicted last usable topology", err)
	}
	id, err := s.BeginScan(ctx, ScanInput{ConfigDigest: "retention-lock", KeepScans: 3})
	if err != nil {
		t.Fatal(err)
	}
	other, err := pgx.ConnectConfig(ctx, s.conn.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	otherStore := &Store{conn: other}
	_, err = otherStore.PruneHistory(ctx, 3)
	otherStore.Close(ctx)
	if !errors.Is(err, ErrLocked) {
		t.Fatal("cleanup ignored the scan lock", err)
	}
	if _, err = s.PruneHistory(ctx, 3); err != nil {
		t.Fatal(err)
	}
	var state string
	if err = s.conn.QueryRow(ctx, `SELECT status FROM scan_runs WHERE id=$1`, id).Scan(&state); err != nil || state != "running" {
		t.Fatal("cleanup removed a running scan", err)
	}
	// A deletion failure rolls back both pruning and the new result, preserving
	// existing history, link state and the running round for explicit recovery.
	if _, err = s.conn.Exec(ctx, `CREATE FUNCTION retention_reject_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic retention failure'; END $$;
 CREATE TRIGGER retention_reject BEFORE DELETE ON scan_runs FOR EACH ROW EXECUTE FUNCTION retention_reject_delete()`); err != nil {
		t.Fatal(err)
	}
	if err = s.CommitResult(ctx, id, r); err == nil {
		t.Fatal("injected cleanup failure was ignored")
	}
	if err = s.conn.QueryRow(ctx, `SELECT status FROM scan_runs WHERE id=$1`, id).Scan(&state); err != nil || state != "running" {
		t.Fatal("cleanup failure partially committed", err)
	}
	if _, err = s.conn.Exec(ctx, `DROP TRIGGER retention_reject ON scan_runs; DROP FUNCTION retention_reject_delete()`); err != nil {
		t.Fatal(err)
	}
	if err = s.CommitResult(ctx, id, r); err != nil {
		t.Fatal(err)
	}
	if err = s.CommitResult(ctx, id, r); err != nil {
		t.Fatal("repeat commit was not idempotent", err)
	}
	// Exercise the actual requested 500 boundary without real device traffic.
	if _, err = s.conn.Exec(ctx, `INSERT INTO scan_runs(started_at,finished_at,status,seed_ips,config_digest)
 SELECT now(),now(),'failed','{}'::inet[],'synthetic-500-boundary' FROM generate_series(1,550)`); err != nil {
		t.Fatal(err)
	}
	p, err := s.PruneHistory(ctx, 500)
	if err != nil || p.Scans != 53 || countRows(t, s, "scan_runs") != 500 {
		t.Fatalf("500 boundary failed: %+v %v", p, err)
	}
	exp, err = ExportTopology(ctx, s.conn, "all")
	if err != nil || exp.LatestScanID != id || len(exp.Links) != 1 || !exp.Links[0].Fresh {
		t.Fatal("500 boundary lost latest graph", err)
	}
	p, err = s.PruneHistory(ctx, 500)
	if err != nil || p.Scans != 0 {
		t.Fatal("repeat pruning was not idempotent", err)
	}
	var badFK int
	if err = s.conn.QueryRow(ctx, `SELECT count(*) FROM observations o LEFT JOIN scan_runs r ON r.id=o.scan_id WHERE r.id IS NULL`).Scan(&badFK); err != nil || badFK != 0 {
		t.Fatal("pruning left invalid observations", err)
	}
}
