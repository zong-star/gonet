package postgres

import (
	"context"
	"net/netip"
	"os"
	"slices"
	"testing"

	"gonet/internal/discovery"
	"gonet/internal/model"
)

func TestScanInterfaceEvidenceMigrationAndLifecycle(t *testing.T) {
	conn := testConn(t)
	resetDB(t, conn)
	ctx := context.Background()
	if _, err := conn.Exec(ctx, `CREATE TABLE schema_migrations (version bigint PRIMARY KEY, name text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	migrations, err := LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations {
		if migration.Version <= 7 {
			if err := applyOne(ctx, conn, migration); err != nil {
				t.Fatal(err)
			}
		}
	}
	store, err := Open(ctx, os.Getenv("GONET_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { store.Close(ctx) }()
	begin := func() int64 {
		t.Helper()
		id, err := store.BeginScan(ctx, ScanInput{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ConfigDigest: "lag"})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	commit := func(id int64, result *discovery.Result) {
		t.Helper()
		if err := store.CommitResult(ctx, id, result); err != nil {
			t.Fatal(err)
		}
	}
	old := sampleResult()
	// Allocate the stable IDs in the reverse order of this round's references.
	old.Devices[0], old.Devices[1] = old.Devices[1], old.Devices[0]
	commit(begin(), old)
	for _, migration := range migrations {
		if migration.Version == 8 || migration.Version == 9 {
			if err := applyOne(ctx, conn, migration); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := conn.Exec(ctx, `INSERT INTO scan_interface_facts
		(scan_id, device_id, if_index, if_name, if_descr, if_alias, if_type, collected_at)
		SELECT scan_id, device_id, 999, '', '', '', 6, now() FROM scan_devices`); err != nil {
		t.Fatal(err)
	}
	applied, err := Migrate(ctx, conn)
	if err != nil || !slices.Equal(applied, []int{10, 11, 12}) {
		t.Fatalf("upgrade: %v, %v", applied, err)
	}
	var oldAliasCollected bool
	if err := conn.QueryRow(ctx, `SELECT if_alias_collected FROM scan_interface_facts LIMIT 1`).Scan(&oldAliasCollected); err != nil || oldAliasCollected {
		t.Fatalf("historical empty alias was marked collected: %t, %v", oldAliasCollected, err)
	}
	if _, err := conn.Exec(ctx, `DELETE FROM scan_interface_facts WHERE if_index=999`); err != nil {
		t.Fatal(err)
	}
	oldView, err := ExportTopologyWithEvidence(ctx, conn, "all")
	if err != nil {
		t.Fatal(err)
	}
	linkID := oldView.Links[0].ID
	previous := oldView.Evidence.Links[linkID]
	if previous.A.IfIndex != nil || previous.B.IfIndex != nil || len(previous.Observations) != 1 ||
		previous.Observations[0].ObserverID != oldView.Links[0].DeviceBID {
		t.Fatalf("old batch evidence %+v", previous)
	}
	result := sampleResult()
	for i, outcome := range result.Outcomes {
		physical := int32(102 + 100*i)
		result.Ports[i].IfIndex = &physical
		outcome.Snapshot.Interfaces = []model.Interface{{IfIndex: physical, Name: "P-new", Type: 6}, {IfIndex: 300, Name: "LAG", Type: 161}}
		if i == 0 {
			outcome.Snapshot.Interfaces[0].AliasCollected = true
		} else {
			outcome.Snapshot.Interfaces[0].Name = ""
			outcome.Snapshot.Interfaces[0].Description = "legacy-ifDescr"
			outcome.Snapshot.Interfaces[0].Alias = "admin label"
		}
		outcome.Snapshot.Interfaces[1].Alias = "LAG label"
		outcome.Snapshot.LAGMembers = []model.LAGMember{{AggregateIfIndex: 300, MemberIfIndex: physical, Source: "ieee_lag", Mode: "lacp", Status: "confirmed"}}
		outcome.Snapshot.Components = map[string]model.ComponentStatus{"lag_membership": {Supported: true, WalkComplete: true, DecodeComplete: true}}
	}
	failedID := begin()
	result.Observations[0].Row.LocalPortNum = 0
	if err := store.CommitResult(ctx, failedID, result); err == nil {
		t.Fatal("invalid observation should roll back the whole scan")
	}
	if countRows(t, store, "scan_interface_facts") != 0 || countRows(t, store, "scan_lag_members") != 0 || countRows(t, store, "links") != 1 {
		t.Fatal("failed scan partially committed")
	}
	if err := store.MarkFailed(ctx, failedID, "TEST_FAILURE", "rollback test"); err != nil {
		t.Fatal(err)
	}
	store.Close(ctx)
	store, err = Open(ctx, os.Getenv("GONET_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	result.Observations[0].Row.LocalPortNum = 1
	current := begin()
	commit(current, result)
	commit(current, result)
	view, err := ExportTopologyWithEvidence(ctx, conn, "all")
	if err != nil {
		t.Fatal(err)
	}
	evidence := view.Evidence.Links[linkID]
	if view.LatestScanID != current || evidence.A.IfIndex == nil || *evidence.A.IfIndex != 202 ||
		evidence.B.IfIndex == nil || *evidence.B.IfIndex != 102 || countRows(t, store, "scan_lag_members") != 2 {
		t.Fatalf("batch evidence: %+v", evidence)
	}
	if evidence.A.IfName != nil || evidence.A.Name == nil || *evidence.A.Name != "legacy-ifDescr" ||
		evidence.A.IfAlias == nil || *evidence.A.IfAlias != "admin label" || evidence.B.IfAlias == nil || *evidence.B.IfAlias != "" ||
		evidence.B.IfName == nil || *evidence.B.IfName != "P-new" {
		t.Fatalf("oriented endpoint evidence: %+v", evidence)
	}
	lag := view.Evidence.LAG[view.Links[0].DeviceAID].Members[0].Endpoint
	if lag.IfName == nil || *lag.IfName != "LAG" || lag.IfAlias == nil || *lag.IfAlias != "LAG label" || lag.IfIndex == nil || *lag.IfIndex != 300 {
		t.Fatalf("aggregate endpoint evidence: %+v", lag)
	}
	next := sampleResult()
	next.Ports[0].IfIndex = ptr32(301)
	next.Outcomes[0].Snapshot.Interfaces = []model.Interface{{IfIndex: 301, Name: "P-reused", Type: 6}}
	next.Links, next.Observations = nil, nil
	commit(begin(), next)
	view, err = ExportTopologyWithEvidence(ctx, conn, "all")
	if err != nil {
		t.Fatal(err)
	}
	if index := view.Evidence.Links[linkID].B.IfIndex; index == nil || *index != 102 {
		t.Fatalf("historical link was joined to a newer interface fact: %v", err)
	}
	commit(begin(), sampleResult())
	if _, err := store.PruneHistory(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if countRows(t, store, "scan_lag_members") != 0 || countRows(t, store, "scan_interface_facts") != 1 {
		t.Fatal("interface and LAG evidence did not follow history retention")
	}
}
