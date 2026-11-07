package postgres

import (
	"context"
	"fmt"
	"gonet/internal/model"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestInterfaceStatusPersistenceAndStableNameMapping(t *testing.T) {
	conn := testConn(t)
	resetDB(t, conn)
	ctx := context.Background()
	if _, e := Migrate(ctx, conn); e != nil {
		t.Fatal(e)
	}
	s, e := Open(ctx, os.Getenv("GONET_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close(ctx)
	r := sampleResult()
	for i := range r.Outcomes {
		r.Outcomes[i].Snapshot.Interfaces = []model.Interface{{IfIndex: int32(101 + 100*i), Name: fmt.Sprintf("Ethernet%d", i), Description: "same", Type: 6}}
	}
	scan, e := s.BeginScan(ctx, ScanInput{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ConfigDigest: "status-fixture"})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.CommitResult(ctx, scan, r); e != nil {
		t.Fatal(e)
	}
	v, e := ExportTopology(ctx, conn, "all")
	if e != nil {
		t.Fatal(e)
	}
	linkID := v.Links[0].ID
	now := time.Now().UTC()
	for i, d := range v.Devices {
		st := model.InterfaceStatus{AdminStatus: "up", OperStatus: "up", StatusCollectionState: "success", StatusCollectedAt: &now}
		if e = SaveInterfaceStatus(ctx, conn, d.ID, []model.Interface{{IfIndex: int32(501 + i), Name: fmt.Sprintf("Ethernet%d", i), Type: 6, InterfaceStatus: st}}, now, nil); e != nil {
			t.Fatal(e)
		}
	}
	v, e = ExportTopology(ctx, conn, "all")
	if e != nil {
		t.Fatal(e)
	}
	if v.Links[0].ID != linkID || v.Links[0].LinkOperStatus != "up" {
		t.Fatalf("ifIndex renumbering broke stable link: %+v", v.Links)
	}
	if e = SaveInterfaceStatus(ctx, conn, v.Devices[0].ID, nil, now.Add(time.Second), fmt.Errorf("SNMP_TIMEOUT")); e != nil {
		t.Fatal(e)
	}
	v, e = ExportTopology(ctx, conn, "all")
	if e != nil {
		t.Fatal(e)
	}
	if v.Links[0].LinkOperStatus != "unknown" || v.Devices[0].Interfaces[0].OperStatus != "up" || !v.Devices[0].Interfaces[0].StatusCollectedAt.Equal(now) {
		t.Fatalf("failure overwrote last success: %+v", v)
	}
	// Older overlapping poll may not overwrite a later failure record.
	if e = SaveInterfaceStatus(ctx, conn, v.Devices[0].ID, []model.Interface{}, now, nil); e != nil {
		t.Fatal(e)
	}
	v, e = ExportTopology(ctx, conn, "all")
	if e != nil || v.Devices[0].Interfaces[0].StatusCollectionState != "failed" {
		t.Fatal("older poll overwrote newer attempt", e)
	}
	if e = SaveInterfaceStatus(ctx, conn, v.Devices[0].ID, []model.Interface{}, now.Add(2*time.Second), nil); e != nil {
		t.Fatal(e)
	}
	v, e = ExportTopology(ctx, conn, "all")
	if e != nil || v.Devices[0].Interfaces[0].StatusCollectionState != "missing" || len(v.Links) != 1 {
		t.Fatal("missing interface or physical link discarded", e)
	}
	// Duplicate current names are ambiguous and must never select an arbitrary row.
	items := []model.Interface{{IfIndex: 1, Name: "Ethernet0", Type: 6, InterfaceStatus: model.InterfaceStatus{AdminStatus: "up", OperStatus: "up", StatusCollectionState: "success", StatusCollectedAt: &now}}, {IfIndex: 2, Name: "Ethernet0", Type: 6}}
	if e = SaveInterfaceStatus(ctx, conn, v.Devices[0].ID, items, now.Add(3*time.Second), nil); e != nil {
		t.Fatal(e)
	}
	v, e = ExportTopology(ctx, conn, "all")
	if e != nil || v.Links[0].LinkOperStatus != "unknown" || v.Links[0].SourceStatusCollectedAt != nil {
		t.Fatal("ambiguous name mapped to a port", e)
	}
}
