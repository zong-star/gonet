package postgres

import (
	"context"
	"gonet/internal/model"
	"net/netip"
	"os"
	"testing"
)

func TestLAGVendorEvidencePersistence(t *testing.T) {
	conn := testConn(t)
	resetDB(t, conn)
	ctx := context.Background()
	if _, err := Migrate(ctx, conn); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, os.Getenv("GONET_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)
	makeResult := sampleResult
	r := makeResult()
	yes := true
	for i := range r.Outcomes {
		snap := r.Outcomes[i].Snapshot
		physical := int32(101 + i*100)
		agg := int32(19 + i*618)
		typ := int32(53)
		source, name := "huawei_private", "Eth-Trunk1"
		if i == 1 {
			typ = 161
			source, name = "ieee_lag", "Bridge-Aggregation2"
		}
		snap.Interfaces = []model.Interface{{IfIndex: physical, Name: "physical", Type: 6}, {IfIndex: agg, Name: name, Type: typ}}
		snap.LAGMembers = []model.LAGMember{{AggregateIfIndex: agg, MemberIfIndex: physical, Source: source, Sources: []string{source}, Mode: "unknown", Status: "confirmed", Configured: &yes}}
		snap.LAGGroups = []model.LAGGroup{{SourceGroupID: source + ":0", AggregateIfIndex: &agg, Source: source, Mode: "unknown"}}
		snap.LAGEvidence = []model.LAGEvidence{{Source: source, Root: "1.3.6.1.4.1.2011", Facts: []model.LAGFact{{OID: "1.3.6.1.4.1.2011.1", Type: "Integer", Value: 19}}}}
		snap.LACPPorts = []model.LACPPort{{MemberIfIndex: physical, Stable: false}}
		snap.Components = map[string]model.ComponentStatus{"lag_membership": {Supported: true, DecodeComplete: true}}
	}
	r.Outcomes[0].Snapshot.LAGAdvertisements = []model.LAGAdvertisement{{Direction: "remote", Index: r.Observations[0].Row, MemberIfIndex: ptr32(101), AggregateID: 27, Enabled: true, Capable: true, RawStatus: []byte{0xc0}}}
	id, err := s.BeginScan(ctx, ScanInput{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ConfigDigest: "vendor-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CommitResult(ctx, id, r); err != nil {
		t.Fatal(err)
	}
	if err = s.CommitResult(ctx, id, r); err != nil {
		t.Fatal(err)
	}
	v, err := ExportTopologyWithEvidence(ctx, conn, "all")
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Links) != 1 || len(v.Evidence.LAG) != 2 || countRows(t, s, "scan_lag_groups") != 2 || countRows(t, s, "scan_lag_evidence") != 5 {
		t.Fatalf("facts lost after commit: %+v", v.Evidence)
	}
	link := v.Evidence.Links[v.Links[0].ID]
	if len(link.Advertisements) != 1 || link.Advertisements[0].Advertisement.AggregateID != 27 || link.LACPA == nil || link.LACPB == nil {
		t.Fatal("evidence not bound through observed endpoints")
	}
	for _, d := range v.Evidence.LAG {
		if d.Complete || len(d.Members) != 1 || d.Members[0].Configured == nil || !*d.Members[0].Configured || len(d.Sources) != 1 || len(d.Groups) != 1 {
			t.Fatalf("coverage/typed members %+v", d)
		}
	}
	var rawType int32
	if err = conn.QueryRow(ctx, `SELECT if_type FROM scan_interface_facts WHERE if_name='Eth-Trunk1'`).Scan(&rawType); err != nil || rawType != 53 {
		t.Fatal("raw interface type changed")
	}
	// A new scan containing an invalid group FK must roll back every new fact.
	bad := sampleResult()
	bad.Outcomes[0].Snapshot.LAGGroups = []model.LAGGroup{{SourceGroupID: "bad", AggregateIfIndex: ptr32(999)}}
	failed, err := s.BeginScan(ctx, ScanInput{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ConfigDigest: "rollback"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CommitResult(ctx, failed, bad); err == nil {
		t.Fatal("invalid group FK accepted")
	}
	if countRows(t, s, "scan_lag_groups") != 2 || countRows(t, s, "scan_lag_evidence") != 5 || countRows(t, s, "links") != 1 {
		t.Fatal("partial evidence transaction committed")
	}
	if err = s.MarkFailed(ctx, failed, "FIXTURE", "expected rollback"); err != nil {
		t.Fatal(err)
	}
}

func TestLAGSchema10ReadCompatibility(t *testing.T) {
	conn := testConn(t)
	resetDB(t, conn)
	ctx := context.Background()
	if _, err := conn.Exec(ctx, `CREATE TABLE schema_migrations (version bigint PRIMARY KEY,name text NOT NULL,applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	all, err := LoadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range all {
		if m.Version <= 10 {
			if err = applyOne(ctx, conn, m); err != nil {
				t.Fatal(err)
			}
		}
	}
	s, err := Open(ctx, os.Getenv("GONET_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)
	id, err := s.BeginScan(ctx, ScanInput{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ConfigDigest: "schema10"})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CommitResult(ctx, id, sampleResult()); err != nil {
		t.Fatal(err)
	}
	v, err := ExportTopologyWithEvidence(ctx, conn, "all")
	if err != nil || len(v.Links) != 1 {
		t.Fatalf("read schema10 failed: %v", err)
	}
}

func TestLegacyLAGModeRequiresConfigurationEvidence(t *testing.T) {
	v := &TopologyEvidence{LAG: map[int64]DeviceLAGEvidence{1: {Members: []LAGMemberEvidence{
		{LAGMember: model.LAGMember{Source: "ieee_lag", Mode: "static"}},
		{LAGMember: model.LAGMember{Source: "ieee_lag", Mode: "static", Sources: []string{"ieee_lag", "h3c_private"}}},
		{LAGMember: model.LAGMember{Source: "ieee_lag", Mode: "lacp"}},
	}}}}
	normalizeLegacyLAGModes(v)
	m := v.LAG[1].Members
	if m[0].Mode != "unknown" || m[1].Mode != "static" || m[2].Mode != "lacp" {
		t.Fatalf("legacy mode normalization %+v", m)
	}
}
