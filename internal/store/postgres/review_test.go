package postgres

import (
	"context"
	"gonet/internal/discovery"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/topology"
	"net/netip"
	"testing"
	"time"
)

func TestPersistedIdentityRefreshAndAddress(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()
	commitRound(t, s, sampleResult())
	var before int64
	if err := s.Conn().QueryRow(ctx, `SELECT device_id FROM device_identities WHERE identity_key='lldp:4:000000000001'`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	id, err := s.BeginScan(ctx, ScanInput{ConfigDigest: "review"})
	if err != nil {
		t.Fatal(err)
	}
	devices, _, err := s.LoadContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := identity.New(identity.Options{Rules: []identity.Rule{{ID: "r", SysObjectIDPrefix: "1.3.6.1.4.1.99999", Action: "switch"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Restore(devices); err != nil {
		t.Fatal(err)
	}
	snap := &model.DeviceSnapshot{Device: model.DeviceInfo{Target: netip.MustParseAddr("192.0.2.11"), Chassis: model.TypedID{Subtype: 4, Raw: []byte{0, 0, 0, 0, 0, 1}}, SysName: "renamed", SysObjectID: "1.3.6.1.4.1.99999.1"}}
	d := reg.ResolveDirect(snap).Device
	if d == nil {
		t.Fatal("context did not resolve known identity")
	}
	if err := s.CommitResult(ctx, id, &discovery.Result{Status: "partial", Devices: []*identity.Device{d}}); err != nil {
		t.Fatal(err)
	}
	var after int64
	var name string
	var n int
	if err := s.Conn().QueryRow(ctx, `SELECT d.id,d.sys_name,(SELECT count(*) FROM device_addresses WHERE device_id=d.id) FROM devices d WHERE id=$1`, before).Scan(&after, &name, &n); err != nil {
		t.Fatal(err)
	}
	if after != before || name != "renamed" || n != 2 {
		t.Fatalf("refresh: id=%d name=%s addresses=%d", after, name, n)
	}
}

func TestPersistedProvisionalUpgrade(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()
	r := sampleResult()
	d := r.Devices[0]
	d.StrongKey = ""
	d.State = identity.StateProvisional
	r.Devices = r.Devices[:1]
	r.Ports = nil
	r.Outcomes = nil
	r.Links = nil
	r.Observations = nil
	commitRound(t, s, r)
	var before int64
	if err := s.Conn().QueryRow(ctx, `SELECT id FROM devices`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	d.StrongKey = "lldp:4:000000000001"
	d.State = identity.StateVerified
	commitRound(t, s, r)
	var after int64
	if err := s.Conn().QueryRow(ctx, `SELECT device_id FROM device_identities`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after || countRows(t, s, "devices") != 1 {
		t.Fatal("provisional identity was not upgraded in place")
	}
}

func TestPersistedAddressReuseIsolated(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()
	commitRound(t, s, sampleResult())
	id, err := s.BeginScan(ctx, ScanInput{ConfigDigest: "review"})
	if err != nil {
		t.Fatal(err)
	}
	devices, _, err := s.LoadContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := identity.New(identity.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.Restore(devices); err != nil {
		t.Fatal(err)
	}
	result := reg.ResolveDirect(&model.DeviceSnapshot{Device: model.DeviceInfo{Target: netip.MustParseAddr("192.0.2.1"), Chassis: model.TypedID{Subtype: 4, Raw: []byte{0, 0, 0, 0, 0, 9}}}})
	if result.State != identity.ResolvedConflict {
		t.Fatal("IP reuse was accepted")
	}
	if err := s.CommitResult(ctx, id, &discovery.Result{Status: "partial", Devices: reg.Devices(), Issues: result.Issues}); err != nil {
		t.Fatal(err)
	}
	var state string
	if err := s.Conn().QueryRow(ctx, `SELECT state FROM device_addresses WHERE address='192.0.2.1'`).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "conflict" || countRows(t, s, "devices") != 2 || countRows(t, s, "device_identities") != 2 {
		t.Fatal("IP conflict rewrote persistent identity")
	}
}

func TestRejectNonPhysicalResultTransaction(t *testing.T) {
	s := setupStore(t)
	ctx := context.Background()
	id, err := s.BeginScan(ctx, ScanInput{ConfigDigest: "review"})
	if err != nil {
		t.Fatal(err)
	}
	r := sampleResult()
	r.Ports[1].Physical = false
	if err := s.CommitResult(ctx, id, r); err == nil {
		t.Fatal("nonphysical link accepted")
	}
	if countRows(t, s, "devices") != 0 || countRows(t, s, "links") != 0 {
		t.Fatal("invalid result was partially committed")
	}
}

func TestT502TwentyPersistentRounds(t *testing.T) {
	s := setupStore(t)
	for round := 0; round < 20; round++ {
		r := sampleResult()
		for _, d := range r.Devices {
			d.LastSeen = d.LastSeen.Add(time.Duration(round) * time.Minute)
		}
		commitRound(t, s, r)
		for table, want := range map[string]int{"devices": 2, "ports": 2, "links": 1, "device_identities": 2, "device_addresses": 2} {
			if n := countRows(t, s, table); n != want {
				t.Fatalf("round %d: %s grew to %d", round, table, n)
			}
		}
	}
}

func TestExcludedCandidateEvidenceStored(t *testing.T) {
	s := setupStore(t)
	r := sampleResult()
	n := model.LLDPNeighbor{Index: model.NeighborIndex{TimeMark: 1, LocalPortNum: 2, RemoteIndex: 1}, Chassis: model.TypedID{Subtype: 4, Raw: []byte{2, 0, 0, 0, 0, 9}}, CapEnabled: []byte{0x10}}
	r.Candidates = []discovery.Candidate{{Observer: 1, Row: n.Index, Raw: n, At: r.Observations[0].At, Disposition: "excluded", Classification: identity.Classification{Result: "excluded", Reason: "AP"}}}
	commitRound(t, s, r)
	var count int
	if err := s.Conn().QueryRow(context.Background(), `SELECT count(*) FROM observations WHERE resolution='excluded' AND raw_neighbor->>'cap_enabled'='EA=='`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("excluded observation evidence was lost")
	}
}

func TestSameChassisMultipleAddressOutcomes(t *testing.T) {
	s := setupStore(t)
	r := sampleResult()
	other := r.Outcomes[0]
	other.Target.Address = netip.MustParseAddr("192.0.2.11")
	other.Snapshot = &model.DeviceSnapshot{CollectionComplete: true, SnapshotStable: true, AbsenceEligible: false}
	r.Outcomes = append(r.Outcomes, other)
	commitRound(t, s, r)
	if countRows(t, s, "scan_devices") != 2 {
		t.Fatal("same chassis created duplicate coverage rows")
	}
}

func TestPortAliasesSurviveLaterScans(t *testing.T) {
	s := setupStore(t)
	r := sampleResult()
	r.Ports[0].Aliases = []topology.PortKey{r.Ports[0].Key, "lldp:5:cccc"}
	commitRound(t, s, r)
	r.Ports[0].Aliases = []topology.PortKey{r.Ports[0].Key}
	commitRound(t, s, r)
	var count int
	if err := s.Conn().QueryRow(context.Background(), `SELECT jsonb_array_length(aliases) FROM ports WHERE port_key='lldp:5:aa'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatal("persistent alias history was overwritten")
	}
}
