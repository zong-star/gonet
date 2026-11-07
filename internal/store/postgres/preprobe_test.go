package postgres

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"gonet/internal/discovery"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/preprobe"
	"gonet/internal/topology"
)

type probeReplay struct {
	facts map[netip.Addr]model.DeviceInfo
	fail  bool
}

func (p probeReplay) Probe(_ context.Context, a netip.Addr) preprobe.Attempt {
	d, ok := p.facts[a]
	out := preprobe.Attempt{IP: a, ResponseIP: a, Facts: d, Attempted: true, Reachable: ok && !p.fail, PDUs: 2, At: time.Now().UTC()}
	if !out.Reachable {
		out.ErrorCode = "SNMP_TIMEOUT"
		out.ErrorReason = "SNMP timeout"
	}
	return out
}

func TestPreprobeIsolatedSchemaPersistence(t *testing.T) {
	s := discoveryTestStore(t)
	ctx := context.Background()
	ip := netip.MustParseAddr
	snap := func(addr string, n byte, peer byte) *model.DeviceSnapshot {
		d := &model.DeviceSnapshot{Device: model.DeviceInfo{Target: ip(addr), Chassis: model.TypedID{Subtype: 4, Raw: []byte{2, 0, 0, 0, 0, n}}, SysObjectID: "1.3.6.1.4.1.99999.1", SysName: "same-name"}, CollectionComplete: true, SnapshotStable: true, CollectedAt: time.Now().UTC(), LocalPorts: []model.LocalPort{{Number: 1, ID: model.TypedID{Subtype: 5, Raw: []byte("P1")}}}, Interfaces: []model.Interface{{IfIndex: 1, Name: "P1", Type: 6}}}
		if peer != 0 {
			d.Neighbors = []model.LLDPNeighbor{{Index: model.NeighborIndex{LocalPortNum: 1, RemoteIndex: 1}, Chassis: model.TypedID{Subtype: 4, Raw: []byte{2, 0, 0, 0, 0, peer}}, Port: model.TypedID{Subtype: 5, Raw: []byte("P1")}, CapEnabled: []byte{0x20}}}
		}
		return d
	}
	core, peer := ip("192.0.2.1"), ip("192.0.2.2")
	full := discoveryReplay{core: snap(core.String(), 1, 2), peer: snap(peer.String(), 2, 1)}
	basic := probeReplay{facts: map[netip.Addr]model.DeviceInfo{core: full[core].Device, peer: full[peer].Device, ip("192.0.2.3"): full[peer].Device, ip("192.0.2.4"): snap("192.0.2.4", 4, 0).Device}}
	run := func(enabled bool, ttl time.Duration) (int64, *discovery.Result) {
		t.Helper()
		id, e := s.BeginScan(ctx, ScanInput{ConfigDigest: "preprobe-fixture", KeepScans: 2})
		if e != nil {
			t.Fatal(e)
		}
		reg, e := identity.New(identity.Options{Rules: []identity.Rule{{ID: "fixture", SysObjectIDPrefix: "1.3.6.1.4.1.99999", Action: "switch"}}})
		if e != nil {
			t.Fatal(e)
		}
		c, e := discovery.New(discovery.Options{Seeds: []netip.Addr{core}, ManagementCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/29")}, MaxTargets: 600, MaxDepth: 4, Workers: 2, Registry: reg, Resolver: topology.NewResolver(nil), Collector: full, Preprobe: preprobe.Options{Enabled: enabled, Workers: 3, MaxHosts: 256, KnownHosts: 64, RefreshInterval: ttl, Prober: basic}})
		if e != nil {
			t.Fatal(e)
		}
		devices, ports, e := s.LoadContext(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if e = c.RestoreContext(devices, ports); e != nil {
			t.Fatal(e)
		}
		if enabled {
			pool, cursor, e := s.LoadProbeContext(ctx)
			if e != nil {
				t.Fatal(e)
			}
			c.SetProbeContext(pool, cursor)
		}
		r := c.Run(ctx)
		if e = s.CommitResult(ctx, id, r); e != nil {
			t.Fatal(e)
		}
		if e = s.CommitResult(ctx, id, r); e != nil {
			t.Fatal("duplicate commit", e)
		}
		return id, r
	}
	// Build a historical device/link first using advertised addresses, then
	// exercise the additive 5 -> 6 migration inside this private schema only.
	full[core].Neighbors[0].MgmtAddresses = []netip.Addr{peer}
	run(false, time.Minute)
	var beforeDev, beforeLink int64
	if e := s.Conn().QueryRow(ctx, `SELECT device_id FROM device_identities WHERE identity_key='lldp:4:020000000002'`).Scan(&beforeDev); e != nil {
		t.Fatal(e)
	}
	if e := s.Conn().QueryRow(ctx, `SELECT id FROM links`).Scan(&beforeLink); e != nil {
		t.Fatal(e)
	}
	var schema string
	if e := s.Conn().QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); e != nil || !strings.HasPrefix(schema, "gonet_test_discovery_") {
		t.Fatal("unsafe isolated upgrade fixture")
	}
	if _, e := s.Conn().Exec(ctx, `DROP TABLE snmp_probe_progress,snmp_probe_results; DELETE FROM schema_migrations WHERE version=6`); e != nil {
		t.Fatal(e)
	}
	if applied, e := Migrate(ctx, s.Conn()); e != nil || len(applied) != 1 || applied[0] != 6 {
		t.Fatalf("migration 6: %v %v", applied, e)
	}
	full[core].Neighbors[0].MgmtAddresses = nil
	first, r := run(true, time.Minute)
	if len(r.Devices) != 2 || len(r.Links) != 1 || len(r.Preprobe.Records) != 6 {
		t.Fatal("no-IP core recursion failed")
	}
	pool, summary, e := loadProbes(ctx, s.Conn())
	if e != nil {
		t.Fatal(e)
	}
	var successTime time.Time
	for _, p := range pool {
		if p.IP == peer {
			if p.MatchedDeviceID == nil || *p.MatchedDeviceID != beforeDev {
				t.Fatal("real device ID association lost")
			}
			successTime = *p.LastSuccess
		}
		if p.IP == ip("192.0.2.3") && (p.MatchedDeviceID == nil || *p.MatchedDeviceID != beforeDev) {
			t.Fatal("multi-IP identity grouping lost")
		}
		if p.IP == ip("192.0.2.4") && p.MatchedDeviceID != nil {
			t.Fatal("unassociated probe created a device")
		}
	}
	if summary.Cursor.Covered != 6 || countRows(t, s, "devices") != 2 || countRows(t, s, "links") != 1 {
		t.Fatal("pool polluted formal topology")
	}
	// Process restart is represented by a new coordinator restoring only DB state.
	_, r = run(true, time.Minute)
	if r.Preprobe.Summary.Completed != 2 {
		t.Fatalf("fresh successful cache was reprobed: %+v", r.Preprobe.Summary)
	} // two unresponsive IPs may retry
	// Fail both phases: previous successful facts and the existing graph survive.
	basic.fail = true
	delete(full, peer)
	run(true, time.Nanosecond)
	pool, _, e = loadProbes(ctx, s.Conn())
	if e != nil {
		t.Fatal(e)
	}
	for _, p := range pool {
		if p.IP == peer && (p.Status != "unresponsive" || !p.LastSuccess.Equal(successTime) || p.Facts.SysName != "same-name") {
			t.Fatal("failed retry destroyed success history")
		}
	}
	var afterDev, afterLink int64
	if e = s.Conn().QueryRow(ctx, `SELECT device_id FROM device_identities WHERE identity_key='lldp:4:020000000002'`).Scan(&afterDev); e != nil {
		t.Fatal(e)
	}
	if e = s.Conn().QueryRow(ctx, `SELECT id FROM links`).Scan(&afterLink); e != nil {
		t.Fatal(e)
	}
	if beforeDev != afterDev || beforeLink != afterLink {
		t.Fatal("stable device/link ID changed")
	}
	// Aborted positive-only commits are accepted, never age the formal graph.
	id, e := s.BeginScan(ctx, ScanInput{ConfigDigest: "canceled", KeepScans: 2})
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	p := pool[0]
	p.LastAttempt = now
	positive := &discovery.Result{Status: "aborted", Preprobe: preprobe.Batch{Records: []preprobe.Record{p}, Summary: preprobe.Summary{Enabled: true, Cursor: summary.Cursor}}}
	if e = s.CommitResult(ctx, id, positive); e != nil {
		t.Fatal(e)
	}
	if _, e = s.PruneHistory(ctx, 2); e != nil {
		t.Fatal(e)
	}
	var exists bool
	if e = s.Conn().QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM scan_runs WHERE id=$1)`, first).Scan(&exists); e != nil || exists {
		t.Fatal("old fixture scan was not pruned")
	}
	pool, _, e = loadProbes(ctx, s.Conn())
	if e != nil || len(pool) != 6 {
		t.Fatal("history cleanup removed probe pool")
	}
	for _, p := range pool {
		if p.IP == ip("192.0.2.4") && p.Facts == nil {
			t.Fatal("orphan facts depended on scan_devices")
		}
	}
	if applied, e := Migrate(ctx, s.Conn()); e != nil || len(applied) != 0 {
		t.Fatal("repeat migration not idempotent")
	}
	raw, e := json.Marshal(pool)
	if e != nil || strings.Contains(string(raw), "community") {
		t.Fatal("unsafe probe export")
	}
}
