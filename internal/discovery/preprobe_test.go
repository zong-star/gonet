package discovery

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"gonet/internal/model"
	"gonet/internal/preprobe"
)

type basicReplay map[netip.Addr]model.DeviceInfo

func (f basicReplay) Probe(_ context.Context, a netip.Addr) preprobe.Attempt {
	d, ok := f[a]
	return preprobe.Attempt{IP: a, ResponseIP: a, Facts: d, Attempted: true, Reachable: ok, At: time.Now().UTC(), PDUs: 2}
}

func TestPreprobeNoManagementIPRecursiveMultiIPAndUnassociated(t *testing.T) {
	snaps := fourSwitchTopology(t)
	basic := basicReplay{}
	for a, s := range snaps {
		copy := *s
		copy.Neighbors = append([]model.LLDPNeighbor(nil), s.Neighbors...)
		for i := range copy.Neighbors {
			copy.Neighbors[i].MgmtAddresses = nil
		}
		snaps[a] = &copy
		basic[a] = s.Device
	}
	agg := mustAddr(t, "192.0.2.2")
	alias := mustAddr(t, "192.0.2.5")
	orphan := mustAddr(t, "192.0.2.6")
	basic[alias] = basic[agg]
	aliasSnapshot := *snaps[agg]
	aliasSnapshot.Device = snaps[agg].Device
	aliasSnapshot.Device.Target = alias
	snaps[alias] = &aliasSnapshot
	other := basic[agg]
	other.Target = orphan
	other.Chassis = model.TypedID{Subtype: 4, Raw: []byte{2, 0, 0, 0, 0, 6}}
	basic[orphan] = other
	f := newFakeCollector(snaps)
	c, err := New(Options{Seeds: []netip.Addr{mustAddr(t, "192.0.2.1")}, ManagementCIDRs: []netip.Prefix{mustPrefix(t, "192.0.2.0/29")}, MaxDepth: 4, MaxTargets: 600, Workers: 3, Registry: newTestRegistry(t), Resolver: newTestResolver(), Collector: f, Preprobe: preprobe.Options{Enabled: true, Workers: 3, MaxHosts: 256, RefreshInterval: time.Minute, Prober: basic}})
	if err != nil {
		t.Fatal(err)
	}
	r := c.Run(context.Background())
	if len(r.Devices) != 4 || len(r.Links) != 5 || r.Counts.DevicesCollected != 4 {
		t.Fatalf("recursive no-management-IP topology failed: devices=%d links=%d counts=%+v issues=%+v", len(r.Devices), len(r.Links), r.Counts, r.Issues)
	}
	if f.callCount(orphan) != 0 || f.callCount(alias)+f.callCount(agg) != 1 {
		t.Fatal("probe IP became an extra seed or duplicate collection")
	}
	if len(r.Preprobe.Records) != 6 || r.Counts.AdmittedCandidates != 6 || r.Preprobe.Summary.Completed != 6 || r.Counts.CollectCompleted != 4 {
		t.Fatalf("phase/unique counts wrong: %+v %+v", r.Counts, r.Preprobe.Summary)
	}
	if f.callCount(mustAddr(t, "192.0.2.4")) != 1 {
		t.Fatal("second-hop access switch not recursively collected")
	}
	for _, d := range r.Devices {
		if d.Chassis.Raw[5] == 2 {
			if len(d.Addresses) == 0 || d.Addresses[0].Source != "snmp_preprobe" {
				t.Fatal("automatic hint was labeled as a seed or manual override")
			}
		}
		if d.Chassis.Raw[5] == 6 {
			t.Fatal("same sysName merged or orphan admitted")
		}
	}
}

func TestPreprobeCollectionIPReuseFreezesLinks(t *testing.T) {
	snaps := ringTopology(t)
	basic := basicReplay{}
	for a, s := range snaps {
		basic[a] = s.Device
		for i := range s.Neighbors {
			s.Neighbors[i].MgmtAddresses = nil
		}
	}
	peer := mustAddr(t, "192.0.2.2")
	copy := *snaps[peer]
	copy.Device = snaps[peer].Device
	copy.Device.Chassis = model.TypedID{Subtype: 4, Raw: []byte{2, 0, 0, 0, 0, 99}}
	snaps[peer] = &copy
	c, err := New(Options{Seeds: []netip.Addr{mustAddr(t, "192.0.2.1")}, ManagementCIDRs: []netip.Prefix{mustPrefix(t, "192.0.2.0/29")}, MaxDepth: 4, MaxTargets: 600, Workers: 2, Registry: newTestRegistry(t), Resolver: newTestResolver(), Collector: newFakeCollector(snaps), Preprobe: preprobe.Options{Enabled: true, Workers: 2, MaxHosts: 20, RefreshInterval: time.Minute, Prober: basic}})
	if err != nil {
		t.Fatal(err)
	}
	r := c.Run(context.Background())
	found := false
	for _, p := range r.Preprobe.Records {
		if p.IP == peer {
			found = p.Conflict && p.PreviousFacts != nil
		}
	}
	if !found {
		t.Fatal("changed IP identity was not quarantined")
	}
	for _, o := range r.Outcomes {
		if o.Target.Address == peer {
			t.Fatal("IP reuse was accepted")
		}
	}
	for _, l := range r.Links {
		for _, d := range r.Devices {
			if d.Chassis.Raw[5] == 2 && (l.Key.A == d.Ref || l.Key.B == d.Ref) {
				t.Fatal("conflicted endpoint produced a physical link")
			}
		}
	}
}

func TestPreprobeRingAndUniqueTargetReservation(t *testing.T) {
	snaps := ringTopology(t)
	basic := basicReplay{}
	for a, s := range snaps {
		basic[a] = s.Device
		for i := range s.Neighbors {
			s.Neighbors[i].MgmtAddresses = nil
		}
	}
	f := newFakeCollector(snaps)
	c, err := New(Options{Seeds: []netip.Addr{mustAddr(t, "192.0.2.1")}, ManagementCIDRs: []netip.Prefix{mustPrefix(t, "192.0.2.0/30"), mustPrefix(t, "192.0.2.3/32")}, MaxDepth: 4, MaxTargets: 6, Workers: 2, Registry: newTestRegistry(t), Resolver: newTestResolver(), Collector: f, Preprobe: preprobe.Options{Enabled: true, Workers: 2, MaxHosts: 20, RefreshInterval: time.Minute, Prober: basic}})
	if err != nil {
		t.Fatal(err)
	}
	r := c.Run(context.Background())
	if r.Counts.AdmittedCandidates != 3 || r.Counts.DevicesCollected != 3 || len(r.Links) != 3 || r.Preprobe.Summary.Completed != 3 {
		t.Fatalf("two-stage visited/budget broken: %+v %+v", r.Counts, r.Preprobe.Summary)
	}
	for a := range snaps {
		if f.callCount(a) != 1 {
			t.Fatal("ring repeated collection", a)
		}
	}
}

func TestPreprobeDeadlineLeavesCoreBudget(t *testing.T) {
	core := mustAddr(t, "192.0.2.1")
	snaps := map[netip.Addr]*model.DeviceSnapshot{core: devSnap(core, []byte{2, 0, 0, 0, 0, 1}, "core", nil, nil, nil)}
	p := blockingBasic{}
	c, err := New(Options{Seeds: []netip.Addr{core}, ManagementCIDRs: []netip.Prefix{mustPrefix(t, "192.0.2.0/24")}, MaxTargets: 2, Workers: 1, Registry: newTestRegistry(t), Resolver: newTestResolver(), Collector: newFakeCollector(snaps), Preprobe: preprobe.Options{Enabled: true, Workers: 1, MaxHosts: 256, PhaseTimeout: 10 * time.Millisecond, RefreshInterval: time.Minute, Prober: p}})
	if err != nil {
		t.Fatal(err)
	}
	r := c.Run(context.Background())
	if r.Counts.DevicesCollected != 1 || r.Counts.AdmittedCandidates > 2 || r.Preprobe.Summary.Termination != "phase_deadline" {
		t.Fatalf("preprobe consumed core budget %+v %+v", r.Counts, r.Preprobe.Summary)
	}
}

type blockingBasic struct{}

func (blockingBasic) Probe(ctx context.Context, a netip.Addr) preprobe.Attempt {
	<-ctx.Done()
	return preprobe.Attempt{IP: a, Attempted: true, ErrorCode: "SNMP_TIMEOUT", At: time.Now()}
}

func TestPreprobeDisabledAndLegacySupplementBudget(t *testing.T) {
	for _, manual := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "legacy_supplement"}[manual], func(t *testing.T) {
			snaps := ringTopology(t)
			if manual {
				for _, s := range snaps {
					for i := range s.Neighbors {
						s.Neighbors[i].MgmtAddresses = nil
					}
				}
			}
			c, e := New(Options{Seeds: []netip.Addr{mustAddr(t, "192.0.2.1")}, ManagementCIDRs: []netip.Prefix{mustPrefix(t, "192.0.2.0/24")}, MaxTargets: 6, MaxDepth: 4, Registry: newTestRegistry(t), Resolver: newTestResolver(), Collector: newFakeCollector(snaps), Preprobe: preprobe.Options{Enabled: manual, Prober: panicBasic{}}})
			if e != nil {
				t.Fatal(e)
			}
			if manual {
				var addrs []netip.Addr
				hints := map[string][]netip.Addr{}
				for a, s := range snaps {
					addrs = append(addrs, a)
					key, _ := c.opts.Registry.EvidenceKey(s.Device.Chassis)
					hints[key] = []netip.Addr{a}
				}
				if len(c.PrepareSupplement(addrs)) != 3 {
					t.Fatal("legacy target reservations lost")
				}
				c.SetSupplementHints(hints)
			}
			r := c.Run(context.Background())
			if r.Counts.DevicesCollected != 3 || r.Counts.AdmittedCandidates != 3 || r.Preprobe.Summary.Completed != 0 || len(r.Links) != 3 {
				t.Fatalf("legacy flow/budget changed: %+v", r.Counts)
			}
		})
	}
}

type panicBasic struct{}

func (panicBasic) Probe(context.Context, netip.Addr) preprobe.Attempt {
	panic("disabled automatic mode issued a probe")
}

func TestStaleProbeConflictAndMissingFullChassis(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale_address_reuse", true: "local_chassis_unavailable"}[missing], func(t *testing.T) {
			a := mustAddr(t, "192.0.2.2")
			reg := newTestRegistry(t)
			c, e := New(Options{Registry: reg, Collector: newFakeCollector(nil), Resolver: newTestResolver(), Preprobe: preprobe.Options{Enabled: true, RefreshInterval: time.Minute}})
			if e != nil {
				t.Fatal(e)
			}
			at := time.Now().Add(-time.Hour)
			facts := model.DeviceInfo{Target: a, Chassis: model.TypedID{Subtype: 4, Raw: []byte{2, 0, 0, 0, 0, 2}}}
			key, _ := reg.EvidenceKey(facts.Chassis)
			r := preprobe.Record{IP: a, Identity: key, Facts: &facts, Status: "identified", LastSuccess: &at, LastIdentitySuccess: &at}
			c.probeIndex = preprobe.NewIndex([]preprobe.Record{r}, preprobe.NewRange([]netip.Prefix{mustPrefix(t, "192.0.2.0/24")}, nil, false), time.Minute, reg)
			current := facts
			current.Chassis = model.TypedID{Subtype: 4, Raw: []byte{2, 0, 0, 0, 0, 99}}
			if missing {
				current.Chassis = model.TypedID{}
			}
			if c.verifyProbeSnapshot(taskResult{Addr: a, Snapshot: &model.DeviceSnapshot{Device: current}}) {
				t.Fatal("unverified/reused access address was accepted")
			}
			p, _ := c.probeIndex.ByIP(a)
			if missing {
				if p.Conflict || len(c.probeBatch.Records) != 0 || c.issues[0].Code != "LLDP_LOCAL_UNAVAILABLE" {
					t.Fatal("missing scalar fabricated an identity conflict")
				}
			} else if !p.Conflict || p.PreviousFacts == nil {
				t.Fatal("stale evidence permitted silent IP reassignment")
			}
		})
	}
}

// A small batch must not gate in-scope LLDP hints or deeper recursion.
// Only the core fits in preprobe; the other devices are reached from LLDP.
func TestBatchedPreprobeDoesNotGateAdvertisedNeighbor(t *testing.T) {
	for _, mode := range []string{"allowed", "excluded", "identity_mismatch"} {
		t.Run(mode, func(t *testing.T) {
			snaps := fourSwitchTopology(t)
			core, peer := mustAddr(t, "192.0.2.1"), mustAddr(t, "192.0.2.2")
			basic := basicReplay{core: snaps[core].Device}
			if mode == "identity_mismatch" {
				copy := *snaps[peer]
				copy.Device.Chassis = model.TypedID{Subtype: 4, Raw: []byte{2, 0, 0, 0, 0, 99}}
				snaps[peer] = &copy
			}
			f := newFakeCollector(snaps)
			opts := Options{Seeds: []netip.Addr{core}, ManagementCIDRs: []netip.Prefix{mustPrefix(t, "192.0.2.0/29")}, MaxDepth: 4, MaxTargets: 100, Workers: 2, Registry: newTestRegistry(t), Resolver: newTestResolver(), Collector: f, Preprobe: preprobe.Options{Enabled: true, Workers: 1, MaxHosts: 1, PhaseTimeout: time.Second, RefreshInterval: time.Minute, Prober: basic}}
			if mode == "excluded" {
				opts.ExcludedCIDRs = []netip.Prefix{mustPrefix(t, "192.0.2.2/32")}
			}
			c, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			r := c.Run(context.Background())
			if r.Preprobe.Summary.Completed != 1 {
				t.Fatalf("unexpected batch size: %+v", r.Preprobe.Summary)
			}
			for _, p := range r.Preprobe.Records {
				if p.IP == peer {
					t.Fatal("peer unexpectedly fitted in preprobe batch")
				}
			}
			if mode == "allowed" {
				if len(r.Devices) != 4 || len(r.Links) != 5 || f.callCount(peer) != 1 || f.callCount(mustAddr(t, "192.0.2.4")) != 1 {
					t.Fatalf("advertised neighbor or its child was not collected and linked: devices=%d links=%d peer=%d", len(r.Devices), len(r.Links), f.callCount(peer))
				}
				for _, d := range r.Devices {
					if d.Chassis.Raw[len(d.Chassis.Raw)-1] == 2 {
						found := false
						for _, a := range d.Addresses {
							if a.Addr == peer && a.Source == "lldp" {
								found = true
							}
						}
						if !found {
							t.Fatal("directly advertised access provenance lost")
						}
					}
				}
			} else {
				for _, d := range r.Devices {
					if d.Chassis.Raw[len(d.Chassis.Raw)-1] == 2 || d.Chassis.Raw[len(d.Chassis.Raw)-1] == 99 {
						t.Fatal("excluded or unverified peer admitted")
					}
				}
				if mode == "excluded" && f.callCount(peer) != 0 {
					t.Fatal("excluded advertised address was requested")
				}
				if mode == "identity_mismatch" && !hasIssue(r.Issues, "IDENTITY_CONFLICT") {
					t.Fatal("direct/advertised chassis mismatch was not reported")
				}
			}
		})
	}
}
