package discovery

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"gonet/internal/preprobe"
)

func TestFullProbeDoesNotExhaustRecursiveTargetBudgetOrAddSeeds(t *testing.T) {
	snaps := ringTopology(t)
	basic := basicReplay{}
	for a, s := range snaps {
		basic[a] = s.Device
		for i := range s.Neighbors {
			s.Neighbors[i].MgmtAddresses = nil
		}
	}
	c, err := New(Options{Seeds: []netip.Addr{mustAddr(t, "192.0.2.1")}, ManagementCIDRs: []netip.Prefix{mustPrefix(t, "192.0.0.0/22")}, MaxTargets: 3, MaxDepth: 4, Workers: 3, RunTimeout: time.Second, Registry: newTestRegistry(t), Resolver: newTestResolver(), Collector: newFakeCollector(snaps), Preprobe: preprobe.Options{Enabled: true, FullRange: true, Workers: 8, MaxHosts: 256, PhaseTimeout: time.Nanosecond, RefreshInterval: time.Minute, Prober: basic}})
	if err != nil {
		t.Fatal(err)
	}
	r := c.Run(context.Background())
	if r.Preprobe.Summary.Completed != 1022 || r.Preprobe.Summary.Deferred != 0 || r.Counts.DevicesCollected != 3 || r.Counts.AdmittedCandidates != 3 {
		t.Fatalf("full probe consumed recursive budget or created seeds: %+v %+v", r.Preprobe.Summary, r.Counts)
	}
}
