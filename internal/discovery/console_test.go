package discovery

import (
	"context"
	"gonet/internal/model"
	"net/netip"
	"testing"
)

func TestExcludedAddressNeverProbedAndProgressTracksTasks(t *testing.T) {
	snaps := ringTopology(t)
	collector := newFakeCollector(snaps)
	c := newRingCoordinator(t, collector, []netip.Addr{mustAddr(t, "192.0.2.1")})
	c.opts.ExcludedCIDRs = []netip.Prefix{mustPrefix(t, "192.0.2.2/32")}
	var progress []Progress
	c.SetProgress(func(p Progress) { progress = append(progress, p) })
	r := c.Run(context.Background())
	if collector.callCount(mustAddr(t, "192.0.2.2")) != 0 {
		t.Fatal("excluded address was probed")
	}
	if len(progress) == 0 || progress[len(progress)-1].Completed != 2 {
		t.Fatalf("progress lost tasks: %+v result=%s", progress, r.Status)
	}
}

func TestUnreadableLocalChassisDoesNotReportIdentityConflict(t *testing.T) {
	snaps := ringTopology(t)
	snaps[mustAddr(t, "192.0.2.2")].Device.Chassis = model.TypedID{}
	c := newRingCoordinator(t, newFakeCollector(snaps), []netip.Addr{mustAddr(t, "192.0.2.1")})
	r := c.Run(context.Background())
	found := false
	for _, issue := range r.Issues {
		if issue.Code == "IDENTITY_CONFLICT" {
			t.Fatal("absent LLDP data was called a conflicting chassis")
		}
		found = found || issue.Code == "LLDP_LOCAL_UNAVAILABLE"
	}
	if !found || r.Status != "partial" {
		t.Fatal("unreadable local LLDP diagnostic missing")
	}
}
