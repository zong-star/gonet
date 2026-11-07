package discovery

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"gonet/internal/model"
)

func newCoord(t *testing.T, fc *fakeCollector, o Options) *Coordinator {
	t.Helper()
	o.Collector = fc
	o.Registry = newTestRegistry(t)
	o.Resolver = newTestResolver()
	if o.Workers == 0 {
		o.Workers = 4
	}
	c, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func hasIssue(issues []model.Issue, code string) bool {
	for _, i := range issues {
		if i.Code == code {
			return true
		}
	}
	return false
}

// linearTopology returns A -> B -> C (each snapshot sees only the next hop).
func linearTopology(t *testing.T) map[netip.Addr]*model.DeviceSnapshot {
	a := mustAddr(t, "192.0.2.1")
	b := mustAddr(t, "192.0.2.2")
	c := mustAddr(t, "192.0.2.3")
	macA := []byte{0, 0, 0, 0, 0, 1}
	macB := []byte{0, 0, 0, 0, 0, 2}
	macC := []byte{0, 0, 0, 0, 0, 3}
	return map[netip.Addr]*model.DeviceSnapshot{
		a: devSnap(a, macA, "A", []model.LocalPort{lp(1, "Gi1")}, []model.Interface{ifc(101, "Gi1")},
			[]model.LLDPNeighbor{nb(7, 1, 1, macB, "Gi2", b)}),
		b: devSnap(b, macB, "B", []model.LocalPort{lp(1, "Gi2"), lp(2, "Gi4")}, []model.Interface{ifc(201, "Gi2"), ifc(202, "Gi4")},
			[]model.LLDPNeighbor{nb(7, 2, 1, macC, "Gi3", c)}),
		c: devSnap(c, macC, "C", []model.LocalPort{lp(1, "Gi3")}, []model.Interface{ifc(301, "Gi3")}, nil),
	}
}

// D03: first candidate address fails, second succeeds; the device is collected
// once and merged after identity verification, within budget.
func TestD03AddressFallback(t *testing.T) {
	a := mustAddr(t, "192.0.2.1")
	bad := mustAddr(t, "192.0.2.11")
	good := mustAddr(t, "192.0.2.12")
	macA := []byte{0, 0, 0, 0, 0, 1}
	macB := []byte{0, 0, 0, 0, 0, 2}

	snapA := devSnap(a, macA, "A", []model.LocalPort{lp(1, "Gi1")}, []model.Interface{ifc(101, "Gi1")},
		[]model.LLDPNeighbor{
			{
				Index:         model.NeighborIndex{TimeMark: 7, LocalPortNum: 1, RemoteIndex: 1},
				Chassis:       model.TypedID{Subtype: 4, Raw: macB},
				Port:          model.TypedID{Subtype: 5, Raw: []byte("Gi2")},
				MgmtAddresses: []netip.Addr{bad, good},
			},
		})
	snapB := devSnap(good, macB, "B", []model.LocalPort{lp(1, "Gi2")}, []model.Interface{ifc(201, "Gi2")},
		[]model.LLDPNeighbor{nb(7, 1, 1, macA, "Gi1", a)})

	fc := newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{a: snapA, good: snapB})
	coord := newCoord(t, fc, Options{
		Seeds:                 []netip.Addr{a},
		ManagementCIDRs:       []netip.Prefix{mustPrefix(t, "192.0.2.0/24")},
		MaxDepth:              8,
		MaxDevices:            200,
		MaxTargets:            600,
		MaxAddressesPerDevice: 3,
	})
	out := coord.Run(context.Background())

	if fc.callCount(bad) != 1 || fc.callCount(good) != 1 {
		t.Fatalf("calls bad=%d good=%d, want 1/1", fc.callCount(bad), fc.callCount(good))
	}
	order := fc.callOrder()
	if len(order) < 3 || order[1] != bad || order[2] != good {
		t.Errorf("call order = %v, want bad then good", order)
	}
	if out.Status != "completed" {
		t.Errorf("status = %q, want completed; issues=%+v", out.Status, out.Issues)
	}
	if out.Counts.DevicesCollected != 2 {
		t.Errorf("devices collected = %d, want 2", out.Counts.DevicesCollected)
	}
	if len(out.Links) != 1 || out.Links[0].Confidence() != "bidirectional" {
		t.Errorf("links = %+v, want one bidirectional", out.Links)
	}
	if out.Counts.AdmittedCandidates > 3 {
		t.Errorf("admitted candidates = %d, want <=3 (budget)", out.Counts.AdmittedCandidates)
	}
}

// D04: depth/device/target boundaries. Only a truly new branch truncated makes
// the run partial; a topology inside the bounds completes.
func TestD04Budgets(t *testing.T) {
	a := mustAddr(t, "192.0.2.1")
	b := mustAddr(t, "192.0.2.2")
	c := mustAddr(t, "192.0.2.3")

	cases := []struct {
		name       string
		maxDepth   int
		maxDevices int
		maxTargets int
		wantStatus string
		wantC      bool
		wantIssue  string
	}{
		{"within depth", 2, 200, 600, "completed", true, ""},
		{"depth limit", 1, 200, 600, "partial", false, "DEPTH_LIMIT"},
		{"device limit", 8, 2, 600, "partial", false, "DEVICE_LIMIT"},
		{"target limit", 8, 200, 2, "partial", false, "TARGET_LIMIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc := newFakeCollector(linearTopology(t))
			coord := newCoord(t, fc, Options{
				Seeds:                 []netip.Addr{a},
				ManagementCIDRs:       []netip.Prefix{mustPrefix(t, "192.0.2.0/24")},
				MaxDepth:              tc.maxDepth,
				MaxDevices:            tc.maxDevices,
				MaxTargets:            tc.maxTargets,
				MaxAddressesPerDevice: 3,
			})
			out := coord.Run(context.Background())
			if out.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q; issues=%+v", out.Status, tc.wantStatus, out.Issues)
			}
			if got := fc.callCount(c); (got > 0) != tc.wantC {
				t.Errorf("C collected %d times, want collected=%v", got, tc.wantC)
			}
			if tc.wantIssue != "" && !hasIssue(out.Issues, tc.wantIssue) {
				t.Errorf("missing %s issue: %+v", tc.wantIssue, out.Issues)
			}
			if tc.wantStatus == "completed" && out.Counts.DevicesCollected != 3 {
				t.Errorf("devices collected = %d, want 3", out.Counts.DevicesCollected)
			}
			_ = b
		})
	}
}

// D05: out-of-scope, multicast and link-local seeds/candidates generate no
// network request and record branch termination reasons.
func TestD05InvalidAddressesNoNetwork(t *testing.T) {
	a := mustAddr(t, "192.0.2.1")
	multicast := mustAddr(t, "224.0.0.1")
	linkLocal := mustAddr(t, "fe80::1")
	outOfScope := mustAddr(t, "10.0.0.1")
	macA := []byte{0, 0, 0, 0, 0, 1}
	snapA := devSnap(a, macA, "A", nil, nil, nil)

	fc := newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{a: snapA})
	coord := newCoord(t, fc, Options{
		Seeds:                 []netip.Addr{a, multicast, linkLocal, outOfScope},
		ManagementCIDRs:       []netip.Prefix{mustPrefix(t, "192.0.2.0/24")},
		MaxDepth:              8,
		MaxDevices:            200,
		MaxTargets:            600,
		MaxAddressesPerDevice: 3,
	})
	out := coord.Run(context.Background())

	for _, bad := range []netip.Addr{multicast, linkLocal, outOfScope} {
		if n := fc.callCount(bad); n != 0 {
			t.Errorf("%s was contacted %d times, want 0", bad, n)
		}
	}
	if !hasIssue(out.Issues, "ADDRESS_INVALID") {
		t.Errorf("missing ADDRESS_INVALID issue: %+v", out.Issues)
	}
	if !hasIssue(out.Issues, "ADDRESS_OUT_OF_SCOPE") {
		t.Errorf("missing ADDRESS_OUT_OF_SCOPE issue: %+v", out.Issues)
	}
	if out.Counts.DevicesCollected != 1 {
		t.Errorf("devices collected = %d, want 1 (only the valid seed)", out.Counts.DevicesCollected)
	}
}

// D06: full-run timeout with a slow request returns partial without deadlock or
// leaked collector goroutines.
func TestD06TimeoutNoLeak(t *testing.T) {
	a := mustAddr(t, "192.0.2.1")
	macA := []byte{0, 0, 0, 0, 0, 1}
	fc := newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{a: devSnap(a, macA, "A", nil, nil, nil)})
	fc.blockOn[a] = true

	coord := newCoord(t, fc, Options{
		Seeds:                 []netip.Addr{a},
		ManagementCIDRs:       []netip.Prefix{mustPrefix(t, "192.0.2.0/24")},
		MaxDepth:              8,
		MaxDevices:            200,
		MaxTargets:            600,
		MaxAddressesPerDevice: 3,
		RunTimeout:            50 * time.Millisecond,
	})
	out := coord.Run(context.Background())
	if out.Status != "partial" {
		t.Errorf("status = %q, want partial", out.Status)
	}
	if !hasIssue(out.Issues, "RUN_TIMEOUT") {
		t.Errorf("missing RUN_TIMEOUT issue: %+v", out.Issues)
	}
	fc.noLeak(t)
}

// Candidate ordering: manual preference, verified, CIDR order, IPv4 first,
// numeric ascending.
func TestSortCandidates(t *testing.T) {
	cands := []candidateAddr{
		{Addr: mustAddr(t, "192.0.2.2"), CIDRIndex: 1},
		{Addr: mustAddr(t, "192.0.2.1"), CIDRIndex: 0},
		{Addr: mustAddr(t, "2001:db8::1"), CIDRIndex: 0},
		{Addr: mustAddr(t, "192.0.2.3"), CIDRIndex: 0, Verified: true},
		{Addr: mustAddr(t, "192.0.2.4"), CIDRIndex: 0, ManualPriority: -1},
	}
	sortCandidates(cands)

	want := []string{"192.0.2.4", "192.0.2.3", "192.0.2.1", "2001:db8::1", "192.0.2.2"}
	for i, w := range want {
		if cands[i].Addr.String() != w {
			t.Errorf("candidate[%d] = %s, want %s", i, cands[i].Addr, w)
		}
	}
}
