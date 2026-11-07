package discovery

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/topology"
)

var t301Time = time.Unix(1700000000, 0).UTC()

type fakeCollector struct {
	mu        sync.Mutex
	snapshots map[netip.Addr]*model.DeviceSnapshot
	calls     map[netip.Addr]int
	order     []netip.Addr
	blockOn   map[netip.Addr]bool
	active    sync.WaitGroup
}

func newFakeCollector(snaps map[netip.Addr]*model.DeviceSnapshot) *fakeCollector {
	return &fakeCollector{snapshots: snaps, calls: map[netip.Addr]int{}, blockOn: map[netip.Addr]bool{}}
}

func (f *fakeCollector) Collect(ctx context.Context, t model.DiscoveryTarget) (*model.DeviceSnapshot, error) {
	f.active.Add(1)
	defer f.active.Done()

	f.mu.Lock()
	f.calls[t.Address]++
	f.order = append(f.order, t.Address)
	block := f.blockOn[t.Address]
	snap := f.snapshots[t.Address]
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if snap == nil {
		return nil, fmt.Errorf("no snapshot for %s", t.Address)
	}
	return snap, nil
}

func (f *fakeCollector) callCount(a netip.Addr) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[a]
}

func (f *fakeCollector) callOrder() []netip.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]netip.Addr, len(f.order))
	copy(out, f.order)
	return out
}

func (f *fakeCollector) noLeak(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() { f.active.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("collector goroutines leaked after Run")
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("bad addr %q: %v", s, err)
	}
	return a
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("bad cidr %q: %v", s, err)
	}
	return p
}

func newTestRegistry(t *testing.T) *identity.Registry {
	t.Helper()
	r, err := identity.New(identity.Options{
		Now: func() time.Time { return t301Time },
		Rules: []identity.Rule{
			{ID: "test-switch", SysObjectIDPrefix: "1.3.6.1.4.1.99999", Action: "switch"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func newTestResolver() *topology.Resolver {
	return topology.NewResolver(topology.NewPortRegistry(func() time.Time { return t301Time }))
}

func lp(num uint32, ifName string) model.LocalPort {
	return model.LocalPort{Number: num, ID: model.TypedID{Subtype: 5, Raw: []byte(ifName)}}
}

func ifc(idx int32, name string) model.Interface {
	return model.Interface{IfIndex: idx, Name: name, Type: 6}
}

func nb(tm, lpn, ri uint32, mac []byte, peerPort string, peerIP netip.Addr) model.LLDPNeighbor {
	return model.LLDPNeighbor{
		Index:         model.NeighborIndex{TimeMark: tm, LocalPortNum: lpn, RemoteIndex: ri},
		Chassis:       model.TypedID{Subtype: 4, Raw: mac},
		Port:          model.TypedID{Subtype: 5, Raw: []byte(peerPort)},
		MgmtAddresses: []netip.Addr{peerIP},
	}
}

func devSnap(target netip.Addr, mac []byte, sysName string, ports []model.LocalPort, ifaces []model.Interface, neighbors []model.LLDPNeighbor) *model.DeviceSnapshot {
	return &model.DeviceSnapshot{
		SchemaVersion: model.SchemaVersion,
		Device: model.DeviceInfo{
			Target: target, Chassis: model.TypedID{Subtype: 4, Raw: mac}, SysName: sysName,
			SysObjectID: "1.3.6.1.4.1.99999.1.1", CapSupported: []byte{0x20}, CapEnabled: []byte{0x20},
		},
		LocalPorts:         ports,
		Interfaces:         ifaces,
		Neighbors:          neighbors,
		CollectionComplete: true,
		SnapshotStable:     true,
		CollectedAt:        t301Time,
	}
}

// ringTopology returns A-B-C-A ring snapshots.
func ringTopology(t *testing.T) map[netip.Addr]*model.DeviceSnapshot {
	a := mustAddr(t, "192.0.2.1")
	b := mustAddr(t, "192.0.2.2")
	c := mustAddr(t, "192.0.2.3")
	macA := []byte{0, 0, 0, 0, 0, 1}
	macB := []byte{0, 0, 0, 0, 0, 2}
	macC := []byte{0, 0, 0, 0, 0, 3}

	snapA := devSnap(a, macA, "A",
		[]model.LocalPort{lp(1, "Gi1"), lp(2, "Gi3")},
		[]model.Interface{ifc(101, "Gi1"), ifc(102, "Gi3")},
		[]model.LLDPNeighbor{
			nb(7, 1, 1, macB, "Gi2", b),
			nb(7, 2, 1, macC, "Gi4", c),
		})
	snapB := devSnap(b, macB, "B",
		[]model.LocalPort{lp(1, "Gi2"), lp(2, "Gi5")},
		[]model.Interface{ifc(201, "Gi2"), ifc(202, "Gi5")},
		[]model.LLDPNeighbor{
			nb(7, 1, 1, macA, "Gi1", a),
			nb(7, 2, 1, macC, "Gi6", c),
		})
	snapC := devSnap(c, macC, "C",
		[]model.LocalPort{lp(1, "Gi4"), lp(2, "Gi6")},
		[]model.Interface{ifc(301, "Gi4"), ifc(302, "Gi6")},
		[]model.LLDPNeighbor{
			nb(7, 1, 1, macA, "Gi3", a),
			nb(7, 2, 1, macB, "Gi5", b),
		})
	return map[netip.Addr]*model.DeviceSnapshot{a: snapA, b: snapB, c: snapC}
}

func newRingCoordinator(t *testing.T, fc *fakeCollector, seeds []netip.Addr) *Coordinator {
	t.Helper()
	c, err := New(Options{
		Seeds:                 seeds,
		ManagementCIDRs:       []netip.Prefix{mustPrefix(t, "192.0.2.0/24")},
		MaxDepth:              8,
		MaxDevices:            200,
		MaxTargets:            600,
		Workers:               4,
		MaxAddressesPerDevice: 3,
		Collector:             fc,
		Registry:              newTestRegistry(t),
		Resolver:              newTestResolver(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// D01: ring A-B-C-A with duplicate seeds. One task per IP, no duplicate graph
// nodes, finite termination.
func TestD01RingDuplicateSeeds(t *testing.T) {
	fc := newFakeCollector(ringTopology(t))
	a := mustAddr(t, "192.0.2.1")
	b := mustAddr(t, "192.0.2.2")
	c := mustAddr(t, "192.0.2.3")
	coord := newRingCoordinator(t, fc, []netip.Addr{a, a}) // duplicate seed
	out := coord.Run(context.Background())

	if out.Status != "completed" {
		t.Fatalf("status = %q, want completed; issues=%+v", out.Status, out.Issues)
	}
	for _, addr := range []netip.Addr{a, b, c} {
		if n := fc.callCount(addr); n != 1 {
			t.Errorf("%s collected %d times, want 1", addr, n)
		}
	}
	if len(out.Devices) != 3 {
		t.Errorf("devices = %d, want 3", len(out.Devices))
	}
	if len(out.Links) != 3 {
		t.Fatalf("links = %d, want 3", len(out.Links))
	}
	for _, ev := range out.Links {
		if ev.Confidence() != "bidirectional" {
			t.Errorf("link %+v confidence = %q", ev.Key, ev.Confidence())
		}
	}
	// C is reachable at depth 1 (from A) and depth 2 (from B): min depth wins.
	for _, oc := range out.Outcomes {
		if oc.Target.Address == c && oc.Target.Depth != 1 {
			t.Errorf("C depth = %d, want 1 (min depth)", oc.Target.Depth)
		}
	}
	if len(out.Observations) != 6 {
		t.Errorf("observations = %d, want 6", len(out.Observations))
	}
}

// D02: a neighbor discovered (in the graph) but not yet collected must still be
// scanned, not blocked by a visited flag.
func TestD02DiscoveredNeighborStillScanned(t *testing.T) {
	a := mustAddr(t, "192.0.2.1")
	b := mustAddr(t, "192.0.2.2")
	macA := []byte{0, 0, 0, 0, 0, 1}
	macB := []byte{0, 0, 0, 0, 0, 2}

	snapA := devSnap(a, macA, "A",
		[]model.LocalPort{lp(1, "Gi1")}, []model.Interface{ifc(101, "Gi1")},
		[]model.LLDPNeighbor{nb(7, 1, 1, macB, "Gi2", b)})
	snapB := devSnap(b, macB, "B",
		[]model.LocalPort{lp(1, "Gi2")}, []model.Interface{ifc(201, "Gi2")},
		[]model.LLDPNeighbor{nb(7, 1, 1, macA, "Gi1", a)})
	fc := newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{a: snapA, b: snapB})

	coord := newRingCoordinator(t, fc, []netip.Addr{a})
	out := coord.Run(context.Background())

	if fc.callCount(b) != 1 {
		t.Fatalf("discovered neighbor B collected %d times, want 1", fc.callCount(b))
	}
	if len(out.Devices) != 2 {
		t.Errorf("devices = %d, want 2", len(out.Devices))
	}
	if len(out.Links) != 1 {
		t.Fatalf("links = %d, want 1", len(out.Links))
	}
	if out.Links[0].Confidence() != "bidirectional" {
		t.Errorf("A-B confidence = %q, want bidirectional", out.Links[0].Confidence())
	}
}

// Cancellation stops new tasks and returns aborted without deadlock.
func TestCancellation(t *testing.T) {
	a := mustAddr(t, "192.0.2.1")
	macA := []byte{0, 0, 0, 0, 0, 1}
	snapA := devSnap(a, macA, "A", nil, nil, nil)
	fc := newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{a: snapA})
	fc.blockOn[a] = true

	coord := newRingCoordinator(t, fc, []netip.Addr{a})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	out := coord.Run(ctx)
	if out.Status != "aborted" {
		t.Errorf("status = %q, want aborted", out.Status)
	}
}
