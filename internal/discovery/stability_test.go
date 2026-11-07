package discovery

import (
	"context"
	"fmt"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/topology"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// Synthetic, deterministic 8-regular graph. Each undirected cable gets its
// own local interface at both ends; no vendor support is implied.
func stressGraph(t *testing.T) map[netip.Addr]*model.DeviceSnapshot {
	out := map[netip.Addr]*model.DeviceSnapshot{}
	addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}) }
	mac := func(i int) []byte { return []byte{2, 0, 0, 0, 0, byte(i + 1)} }
	for i := 0; i < 200; i++ {
		var ports []model.LocalPort
		var ifaces []model.Interface
		var neighbors []model.LLDPNeighbor
		for n, offset := range []int{1, -1, 4, -4, 16, -16, 64, -64} {
			peer := (i + offset + 200) % 200
			name := fmt.Sprintf("to-%03d", peer)
			ports = append(ports, lp(uint32(n+1), name))
			ifaces = append(ifaces, ifc(int32(100+n), name))
			neighbors = append(neighbors, nb(7, uint32(n+1), 1, mac(peer), fmt.Sprintf("to-%03d", i), addr(peer)))
		}
		out[addr(i)] = devSnap(addr(i), mac(i), fmt.Sprintf("synthetic-%03d", i), ports, ifaces, neighbors)
	}
	return out
}

type measuredCollector struct {
	snaps  map[netip.Addr]*model.DeviceSnapshot
	delay  time.Duration
	active atomic.Int32
	peak   atomic.Int32
	calls  atomic.Int32
}

func (c *measuredCollector) Collect(ctx context.Context, target model.DiscoveryTarget) (*model.DeviceSnapshot, error) {
	n := c.active.Add(1)
	defer c.active.Add(-1)
	c.calls.Add(1)
	for old := c.peak.Load(); n > old; old = c.peak.Load() {
		if c.peak.CompareAndSwap(old, n) {
			break
		}
	}
	if c.delay > 0 {
		timer := time.NewTimer(c.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return c.snaps[target.Address], nil
}

func stressCoordinator(t *testing.T, c model.Collector, reg *identity.Registry, res *topology.Resolver) *Coordinator {
	t.Helper()
	coord, err := New(Options{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ManagementCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, MaxDepth: 8, MaxDevices: 200, MaxTargets: 600, Workers: 8, RunTimeout: time.Minute, MaxAddressesPerDevice: 3, Collector: c, Registry: reg, Resolver: res})
	if err != nil {
		t.Fatal(err)
	}
	return coord
}

func TestT502200Devices(t *testing.T) {
	c := &measuredCollector{snaps: stressGraph(t), delay: 100 * time.Millisecond}
	runtime.GC()
	var peak atomic.Uint64
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			var stats runtime.MemStats
			runtime.ReadMemStats(&stats)
			if stats.Sys > peak.Load() {
				peak.Store(stats.Sys)
			}
			select {
			case <-done:
				return
			case <-ticker.C:
			}
		}
	}()
	start := time.Now()
	out := stressCoordinator(t, c, newTestRegistry(t), newTestResolver()).Run(context.Background())
	elapsed := time.Since(start)
	close(done)
	<-stopped
	if out.Status != "completed" || len(out.Devices) != 200 || len(out.Links) != 800 || len(out.Observations) != 1600 {
		t.Fatalf("graph: status=%s devices=%d links=%d observations=%d issues=%v", out.Status, len(out.Devices), len(out.Links), len(out.Observations), out.Issues)
	}
	for _, l := range out.Links {
		if l.Confidence() != "bidirectional" {
			t.Fatal("missing direction")
		}
	}
	if c.calls.Load() != 200 || c.peak.Load() > 8 || c.active.Load() != 0 {
		t.Fatalf("calls=%d peak=%d active=%d", c.calls.Load(), c.peak.Load(), c.active.Load())
	}
	if elapsed > time.Minute || peak.Load() > 256<<20 {
		t.Fatalf("budget exceeded: elapsed=%s Go Sys=%d", elapsed, peak.Load())
	}
	t.Logf("devices=200 neighbors=1600 links=800 duration=%s peak_workers=%d peak_go_sys_bytes=%d", elapsed, c.peak.Load(), peak.Load())
}

func TestT502TwentyRounds(t *testing.T) {
	c := &measuredCollector{snaps: stressGraph(t)}
	reg, res := newTestRegistry(t), newTestResolver()
	for round := 0; round < 20; round++ {
		out := stressCoordinator(t, c, reg, res).Run(context.Background())
		if out.Status != "completed" || len(out.Devices) != 200 || len(reg.Devices()) != 200 || len(res.Ports().All()) != 1600 || len(out.Links) != 800 {
			t.Fatalf("round %d: status=%s devices=%d ports=%d links=%d", round, out.Status, len(reg.Devices()), len(res.Ports().All()), len(out.Links))
		}
	}
	if c.active.Load() != 0 || c.peak.Load() > 8 {
		t.Fatal("workers did not drain")
	}
}

func TestT502CancelGoroutines(t *testing.T) {
	baseline := runtime.NumGoroutine()
	c := &measuredCollector{snaps: stressGraph(t), delay: time.Hour}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	out := stressCoordinator(t, c, newTestRegistry(t), newTestResolver()).Run(ctx)
	if out.Status != "partial" || c.active.Load() != 0 {
		t.Fatalf("timeout status=%s active=%d", out.Status, c.active.Load())
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > baseline+2 && time.Now().Before(deadline) {
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	if runtime.NumGoroutine() > baseline+2 {
		t.Fatalf("goroutines baseline=%d now=%d", baseline, runtime.NumGoroutine())
	}
}
