package preprobe

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFullRangeExceedsLegacyBatchAndTargetBudgets(t *testing.T) {
	r := NewRange(prefixes("192.0.0.0/22", "192.0.2.0/24"), prefixes("192.0.2.8/30"), false)
	if r.Count <= 600 {
		t.Fatal("fixture must exceed both old limits")
	}
	var mu sync.Mutex
	calls := map[netip.Addr]int{}
	var active, peak atomic.Int64
	p := probeFunc(func(ctx context.Context, a netip.Addr) Attempt {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		mu.Lock()
		calls[a]++
		mu.Unlock()
		return success(a)
	})
	o := Options{Enabled: true, FullRange: true, Workers: 8, MaxHosts: 256, PhaseTimeout: time.Nanosecond, RefreshInterval: time.Hour, Prober: p}
	reserve := func(netip.Addr) bool { t.Error("full probe used LLDP reservation budget"); return false }
	b := Run(context.Background(), o, r, nil, Cursor{}, registry(t), reserve, nil, nil)
	if uint64(len(calls)) != r.Count || uint64(b.Summary.Completed) != r.Count || b.Summary.Deferred != 0 || b.Summary.Termination != "range_complete" || peak.Load() > 8 {
		t.Fatalf("incomplete/unbounded full range: %+v peak=%d calls=%d", b.Summary, peak.Load(), len(calls))
	}
	for a, n := range calls {
		if n != 1 || !r.Contains(a) {
			t.Fatalf("duplicate/outside request: %v %d", a, n)
		}
	}
	// A second full update must actually refresh every address, even with a
	// fresh cache and the previous complete cursor.
	b2 := Run(context.Background(), o, r, b.Records, b.Summary.Cursor, registry(t), reserve, nil, nil)
	if uint64(b2.Summary.Completed) != r.Count || b2.Summary.Cursor.Cycles != 2 {
		t.Fatalf("fresh cache suppressed full probe: %+v", b2.Summary)
	}
	for a, n := range calls {
		if n != 2 {
			t.Fatalf("host not refreshed: %v %d", a, n)
		}
	}
}

func TestFullRangeCancellationDoesNotClaimCompletion(t *testing.T) {
	r := NewRange(prefixes("192.0.2.0/24"), nil, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var calls atomic.Int64
	p := probeFunc(func(ctx context.Context, a netip.Addr) Attempt {
		if calls.Add(1) >= 7 {
			cancel()
		}
		return success(a)
	})
	b := Run(ctx, Options{Enabled: true, FullRange: true, Workers: 3, Prober: p}, r, nil, Cursor{}, registry(t), nil, nil, nil)
	if b.Summary.Termination != "canceled" || b.Summary.Deferred == 0 || b.Summary.Cursor.Cycles != 0 || b.Summary.Completed != len(b.Records) || uint64(b.Summary.Completed)+b.Summary.Deferred != r.Count {
		t.Fatalf("canceled coverage is misleading: %+v", b.Summary)
	}
}

func TestFullRangeHonorsOuterDeadline(t *testing.T) {
	r := NewRange(prefixes("192.0.2.0/24"), nil, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	p := probeFunc(func(ctx context.Context, a netip.Addr) Attempt {
		<-ctx.Done()
		return Attempt{IP: a, Attempted: true, At: time.Now(), ErrorCode: "SNMP_TIMEOUT"}
	})
	b := Run(ctx, Options{Enabled: true, FullRange: true, Workers: 2, Prober: p}, r, nil, Cursor{}, registry(t), nil, nil, nil)
	if b.Summary.Termination != "run_deadline" || b.Summary.Deferred == 0 || b.Summary.Completed != 2 {
		t.Fatalf("deadline not reported correctly: %+v", b.Summary)
	}
}
