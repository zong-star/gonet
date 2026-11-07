package preprobe

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gonet/internal/identity"
	"gonet/internal/model"
)

func prefixes(raw ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range raw {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}
func ip(raw string) netip.Addr { return netip.MustParseAddr(raw) }
func registry(t *testing.T) *identity.Registry {
	t.Helper()
	r, e := identity.New(identity.Options{})
	if e != nil {
		t.Fatal(e)
	}
	return r
}

type probeFunc func(context.Context, netip.Addr) Attempt

func (f probeFunc) Probe(ctx context.Context, a netip.Addr) Attempt { return f(ctx, a) }
func success(a netip.Addr) Attempt {
	return Attempt{IP: a, Attempted: true, Reachable: true, At: time.Now().UTC(), Facts: model.DeviceInfo{Target: a, SysName: "same-name", Chassis: model.TypedID{Subtype: 4, Raw: []byte{2, 0, 0, 0, 0, a.As4()[3]}}}, PDUs: 2}
}

func TestRangeDedupeExclusionsAndHostEdges(t *testing.T) {
	r := NewRange(prefixes("192.0.2.0/24", "192.0.2.0/25", "192.0.3.0/31", "192.0.3.5/32", "2001:db8::/32"), prefixes("192.0.2.2/31"), false)
	if r.Count != 255 {
		t.Fatalf("count=%d", r.Count)
	}
	seen := map[netip.Addr]bool{}
	for n := uint64(0); n < r.Count; n++ {
		a, ok := r.At(n)
		if !ok || seen[a] || !r.Contains(a) {
			t.Fatalf("duplicate/bad address %v", a)
		}
		seen[a] = true
	}
	for _, a := range []string{"192.0.2.0", "192.0.2.255", "192.0.2.2", "192.0.2.3"} {
		if r.Contains(ip(a)) {
			t.Fatal("forbidden host", a)
		}
	}
	for _, a := range []string{"192.0.3.0", "192.0.3.1", "192.0.3.5"} {
		if !seen[ip(a)] {
			t.Fatal("missing /31 or /32", a)
		}
	}
	large := NewRange(prefixes("0.0.0.0/0"), nil, false)
	if len(large.spans) > 10 || large.Count < 3_000_000_000 {
		t.Fatal("large scope must stay compact")
	}
	for _, a := range []string{"0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1", "255.255.255.255"} {
		if large.Contains(ip(a)) {
			t.Fatal("invalid host allowed", a)
		}
	}
	if NewRange(prefixes("169.254.1.0/31"), nil, true).Count != 2 {
		t.Fatal("explicit link-local policy lost")
	}
}

func TestFairRotation689WithKnownQuota(t *testing.T) {
	r := NewRange(prefixes("192.0.2.0/24", "192.0.3.0/24", "192.0.4.0/24", "192.0.5.1/32", "192.0.5.2/32"), prefixes("192.0.2.64/26", "192.0.2.128/29", "192.0.2.137/32", "192.0.2.138/32", "192.0.2.139/32"), false)
	if r.Count != 689 {
		t.Fatal(r.Count)
	}
	seen := map[netip.Addr]bool{}
	pool := map[netip.Addr]Record{}
	var cursor Cursor
	for round := 0; round < 5; round++ {
		var records []Record
		for _, p := range pool {
			records = append(records, p)
		}
		reserved := map[netip.Addr]bool{}
		reserve := func(a netip.Addr) bool {
			if len(reserved) >= 300 && !reserved[a] {
				return false
			}
			reserved[a] = true
			return true
		}
		p := probeFunc(func(_ context.Context, a netip.Addr) Attempt { aResult := success(a); return aResult })
		batch := Run(context.Background(), Options{Enabled: true, Workers: 8, MaxHosts: 256, KnownHosts: 64, RefreshInterval: time.Nanosecond, Prober: p}, r, records, cursor, registry(t), reserve, nil, nil)
		cursor = batch.Summary.Cursor
		if batch.Summary.Completed > 256 || len(reserved) > 300 {
			t.Fatal("budget exceeded")
		}
		for _, p := range batch.Records {
			seen[p.IP] = true
			pool[p.IP] = p
		}
	}
	if len(seen) != 689 || cursor.Covered != 689 || cursor.Cycles == 0 {
		t.Fatalf("rotation starved hosts: seen=%d cursor=%+v", len(seen), cursor)
	}
}

func TestCancelRetainsPositiveAndCursorHole(t *testing.T) {
	r := NewRange(prefixes("192.0.2.0/30"), nil, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := probeFunc(func(ctx context.Context, a netip.Addr) Attempt {
		if a == ip("192.0.2.1") {
			<-ctx.Done()
			return Attempt{IP: a}
		}
		return success(a)
	})
	batch := Run(ctx, Options{Enabled: true, Workers: 2, MaxHosts: 2, Prober: p}, r, nil, Cursor{}, registry(t), func(netip.Addr) bool { return true }, nil, func(Attempt, Record) { cancel() })
	if len(batch.Records) != 1 || batch.Records[0].IP != ip("192.0.2.2") || batch.Summary.Cursor.Next != 0 {
		t.Fatalf("cancellation skipped unattempted host: %+v", batch)
	}
	next := Run(context.Background(), Options{Enabled: true, Workers: 1, MaxHosts: 2, RefreshInterval: time.Minute, Prober: probeFunc(func(_ context.Context, a netip.Addr) Attempt { return success(a) })}, r, batch.Records, batch.Summary.Cursor, registry(t), func(netip.Addr) bool { return true }, nil, nil)
	if next.Summary.Cursor.Covered != 2 {
		t.Fatal("restart did not close cursor hole")
	}
}

func TestFailureMissingChassisAndAddressConflict(t *testing.T) {
	r := registry(t)
	a := success(ip("192.0.2.2"))
	first := Merge(Record{}, a, r)
	fail := a
	fail.Reachable = false
	fail.ErrorCode = "SNMP_TIMEOUT"
	fail.At = a.At.Add(time.Minute)
	failed := Merge(first, fail, r)
	if failed.Facts.SysName != "same-name" || !failed.LastSuccess.Equal(*first.LastSuccess) {
		t.Fatal("failure erased successful facts")
	}
	missing := a
	missing.Facts.Chassis = model.TypedID{}
	missing.At = a.At.Add(time.Hour)
	partial := Merge(first, missing, r)
	if partial.Status != "identity_pending" || partial.Facts.Chassis.Subtype != 4 || Fresh(partial, missing.At, time.Minute) {
		t.Fatal("missing chassis erased/renewed identity evidence")
	}
	changed := a
	changed.Facts.Chassis.Raw = []byte{2, 0, 0, 0, 0, 9}
	changed.At = a.At.Add(time.Second)
	conflict := Merge(first, changed, r)
	if !conflict.Conflict || conflict.PreviousFacts == nil || Fresh(conflict, changed.At, time.Hour) {
		t.Fatal("IP reuse silently replaced identity")
	}
	if !Merge(conflict, changed, r).Conflict {
		t.Fatal("conflict must remain explicit")
	}
}

func TestScopeChangeInvalidatesCursorAndNeverRequestsExclusions(t *testing.T) {
	r := NewRange(prefixes("192.0.2.0/29"), prefixes("192.0.2.2/32"), false)
	var mu sync.Mutex
	called := map[netip.Addr]bool{}
	b := Run(context.Background(), Options{Enabled: true, Workers: 3, MaxHosts: 20, Prober: probeFunc(func(_ context.Context, a netip.Addr) Attempt {
		mu.Lock()
		called[a] = true
		mu.Unlock()
		return success(a)
	})}, r, nil, Cursor{ScopeDigest: "old", Next: 999}, registry(t), func(netip.Addr) bool { return true }, nil, nil)
	if len(called) != 5 || called[ip("192.0.2.2")] || b.Summary.Cursor.ScopeDigest != r.Digest {
		t.Fatal("scope exclusion or cursor reset failed")
	}
}
