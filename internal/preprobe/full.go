package preprobe

import (
	"context"
	"net/netip"
	"sort"
	"sync"
	"time"

	"gonet/internal/identity"
)

// runFull visits each effective host once, including fresh cached hosts. The
// range stays compact and only Workers jobs can be in flight. Unlike the legacy
// rotating batch, this stage has no per-batch or shared LLDP target limit.
func runFull(ctx context.Context, o Options, scope *Range, pool []Record, cursor Cursor, reg *identity.Registry, progress func(Summary, netip.Addr), event func(Attempt, Record)) Batch {
	started := time.Now()
	if cursor.ScopeDigest != scope.Digest {
		cursor = Cursor{ScopeDigest: scope.Digest}
	}
	s := Summary{Enabled: o.Enabled, FullRange: true, RangeHosts: scope.Count, RefreshInterval: o.RefreshInterval, Cursor: Cursor{ScopeDigest: scope.Digest, Cycles: cursor.Cycles}}
	if !o.Enabled || o.Prober == nil {
		return Batch{Summary: s}
	}
	s.Queued = int(scope.Count)
	s.Deferred = scope.Count
	byIP := make(map[netip.Addr]Record, len(pool))
	for _, r := range pool {
		byIP[r.IP] = r
	}
	workers := max(1, min(o.Workers, 64))
	type job struct {
		offset uint64
		ip     netip.Addr
	}
	type result struct {
		job job
		a   Attempt
	}
	work := make(chan job)
	done := make(chan result, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				a := Attempt{IP: j.ip}
				if ctx.Err() == nil {
					a = o.Prober.Probe(ctx, j.ip)
					a.IP = j.ip
				}
				done <- result{j, a}
			}
		}()
	}
	var next, contiguous uint64
	completed := map[uint64]bool{}
	inflight := 0
	records := []Record{}
	if progress != nil {
		progress(s, netip.Addr{})
	}
	for next < scope.Count || inflight > 0 {
		var send chan job
		var j job
		if next < scope.Count && ctx.Err() == nil {
			j.offset = next
			j.ip, _ = scope.At(next)
			send = work
		}
		if send == nil && inflight == 0 {
			break
		}
		select {
		case send <- j:
			next++
			inflight++
		case v := <-done:
			inflight--
			if !v.a.Attempted && !v.a.Reachable && v.a.PDUs == 0 {
				continue
			}
			if v.a.At.IsZero() {
				v.a.At = time.Now().UTC()
			}
			r := Merge(byIP[v.job.ip], v.a, reg)
			byIP[v.job.ip] = r
			records = append(records, r)
			s.Completed++
			s.PDUs += v.a.PDUs
			if !v.a.Reachable {
				s.Failed++
			}
			if r.Status == "identified" {
				s.Identified++
			}
			completed[v.job.offset] = true
			for completed[contiguous] {
				delete(completed, contiguous)
				contiguous++
			}
			s.Cursor.Next = contiguous
			s.Cursor.Covered = uint64(s.Completed)
			s.Deferred = scope.Count - uint64(s.Completed)
			if event != nil {
				event(v.a, r)
			}
			if progress != nil {
				progress(s, v.job.ip)
			}
		}
	}
	close(work)
	wg.Wait()
	s.Elapsed = time.Since(started)
	s.Termination = "range_complete"
	if s.Deferred == 0 {
		s.Cursor.Next = 0
		s.Cursor.Cycles++
	} else {
		s.Termination = "run_deadline"
		if ctx.Err() == context.Canceled {
			s.Termination = "canceled"
		}
	}
	s.PoolAddresses, s.PoolIdentities = countPool(byIP, scope, reg)
	sort.Slice(records, func(i, j int) bool { return records[i].IP.Less(records[j].IP) })
	if progress != nil {
		progress(s, netip.Addr{})
	}
	return Batch{Records: records, Summary: s}
}
