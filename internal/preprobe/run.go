package preprobe

import (
	"bytes"
	"context"
	"net/netip"
	"sort"
	"sync"
	"time"

	"gonet/internal/identity"
	"gonet/internal/model"
)

type Options struct {
	Enabled                       bool
	FullRange                     bool
	Workers, MaxHosts, KnownHosts int
	PhaseTimeout, RefreshInterval time.Duration
	Prober                        Prober
}
type Batch struct {
	MatchedRefs map[string]model.DevRef `json:"-"`
	Records     []Record                `json:"records"` // only attempted addresses are persisted
	Summary     Summary                 `json:"summary"`
}

func Fresh(r Record, now time.Time, ttl time.Duration) bool {
	return !r.Conflict && r.Status != "identity_pending" && r.Identity != "" && r.Facts != nil && r.LastIdentitySuccess != nil && !now.Before(*r.LastIdentitySuccess) && now.Sub(*r.LastIdentitySuccess) <= ttl
}

func SameIdentity(reg *identity.Registry, a, b model.TypedID) bool {
	if a.Subtype == b.Subtype && bytes.Equal(a.Raw, b.Raw) {
		return true
	}
	ka, sa := reg.EvidenceKey(a)
	kb, sb := reg.EvidenceKey(b)
	if sa && sb && ka == kb {
		return true
	}
	if sa && sb && (len(ka) >= 7 && ka[:7] == "manual:" || len(kb) >= 7 && kb[:7] == "manual:") {
		return false
	}
	oa, aa := reg.EvidenceOwner(a)
	ob, ab := reg.EvidenceOwner(b)
	if aa || ab {
		return false
	}
	if oa != nil && ob != nil {
		return oa == ob
	}
	ma, ok := identity.ChassisMAC(a)
	mb, okb := identity.ChassisMAC(b)
	return ok && okb && bytes.Equal(ma, mb)
}

func Merge(old Record, a Attempt, reg *identity.Registry) Record {
	r := old
	r.IP = a.IP
	r.LastAttempt = a.At
	r.Profile = a.Profile
	r.Source = "snmp_preprobe"
	r.FailureCode = a.ErrorCode
	r.FailureReason = a.ErrorReason
	if r.FirstSeen.IsZero() {
		r.FirstSeen = a.At
	}
	if !a.Reachable {
		r.Status = "unresponsive"
		if a.ErrorCode == "CANCELED" {
			r.Status = "canceled"
		}
		if a.ErrorCode == "SNMP_AUTH" {
			r.Status = "authentication_failed"
		}
		return r
	}
	key, strong := reg.EvidenceKey(a.Facts.Chassis)
	r.ResponseIP = a.ResponseIP
	if old.Facts != nil && old.Facts.Chassis.Subtype != 0 && len(old.Facts.Chassis.Raw) > 0 && a.Facts.Chassis.Subtype != 0 && len(a.Facts.Chassis.Raw) > 0 && !SameIdentity(reg, old.Facts.Chassis, a.Facts.Chassis) {
		r.Conflict = true
		if r.PreviousFacts == nil {
			r.PreviousFacts = old.Facts
		}
	}
	if owner, ambiguous := reg.EvidenceOwner(a.Facts.Chassis); ambiguous || owner != nil && owner.State == identity.StateConflict {
		r.Conflict = true
	}
	if owner, ok := reg.ByAddr(a.IP); ok && owner.StrongKey != "" && strong && !reg.Matches(owner.Ref, a.Facts.Chassis) {
		r.Conflict = true
	}
	facts := a.Facts
	// A successful system-only response must not erase previously verified chassis.
	if old.Facts != nil && len(facts.Chassis.Raw) == 0 {
		facts.Chassis = old.Facts.Chassis
		key = old.Identity
	}
	if old.Facts != nil {
		if facts.SysName == "" {
			facts.SysName = old.Facts.SysName
		}
		if facts.SysDescription == "" {
			facts.SysDescription = old.Facts.SysDescription
		}
		if facts.SysObjectID == "" {
			facts.SysObjectID = old.Facts.SysObjectID
		}
	}
	r.Facts = &facts
	r.Identity = key
	r.LastSuccess = &a.At
	if strong {
		r.LastIdentitySuccess = &a.At
	}
	class := reg.ClassifyFacts(facts)
	r.Kind = class.Result
	r.Rule = class.RuleID
	r.Status = "identity_pending"
	if strong {
		r.Status = "identified"
	}
	if !strong {
		if r.FailureCode == "" {
			r.FailureCode = "LLDP_LOCAL_UNAVAILABLE"
			r.FailureReason = "SNMP reachable; local chassis needs verification"
		}
	}
	if r.Conflict {
		r.Status = "identity_conflict"
		r.FailureCode = "IDENTITY_CONFLICT"
		r.FailureReason = "access address or chassis conflicts with previous evidence"
		r.MatchedDeviceID = nil
	}
	return r
}

// Run uses a bounded worker pool; only this goroutine merges records and advances
// the contiguous attempted cursor. Out-of-order completion cannot skip a host.
func Run(ctx context.Context, o Options, scope *Range, pool []Record, cursor Cursor, reg *identity.Registry, reserve func(netip.Addr) bool, progress func(Summary, netip.Addr), event func(Attempt, Record)) Batch {
	if o.FullRange {
		return runFull(ctx, o, scope, pool, cursor, reg, progress, event)
	}
	started := time.Now()
	summary := Summary{Enabled: o.Enabled, RangeHosts: scope.Count, RefreshInterval: o.RefreshInterval}
	if cursor.ScopeDigest != scope.Digest {
		cursor = Cursor{ScopeDigest: scope.Digest}
	}
	if scope.Count > 0 {
		cursor.Next %= scope.Count
	}
	if !o.Enabled || o.Prober == nil || scope.Count == 0 {
		summary.Cursor = cursor
		return Batch{Summary: summary}
	}
	if o.Workers < 1 {
		o.Workers = 1
	}
	if o.MaxHosts < 1 {
		o.MaxHosts = 256
	}
	if o.KnownHosts < 1 {
		o.KnownHosts = 64
	}
	if o.PhaseTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.PhaseTimeout)
		defer cancel()
	}
	byIP := map[netip.Addr]Record{}
	var known []Record
	for _, r := range pool {
		byIP[r.IP] = r
		if scope.Contains(r.IP) && r.LastSuccess != nil {
			known = append(known, r)
		}
	}
	sort.Slice(known, func(i, j int) bool { return known[i].IP.Less(known[j].IP) })
	type job struct {
		ip     netip.Addr
		offset int
	}
	var jobs []job
	selected := map[netip.Addr]bool{}
	// Reserve at least half the batch for range rotation even with many known IPs.
	quota := min(o.KnownHosts, o.MaxHosts/2)
	knownStart := cursor.KnownNext
	for i := 0; i < len(known) && len(jobs) < quota; i++ {
		r := known[(int(knownStart%uint64(len(known)))+i)%len(known)]
		cursor.KnownNext = uint64((int(knownStart%uint64(len(known))) + i + 1) % len(known))
		if Fresh(r, started, o.RefreshInterval) {
			continue
		}
		if reserve(r.IP) {
			jobs = append(jobs, job{r.IP, -1})
			selected[r.IP] = true
		}
	}
	var advanced []bool
	var offsets []uint64
	for step := uint64(0); step < scope.Count && len(jobs) < o.MaxHosts; step++ {
		n := (cursor.Next + step) % scope.Count
		a, _ := scope.At(n)
		// A selected refresh has its own completion marker when encountered.
		done := Fresh(byIP[a], started, o.RefreshInterval)
		if !done && !selected[a] && !reserve(a) {
			break
		}
		i := len(advanced)
		advanced = append(advanced, done)
		offsets = append(offsets, n)
		if selected[a] {
			for j := range jobs {
				if jobs[j].ip == a {
					jobs[j].offset = i
					break
				}
			}
			continue
		}
		if !done {
			jobs = append(jobs, job{a, i})
			selected[a] = true
		}
	}
	summary.Queued = len(jobs)
	if progress != nil {
		progress(summary, netip.Addr{})
	}
	type completed struct {
		j job
		a Attempt
	}
	work := make(chan job)
	results := make(chan completed, o.Workers)
	var wg sync.WaitGroup
	for i := 0; i < o.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range work {
				if ctx.Err() != nil {
					results <- completed{j, Attempt{IP: j.ip}}
					continue
				}
				a := o.Prober.Probe(ctx, j.ip)
				a.IP = j.ip
				results <- completed{j, a}
			}
		}()
	}
	// Keep no more than Workers tasks in flight, and drain every dispatched result.
	next, inflight := 0, 0
	var records []Record
	for next < len(jobs) || inflight > 0 {
		var send chan job
		var j job
		if next < len(jobs) && ctx.Err() == nil {
			send = work
			j = jobs[next]
		}
		if send == nil && inflight == 0 {
			break
		}
		select {
		case send <- j:
			next++
			inflight++
		case v := <-results:
			inflight--
			if !v.a.Attempted && !v.a.Reachable && v.a.PDUs == 0 {
				continue
			}
			if v.a.At.IsZero() {
				v.a.At = time.Now().UTC()
			}
			r := Merge(byIP[v.j.ip], v.a, reg)
			byIP[v.j.ip] = r
			records = append(records, r)
			if v.j.offset >= 0 {
				advanced[v.j.offset] = true
			}
			summary.Completed++
			summary.PDUs += v.a.PDUs
			if !v.a.Reachable {
				summary.Failed++
			}
			if r.Status == "identified" {
				summary.Identified++
			}
			if event != nil {
				event(v.a, r)
			}
			if progress != nil {
				progress(summary, v.j.ip)
			}
		}
	}
	close(work)
	wg.Wait()
	for i, done := range advanced {
		if !done {
			break
		}
		cursor.Next = (offsets[i] + 1) % scope.Count
		cursor.Covered = min(scope.Count, cursor.Covered+1)
		if cursor.Next == 0 {
			cursor.Cycles++
		}
	}
	summary.Cursor = cursor
	summary.Deferred = scope.Count - uint64(summary.Completed)
	summary.Elapsed = time.Since(started)
	summary.Termination = "batch_complete"
	if ctx.Err() != nil {
		summary.Termination = "phase_deadline"
		if ctx.Err() == context.Canceled {
			summary.Termination = "canceled"
		}
	}
	summary.PoolAddresses, summary.PoolIdentities = countPool(byIP, scope, reg)
	sort.Slice(records, func(i, j int) bool { return records[i].IP.Less(records[j].IP) })
	if progress != nil {
		progress(summary, netip.Addr{})
	}
	return Batch{Records: records, Summary: summary}
}

func countPool(byIP map[netip.Addr]Record, scope *Range, reg *identity.Registry) (int, int) {
	addresses := 0
	identities := map[string]bool{}
	for _, r := range byIP {
		if scope.Contains(r.IP) && r.Facts != nil {
			addresses++
			if r.Identity != "" && !r.Conflict {
				key := r.Identity
				if owner, ambiguous := reg.EvidenceOwner(r.Facts.Chassis); ambiguous {
					continue
				} else if owner != nil {
					if owner.State == identity.StateConflict {
						continue
					}
					key = owner.StrongKey
				} else if mac, ok := identity.ChassisMAC(r.Facts.Chassis); ok && (len(key) < 7 || key[:7] != "manual:") {
					key = identity.WeakKey(4, mac)
				}
				identities[key] = true
			}
		}
	}
	return addresses, len(identities)
}
