package discovery

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/preprobe"
)

func (c *Coordinator) SetProbeContext(pool []preprobe.Record, cursor preprobe.Cursor) {
	c.probePool = pool
	c.probeCursor = cursor
}
func (c *Coordinator) SetProbeHandler(fn func(preprobe.Attempt, preprobe.Record)) {
	c.opts.OnProbe = fn
}

// PrepareSupplement shares the same target budget with full collection. The
// explicit legacy supplement still requests only its original two scalars.
func (c *Coordinator) PrepareSupplement(addrs []netip.Addr) []netip.Addr {
	c.reserveSeeds()
	var out []netip.Addr
	for _, a := range addrs {
		if c.inScope(a) && c.validHostAddr(a) && c.reserveProbe(a) {
			out = append(out, a)
		}
	}
	c.opts.Preprobe.Enabled = false
	return out
}
func (c *Coordinator) SetSupplementHints(hints map[string][]netip.Addr) { c.accessHints = hints }

func (c *Coordinator) reserveSeeds() {
	for _, a := range c.opts.Seeds {
		if c.inScope(a) && c.validHostAddr(a) {
			c.reserveTarget(a)
		}
	}
}
func (c *Coordinator) reserveProbe(a netip.Addr) bool {
	if c.budget.addresses[a.Unmap()] {
		return true
	}
	// At least half of the unique-target capacity remains for core recursion.
	limit := c.opts.MaxTargets - max(1, c.opts.MaxTargets/2, len(c.opts.Seeds))
	if c.probeNewTargets >= limit {
		return false
	}
	if !c.reserveTarget(a) {
		return false
	}
	c.probeNewTargets++
	return true
}
func (c *Coordinator) runPreprobe(ctx context.Context) {
	c.reserveSeeds()
	o := c.opts.Preprobe
	if !o.Enabled {
		return
	}
	if !o.FullRange && c.opts.RunTimeout > 0 && (o.PhaseTimeout <= 0 || o.PhaseTimeout > c.opts.RunTimeout/3) {
		o.PhaseTimeout = c.opts.RunTimeout / 3
	}
	// Existing verified addresses are refresh targets, never topology seeds.
	byIP := map[netip.Addr]preprobe.Record{}
	for _, d := range c.opts.Registry.Devices() {
		for _, a := range d.Addresses {
			if a.State == identity.AddrVerified {
				at := d.LastSeen
				byIP[a.Addr] = preprobe.Record{IP: a.Addr, LastSuccess: &at}
			}
		}
	}
	for _, r := range c.probePool {
		byIP[r.IP] = r
	}
	c.probePool = nil
	for _, r := range byIP {
		c.probePool = append(c.probePool, r)
	}
	scope := preprobe.NewRange(c.opts.ManagementCIDRs, c.opts.ExcludedCIDRs, c.opts.AllowIPv4LinkLocal)
	batch := preprobe.Run(ctx, o, scope, c.probePool, c.probeCursor, c.opts.Registry, c.reserveProbe, func(s preprobe.Summary, a netip.Addr) {
		if c.opts.OnProgress != nil {
			target := ""
			if a.IsValid() {
				target = a.String()
			}
			c.opts.OnProgress(Progress{Stage: "preprobe", Target: target, Completed: s.Completed, Scheduled: s.Queued, Probe: &s})
		}
	}, c.opts.OnProbe)
	for _, r := range batch.Records {
		byIP[r.IP] = r
		if r.Conflict {
			c.issues = append(c.issues, model.Issue{Code: "IDENTITY_CONFLICT", Component: "preprobe", Message: "SNMP access identity conflicts at " + r.IP.String()})
		}
	}
	c.probePool = nil
	for _, r := range byIP {
		c.probePool = append(c.probePool, r)
	}
	sort.Slice(c.probePool, func(i, j int) bool {
		a, b := c.probePool[i].LastSuccess, c.probePool[j].LastSuccess
		if a == nil {
			return false
		}
		if b == nil {
			return true
		}
		return a.After(*b)
	})
	c.probeIndex = preprobe.NewIndex(c.probePool, scope, o.RefreshInterval, c.opts.Registry)
	c.probeBatch = batch
}
func (c *Coordinator) addProbeCandidates(d *identity.Device) {
	for _, key := range c.opts.Registry.CandidateKeys(d) {
		for _, a := range c.accessHints[key] {
			c.addCandidate(d.Ref, a, "manual_supplement", false)
		}
	}
	if !c.opts.Preprobe.Enabled {
		return
	}
	if c.probeIndex == nil {
		return
	}
	for _, r := range c.probeIndex.Candidates(d) {
		source := "probe_cache"
		for _, current := range c.probeBatch.Records {
			if current.IP == r.IP {
				source = "snmp_preprobe"
				break
			}
		}
		c.addCandidate(d.Ref, r.IP, source, true)
		if state := c.devStates[d.Ref]; state != nil {
			for i := range state.Candidates {
				if state.Candidates[i].Addr == r.IP {
					state.Candidates[i].Freshness = *r.LastIdentitySuccess
				}
			}
		}
	}
}
func (c *Coordinator) verifyProbeSnapshot(r taskResult) bool {
	if !c.opts.Preprobe.Enabled || c.probeIndex == nil {
		return true
	}
	p, found := c.probeIndex.ByIP(r.Addr)
	if !found || p.Facts == nil {
		return true
	}
	if !p.Conflict && p.Identity == "" {
		return true
	}
	if _, strong := c.opts.Registry.EvidenceKey(r.Snapshot.Device.Chassis); !strong {
		c.status = "partial"
		c.failVerification(r.Task.Device, "LLDP_LOCAL_UNAVAILABLE", "full collection could not verify local chassis", r.Addr)
		c.issues = append(c.issues, model.Issue{Code: "LLDP_LOCAL_UNAVAILABLE", Component: "preprobe", Message: "full collection has no trusted local chassis at " + r.Addr.String()})
		return false
	}
	if !p.Conflict && preprobe.SameIdentity(c.opts.Registry, p.Facts.Chassis, r.Snapshot.Device.Chassis) {
		return true
	}
	if d, ok := c.opts.Registry.ByRef(r.Task.Device); ok {
		d.State = identity.StateConflict
		c.disableAbsence(d.Ref)
	}
	if d, ok := c.opts.Registry.ByAddr(r.Addr); ok {
		d.State = identity.StateConflict
		c.disableAbsence(d.Ref)
	}
	c.status = "partial"
	c.failVerification(r.Task.Device, "IDENTITY_CONFLICT", "SNMP chassis changed between probe and collection", r.Addr)
	c.issues = append(c.issues, model.Issue{Code: "IDENTITY_CONFLICT", Component: "preprobe", Message: "SNMP chassis changed between stages at " + r.Addr.String()})
	p.Conflict = true
	p.Status = "identity_conflict"
	p.FailureCode = "IDENTITY_CONFLICT"
	p.FailureReason = "SNMP chassis changed between probe and full collection"
	if p.PreviousFacts == nil {
		p.PreviousFacts = p.Facts
	}
	facts := r.Snapshot.Device
	p.Facts = &facts
	p.Identity, _ = c.opts.Registry.EvidenceKey(facts.Chassis)
	at := time.Now().UTC()
	p.LastAttempt = at
	p.LastSuccess = &at
	p.MatchedDeviceID = nil
	if c.probeIndex != nil {
		c.probeIndex.Update(p)
	}
	updated := false
	for i := range c.probeBatch.Records {
		if c.probeBatch.Records[i].IP == r.Addr {
			c.probeBatch.Records[i] = p
			updated = true
		}
	}
	if !updated {
		c.probeBatch.Records = append(c.probeBatch.Records, p)
	}
	return false
}

func (c *Coordinator) associateProbeRecords() {
	c.probeBatch.MatchedRefs = map[string]model.DevRef{}
	if c.probeIndex == nil {
		return
	}
	c.probeBatch.Summary.PoolAddresses, c.probeBatch.Summary.PoolIdentities = c.probeIndex.Counts()
	for ref, state := range c.devStates {
		if !state.Collected {
			continue
		}
		d, ok := c.opts.Registry.ByRef(ref)
		if !ok || d.State == identity.StateConflict || !d.Classification.Managed() {
			continue
		}
		for _, p := range c.probeIndex.Candidates(d) {
			c.probeBatch.MatchedRefs[p.IP.String()] = d.Ref
		}
	}
}
