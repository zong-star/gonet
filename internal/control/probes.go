package control

import (
	"gonet/internal/config"
	"gonet/internal/preprobe"
	"gonet/internal/store/postgres"
	"net/netip"
	"time"
)

// PrepareProbeView reconciles persisted coverage with the currently authoritative
// scope before projecting it, even if no scan has yet run after a policy change.
func PrepareProbeView(exp *postgres.TopologyExport, cfg *config.Config, settings Settings) {
	var allowed, excluded []netip.Prefix
	for _, s := range settings.AllowedCIDRs {
		if p, e := prefix(s); e == nil {
			allowed = append(allowed, p)
		}
	}
	for _, s := range settings.ExcludedCIDRs {
		if p, e := prefix(s); e == nil {
			excluded = append(excluded, p)
		}
	}
	r := preprobe.NewRange(allowed, excluded, cfg.Discovery.AllowIPv4LinkLocal)
	if exp.ProbeSummary.Cursor.ScopeDigest != r.Digest {
		exp.ProbeSummary = preprobe.Summary{RangeHosts: r.Count, Deferred: r.Count, Cursor: preprobe.Cursor{ScopeDigest: r.Digest}, Termination: "scope_changed"}
	}
	exp.ProbeSummary.Enabled = cfg.Discovery.Preprobe.Enabled
	exp.ProbeSummary.RefreshInterval = cfg.Discovery.Preprobe.RefreshInterval.Duration
}

type Probe struct {
	preprobe.Record
	Model          string `json:"model,omitempty"`
	CacheStatus    string `json:"cache_status"`
	ScopeStatus    string `json:"scope_status"`
	TopologyStatus string `json:"topology_status"`
}

func projectProbes(exp *postgres.TopologyExport, s Scope) []Probe {
	out := make([]Probe, 0, len(exp.ProbePool))
	linked := map[int64]bool{}
	for _, l := range exp.Links {
		linked[l.DeviceAID] = true
		linked[l.DeviceBID] = true
	}
	ttl := exp.ProbeSummary.RefreshInterval
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	for _, r := range exp.ProbePool {
		p := Probe{Record: r, CacheStatus: "stale", ScopeStatus: "allowed", TopologyStatus: "unassociated"}
		if preprobe.Fresh(r, time.Now(), ttl) {
			p.CacheStatus = "fresh"
		}
		if !s.Settings.Allows(r.IP) {
			p.ScopeStatus = "excluded_or_out_of_scope"
		}
		if r.MatchedDeviceID != nil {
			p.TopologyStatus = "managed"
			if linked[*r.MatchedDeviceID] {
				p.TopologyStatus = "linked"
			}
		}
		out = append(out, p)
	}
	return out
}
