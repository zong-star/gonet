package preprobe

import (
	"net/netip"
	"sort"
	"time"

	"gonet/internal/identity"
)

// Index is owned by the discovery coordinator. It never admits devices. Typed
// keys and configured mappings provide lookups; registry ownership guards every
// MAC alias, and each IP retains its own independent successful facts.
type Index struct {
	byIP       map[netip.Addr]Record
	byIdentity map[string][]netip.Addr
	scope      *Range
	ttl        time.Duration
	registry   *identity.Registry
}

func NewIndex(pool []Record, scope *Range, ttl time.Duration, reg *identity.Registry) *Index {
	x := &Index{byIP: map[netip.Addr]Record{}, byIdentity: map[string][]netip.Addr{}, scope: scope, ttl: ttl, registry: reg}
	for _, r := range pool {
		x.byIP[r.IP] = r
		if r.Facts == nil || !scope.Contains(r.IP) || !Fresh(r, time.Now(), ttl) {
			continue
		}
		key, ok := reg.EvidenceKey(r.Facts.Chassis)
		if !ok {
			continue
		}
		x.byIdentity[key] = append(x.byIdentity[key], r.IP)
	}
	return x
}
func (x *Index) ByIP(a netip.Addr) (Record, bool) { r, ok := x.byIP[a.Unmap()]; return r, ok }

// Update invalidates an address immediately if full collection contradicts it.
func (x *Index) Update(r Record)    { x.byIP[r.IP] = r }
func (x *Index) Counts() (int, int) { return countPool(x.byIP, x.scope, x.registry) }
func (x *Index) Candidates(d *identity.Device) []Record {
	seen := map[netip.Addr]bool{}
	var out []Record
	for _, key := range x.registry.CandidateKeys(d) {
		for _, a := range x.byIdentity[key] {
			if seen[a] {
				continue
			}
			seen[a] = true
			r := x.byIP[a]
			if x.scope.Contains(a) && Fresh(r, time.Now(), x.ttl) && x.registry.Matches(d.Ref, r.Facts.Chassis) {
				out = append(out, r)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].LastIdentitySuccess, out[j].LastIdentitySuccess
		if !a.Equal(*b) {
			return a.After(*b)
		}
		return out[i].IP.Less(out[j].IP)
	})
	return out
}
