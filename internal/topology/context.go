package topology

import "fmt"

// Restore retains typed identities and historical ifIndex for change/conflict
// checks. Old physicality does not verify a port in the current round.
func (r *PortRegistry) Restore(ports []*Port) error {
	if len(r.ports) != 0 {
		return fmt.Errorf("port context must be restored before collection")
	}
	for _, p := range ports {
		if p.Ref == 0 || r.ports[p.Ref] != nil {
			return fmt.Errorf("invalid context port reference")
		}
		p.Physical = false
		p.Resolution = PortUnresolved
		r.ports[p.Ref] = p
		r.byKey[compositeKey(p.Device, p.Key)] = p

		if p.Ref > r.next {
			r.next = p.Ref
		}
	}
	// Install aliases after all canonical keys, independent of SQL row order.
	for _, p := range ports {
		for _, alias := range p.Aliases {
			k := compositeKey(p.Device, alias)
			if owner := r.byKey[k]; owner != nil && owner != p {
				if HasVerifiedAliases(p.MappingRule) && p.IfIndex != nil && owner.IfIndex == nil && owner.MappingRule == "provisional-ifname" {
					r.byKey[k] = p
					continue
				}
				if HasVerifiedAliases(owner.MappingRule) && owner.IfIndex != nil && p.IfIndex == nil && p.MappingRule == "provisional-ifname" {
					continue
				}
				return fmt.Errorf("IFINDEX_ALIAS_CONFLICT: alias %s has multiple owners", alias)
			}
			r.byKey[k] = p
		}
	}
	return nil
}
