package discovery

import "net/netip"

// targetBudget is owned by the coordinator. Probe and collection reservations
// share a unique-IP counter, while their task/visited state remains separate.
type targetBudget struct {
	max       int
	addresses map[netip.Addr]bool
}

func (b *targetBudget) reserve(a netip.Addr) bool {
	a = a.Unmap()
	if b.addresses[a] {
		return true
	}
	if len(b.addresses) >= b.max {
		return false
	}
	b.addresses[a] = true
	return true
}
