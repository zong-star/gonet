package identity

import "fmt"

// Restore loads resolution context only. It neither schedules devices nor
// verifies a current observation. References are temporary, allocated by the
// context loader independently of database primary keys.
func (r *Registry) Restore(devices []*Device) error {
	if len(r.devices) != 0 {
		return fmt.Errorf("identity context must be restored before collection")
	}
	for _, d := range devices {
		if d.Ref == 0 || r.devices[d.Ref] != nil {
			return fmt.Errorf("invalid context device reference")
		}
		r.devices[d.Ref] = d
		if d.Ref > r.nextRef {
			r.nextRef = d.Ref
		}
		if d.StrongKey != "" {
			r.byKey[d.StrongKey] = d
		}
		for _, key := range d.IdentityKeys {
			if owner, ok := r.byKey[key]; ok && owner != d {
				return fmt.Errorf("identity context contains conflicting keys")
			}
			r.byKey[key] = d
		}
		for _, a := range d.Addresses {
			if a.State != AddrRetired {
				r.byAddr[a.Addr.Unmap()] = d
			}
		}
	}
	return nil
}
