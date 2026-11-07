package topology

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"gonet/internal/collector/lldp"
	"gonet/internal/model"
)

const TS7914AliasRule = "verified-alias:ts7914-gi-ge"

var tsPhysicalName = regexp.MustCompile(`^ge([1-9][0-9]*)_([1-9][0-9]*)_([1-9][0-9]*)$`)
var tsAdvertisedName = regexp.MustCompile(`^Gi([1-9][0-9]*)/([1-9][0-9]*)/([1-9][0-9]*)$`)

// SetDeviceSnapshot supplies current direct evidence. Historical attributes or
// an advertised product name alone cannot enable an interface-name alias.
func (r *Resolver) SetDeviceSnapshot(device model.DevRef, snap *model.DeviceSnapshot) {
	if r.snapshots == nil {
		r.snapshots = map[model.DevRef]*model.DeviceSnapshot{}
	}
	r.snapshots[device] = snap
}

func (r *Resolver) tsInterface(device model.DevRef, name string) (model.Interface, bool) {
	s := r.snapshots[device]
	if s == nil || !lldp.IsTS7914Adapter(s.Device, []string{lldp.TS7914Adapter}) {
		return model.Interface{}, false
	}
	i, ok := uniqueByName(s.Interfaces, name)
	if !ok || s.Interfaces[i].Type != IfTypeEthernetCsmacd || s.Interfaces[i].IfIndex <= 0 {
		return model.Interface{}, false
	}
	// Require the device's own typed LLDP identity, not just an IF-MIB name.
	for _, lp := range s.LocalPorts {
		if lp.ID.Subtype == 5 && bytes.Equal(lp.ID.Raw, []byte(name)) {
			return s.Interfaces[i], true
		}
	}
	return model.Interface{}, false
}

func (r *Resolver) verifiedInterfaceAlias(device model.DevRef, id model.TypedID) (string, bool) {
	if id.Subtype != 5 {
		return "", false
	}
	m := tsAdvertisedName.FindStringSubmatch(string(id.Raw))
	if m == nil {
		return "", false
	}
	name := fmt.Sprintf("ge%s_%s_%s", m[1], m[2], m[3])
	_, ok := r.tsInterface(device, name)
	return name, ok
}

func (r *Resolver) aliasForCanonical(device model.DevRef, p *Port) (PortKey, bool) {
	if p.Subtype != 5 || p.IfIndex == nil {
		return "", false
	}
	m := tsPhysicalName.FindStringSubmatch(string(p.RawID))
	if m == nil {
		return "", false
	}
	iface, ok := r.tsInterface(device, string(p.RawID))
	if !ok || iface.IfIndex != *p.IfIndex {
		return "", false
	}
	return MakePortKey(5, []byte(fmt.Sprintf("Gi%s/%s/%s", m[1], m[2], m[3]))), true
}

// HasVerifiedAliases also scopes the persistence cleanup of never-mapped,
// unreferenced name-only placeholders. It cannot authorize merging real ports.
func HasVerifiedAliases(rule string) bool {
	return strings.HasPrefix(rule, "manual:") || rule == TS7914AliasRule
}

func (r *Resolver) bindVerifiedAlias(p *Port, alias PortKey) *model.Issue {
	if existing, ok := r.ports.Get(p.Device, alias); ok && existing != p {
		if existing.IfIndex != nil || existing.Physical || existing.MappingRule != "provisional-ifname" {
			existing.Physical = false
			existing.Resolution = PortConflict
			return &model.Issue{Code: "IFINDEX_ALIAS_CONFLICT", Component: "topology", Message: fmt.Sprintf("alias %s belongs to port %d; canonical port %d not merged", alias, existing.Ref, p.Ref)}
		}
		delete(r.ports.ports, existing.Ref)
		for k, owner := range r.ports.byKey {
			if owner == existing {
				r.ports.byKey[k] = p
			}
		}
	}
	r.ports.byKey[compositeKey(p.Device, alias)] = p
	found := false
	for _, key := range p.Aliases {
		found = found || key == alias
	}
	if !found {
		p.Aliases = append(p.Aliases, alias)
	}
	if !strings.HasPrefix(p.MappingRule, "manual:") {
		p.MappingRule = TS7914AliasRule
	}
	return nil
}

// RemotePortFailure describes the unresolved endpoint using current evidence.
func (r *Resolver) RemotePortFailure(device model.DevRef, id model.TypedID) (string, string) {
	key := MakePortKey(id.Subtype, id.Raw)
	if p, ok := r.ports.Get(device, key); ok && p.Resolution == PortConflict {
		return "IFINDEX_ALIAS_CONFLICT", fmt.Sprintf("remote port %s has conflicting alias or ifIndex ownership", key)
	}
	if id.Subtype == lldp.PortSubtypeMACAddress {
		count := 0
		if s := r.snapshots[device]; s != nil {
			for _, iface := range s.Interfaces {
				if iface.Type == IfTypeEthernetCsmacd && iface.IfIndex > 0 && bytes.Equal(iface.PhysAddress, id.Raw) {
					count++
				}
			}
		}
		code := "REMOTE_MAC_NO_PHYSICAL_MATCH"
		if count > 1 {
			code = "REMOTE_MAC_AMBIGUOUS"
		}
		return code, fmt.Sprintf("remote port %s has %d current physical MAC candidates", key, count)
	}
	if id.Subtype == lldp.PortSubtypeInterfaceName {
		return "REMOTE_IFNAME_ALIAS_UNMAPPED", fmt.Sprintf("remote interfaceName %q (%s) is not verified against its current physical interface", id.Raw, key)
	}
	return "REMOTE_PORT_UNMAPPED", fmt.Sprintf("remote typed port %s has no current physical mapping", key)
}
