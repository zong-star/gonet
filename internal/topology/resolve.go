package topology

import (
	"bytes"
	"fmt"
	"regexp"

	"gonet/internal/collector/lldp"
	"gonet/internal/model"
)

// PortResolution is the outcome of resolving one port.
type PortResolution struct {
	Port   *Port
	State  PortState
	Issues []model.Issue
}

// Resolver resolves local and remote ports into the registry.
type Resolver struct {
	ports            *PortRegistry
	rules            map[string]PortRule
	deviceRules      map[model.DevRef]string
	deviceIdentities map[model.DevRef]string
	overrides        map[string]map[PortKey]Override
	snapshots        map[model.DevRef]*model.DeviceSnapshot
}

// NewResolver builds a Resolver over the given registry.
func NewResolver(registry *PortRegistry) *Resolver {
	if registry == nil {
		registry = NewPortRegistry(nil)
	}
	return &Resolver{ports: registry}
}

// Ports returns the underlying registry.
func (r *Resolver) Ports() *PortRegistry { return r.ports }

// ResolveLocalPort creates or updates the local port for lp. The typed key is
// derived from the LLDP port subtype and raw bytes; ifIndex is only an
// attribute, so an ifIndex change reuses the same port ref (L04).
func (r *Resolver) ResolveLocalPort(device model.DevRef, lp model.LocalPort, ifaces []model.Interface) PortResolution {
	key := MakePortKey(lp.ID.Subtype, lp.ID.Raw)
	originalKey := key
	if name, ok := r.verifiedInterfaceAlias(device, lp.ID); ok {
		key = MakePortKey(5, []byte(name))
	}
	if lp.ID.Subtype == 5 {
		if name, ok := r.rules[r.deviceRules[device]].Aliases[string(lp.ID.Raw)]; ok {
			key = MakePortKey(5, []byte(name))
		}
	}
	override, overridden := r.overrides[r.deviceIdentities[device]][key]
	if overridden {
		key = override.CanonicalKey
	}
	ifIndex, ifType, rule := r.localMapping(device, lp, ifaces)
	if !ValidPortKey(string(originalKey)) {
		ifIndex = nil
		ifType = 0
		rule = "invalid-typed-id"
	}

	// A real typed-key change on the same ifIndex is isolated and reported
	// (section 5.1); a verified one-to-one override is required to merge them.
	var extra []model.Issue
	_, knownKey := r.ports.Get(device, key)
	if ifIndex != nil && !knownKey {
		for _, p := range r.ports.All() {
			if p.Device == device && p.Key != key && p.IfIndex != nil && *p.IfIndex == *ifIndex {
				p.Physical = false
				p.Resolution = PortConflict
				extra = append(extra, model.Issue{
					Code: "PORT_ID_CHANGED", Component: "topology",
					Message: fmt.Sprintf("ifIndex %d now carries key %s (previously %s); isolated", *ifIndex, key, p.Key),
				})
				break
			}
		}
	}

	stored := lp
	if key != originalKey {
		stored.ID = idFromKey(key)
	}
	p := r.ports.upsert(device, key, stored, ifIndex, ifType, rule)
	if p.Aliases == nil {
		p.Aliases = []PortKey{key}
	}
	if key != originalKey {
		if existing, ok := r.ports.Get(device, originalKey); ok && existing != p && existing.IfIndex != nil {
			existing.Physical = false
			existing.Resolution = PortConflict
			extra = append(extra, model.Issue{Code: "PORT_ID_CHANGED", Component: "topology", Message: "typed alias is already bound to another port"})
		} else {
			if ok && existing != p {
				existing.Resolution = PortUnresolved
			}
			r.ports.byKey[compositeKey(device, originalKey)] = p
		}
		found := false
		for _, a := range p.Aliases {
			if a == originalKey {
				found = true
			}
		}
		if !found {
			p.Aliases = append(p.Aliases, originalKey)
		}
	}
	res := r.classify(p)
	if overridden {
		p.MappingRule = "manual:" + override.Reason
		p.Physical = override.Physical && (ifIndex == nil || ifType == IfTypeEthernetCsmacd)
		if p.Physical {
			if ifIndex == nil {
				p.Resolution = PortProvisional
			} else {
				p.Resolution = PortVerified
			}
			res.State = p.Resolution
			res.Issues = nil
		}
		for _, alias := range append([]PortKey{key}, override.Aliases...) {
			if existing, ok := r.ports.Get(device, alias); ok && existing != p {
				// Explicitly verified aliases may supersede a name-only remote
				// placeholder. A mapped or otherwise independent port remains a
				// conflict; never merge two physical ports based on an alias.
				if existing.IfIndex == nil && !existing.Physical && existing.MappingRule == "provisional-ifname" && p.IfIndex != nil && p.Physical {
					delete(r.ports.ports, existing.Ref)
					for k, owner := range r.ports.byKey {
						if owner == existing {
							r.ports.byKey[k] = p
						}
					}
				} else {
					extra = append(extra, model.Issue{Code: "PORT_ID_CHANGED", Component: "topology", Message: "manual alias already belongs to another port"})
					continue
				}
			}
			r.ports.byKey[compositeKey(device, alias)] = p
			found := false
			for _, a := range p.Aliases {
				if a == alias {
					found = true
				}
			}
			if !found {
				p.Aliases = append(p.Aliases, alias)
			}
		}
	}
	if p.Physical && p.Resolution == PortVerified {
		if alias, ok := r.aliasForCanonical(device, p); ok {
			if issue := r.bindVerifiedAlias(p, alias); issue != nil {
				extra = append(extra, *issue)
			}
		}
	}
	res.Issues = append(extra, res.Issues...)
	if len(extra) > 0 {
		p.Resolution = PortConflict
		p.Physical = false
		res.State = PortConflict
	}
	return res
}

// ResolveRemotePort resolves the advertised remote port. It first tries an
// exact subtype+raw match against the remote device's own local port table; if
// the peer has not been scanned it may build a provisional port for an
// interfaceName, otherwise the port is unresolved (no formal link).
func (r *Resolver) ResolveRemotePort(remote model.DevRef, n model.LLDPNeighbor, remoteLocalPorts []model.LocalPort, remoteIfaces []model.Interface) PortResolution {
	key := MakePortKey(n.Port.Subtype, n.Port.Raw)
	if p, ok := r.ports.Get(remote, key); ok && (p.Resolution == PortVerified || p.Resolution == PortConflict || (p.IfIndex != nil && r.snapshots[remote] == nil)) {
		return PortResolution{Port: p, State: p.Resolution}
	}
	if snap := r.snapshots[remote]; snap != nil {
		remoteLocalPorts, remoteIfaces = snap.LocalPorts, snap.Interfaces
	}
	if _, ok := r.verifiedInterfaceAlias(remote, n.Port); ok {
		return r.ResolveLocalPort(remote, model.LocalPort{ID: n.Port, Description: n.PortDescription}, remoteIfaces)
	}
	if n.Port.Subtype == 5 {
		if name, ok := r.rules[r.deviceRules[remote]].Aliases[string(n.Port.Raw)]; ok {
			if p, exists := r.ports.Get(remote, MakePortKey(5, []byte(name))); exists {
				return PortResolution{Port: p, State: p.Resolution}
			}
		}
	}
	if _, ok := r.overrides[r.deviceIdentities[remote]][key]; ok {
		return r.ResolveLocalPort(remote, model.LocalPort{ID: n.Port, Description: n.PortDescription}, remoteIfaces)
	}

	for _, rlp := range remoteLocalPorts {
		if rlp.ID.Subtype == n.Port.Subtype && bytes.Equal(rlp.ID.Raw, n.Port.Raw) {
			ifIndex, ifType, rule := r.localMapping(remote, rlp, remoteIfaces)
			p := r.ports.upsert(remote, key, rlp, ifIndex, ifType, "remote-"+rule)
			if p.Aliases == nil {
				p.Aliases = []PortKey{key}
			}
			return r.classify(p)
		}
	}

	lp := model.LocalPort{ID: n.Port, Description: n.PortDescription}
	if n.Port.Subtype == lldp.PortSubtypeInterfaceName {
		p := r.ports.upsert(remote, key, lp, nil, 0, "provisional-ifname")
		p.Resolution = PortProvisional
		return PortResolution{Port: p, State: PortProvisional, Issues: []model.Issue{{
			Code: "PORT_UNRESOLVED", Component: "topology",
			Message: "remote interfaceName port is provisional until the peer is scanned",
		}}}
	}
	p := r.ports.upsert(remote, key, lp, nil, 0, "unresolved-subtype")
	p.Resolution = PortUnresolved
	return PortResolution{Port: p, State: PortUnresolved, Issues: []model.Issue{{
		Code: "PORT_UNRESOLVED", Component: "topology",
		Message: fmt.Sprintf("remote port subtype %d cannot be mapped to a physical interface", n.Port.Subtype),
	}}}
}

var legacyGigabitPortName = regexp.MustCompile(`^GigabitEthernet[1-9][0-9]*/0/[1-9][0-9]*$`)

func (r *Resolver) classify(p *Port) PortResolution {
	var issues []model.Issue
	state := PortUnresolved
	// Preserve the observed ifType. Only an explicitly verified model rule can
	// accept obsolete gigabitEthernet(117), and only for exact physical names.
	legacy := p.IfType == 117 && p.Subtype == 5 && legacyGigabitPortName.Match(p.RawID) && r.rules[r.deviceRules[p.Device]].LegacyGigabitEthernet
	p.Physical = p.IfIndex != nil && (IsPhysicalIfType(p.IfType) || legacy)
	switch {
	case p.Physical:
		state = PortVerified
	case p.IfIndex != nil && IsLagIfType(p.IfType):
		state = PortProvisional
		issues = append(issues, model.Issue{
			Code: "NON_PHYSICAL_PORT", Component: "topology",
			Message: "resolved to LAG; LAG LLDP rows are not split into member links",
		})
	case p.IfIndex != nil:
		state = PortProvisional
		issues = append(issues, model.Issue{
			Code: "NON_PHYSICAL_PORT", Component: "topology",
			Message: fmt.Sprintf("resolved to non-physical ifType %d", p.IfType),
		})
	default:
		state = PortUnresolved
		issues = append(issues, model.Issue{
			Code: "PORT_UNRESOLVED", Component: "topology",
			Message: fmt.Sprintf("port %s has no unambiguous interface (%s)", p.Key, p.MappingRule),
		})
	}
	p.Resolution = state
	return PortResolution{Port: p, State: state, Issues: issues}
}

// resolveLocalMapping maps a local LLDP port ID to an ifIndex using only exact,
// unambiguous matches. It never treats locPortNum as an ifIndex.
func resolveLocalMapping(lp model.LocalPort, ifaces []model.Interface) (*int32, int32, string) {
	switch lp.ID.Subtype {
	case lldp.PortSubtypeInterfaceName:
		if idx, ok := uniqueByName(ifaces, string(lp.ID.Raw)); ok {
			return ptrIface(ifaces, idx, "ifname-exact")
		}
		return nil, 0, "ifname-unresolved"
	case lldp.PortSubtypeInterfaceAlias:
		if idx, ok := uniqueByAlias(ifaces, string(lp.ID.Raw)); ok {
			return ptrIface(ifaces, idx, "ifalias-exact")
		}
		return nil, 0, "ifalias-unresolved"
	case lldp.PortSubtypeMACAddress:
		if idx, ok := uniqueByMAC(ifaces, lp.ID.Raw); ok {
			return ptrIface(ifaces, idx, "mac-exact")
		}
		return nil, 0, "mac-unresolved"
	default:
		return nil, 0, "unmapped-subtype"
	}
}

func ptrIface(ifaces []model.Interface, idx int, rule string) (*int32, int32, string) {
	i := ifaces[idx].IfIndex
	return &i, ifaces[idx].Type, rule
}

func uniqueByName(ifaces []model.Interface, name string) (int, bool) {
	if name == "" {
		return 0, false
	}
	idx := -1
	for i := range ifaces {
		if ifaces[i].Name == name {
			if idx != -1 {
				return 0, false
			}
			idx = i
		}
	}
	return idx, idx != -1
}

func uniqueByAlias(ifaces []model.Interface, alias string) (int, bool) {
	if alias == "" {
		return 0, false
	}
	idx := -1
	for i := range ifaces {
		if ifaces[i].Alias == alias {
			if idx != -1 {
				return 0, false
			}
			idx = i
		}
	}
	return idx, idx != -1
}

func uniqueByMAC(ifaces []model.Interface, mac []byte) (int, bool) {
	return model.PhysicalInterfaceByMAC(ifaces, mac)
}
