package identity

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"gonet/internal/model"
)

// IdentityState is the device-level identity state.
type IdentityState string

const (
	StateProvisional IdentityState = "provisional"
	StateVerified    IdentityState = "verified"
	StateConflict    IdentityState = "conflict"
)

// AddressState is the per-address binding state.
type AddressState string

const (
	AddrVerified AddressState = "verified"
	AddrConflict AddressState = "conflict"
	AddrRetired  AddressState = "retired"
)

// Address is one management address bound to a device.
type Address struct {
	Addr   netip.Addr   `json:"addr"`
	State  AddressState `json:"state"`
	Source string       `json:"source"`
}

// Device is an in-memory device record. Ref is a temporary M2 identifier.
type Device struct {
	Ref            model.DevRef   `json:"ref"`
	State          IdentityState  `json:"state"`
	StrongKey      string         `json:"strong_key"`
	IdentityKeys   []string       `json:"identity_keys,omitempty"`
	Chassis        model.TypedID  `json:"chassis"`
	SysName        string         `json:"sys_name"`
	SysObjectID    string         `json:"sys_object_id"`
	Classification Classification `json:"classification"`
	Addresses      []Address      `json:"addresses"`
	FirstSeen      time.Time      `json:"first_seen"`
	LastSeen       time.Time      `json:"last_seen"`
}

// ResolutionState is the outcome of identity resolution.
type ResolutionState string

const (
	Resolved            ResolutionState = "resolved"
	ResolvedProvisional ResolutionState = "provisional"
	ResolvedConflict    ResolutionState = "conflict"
	ResolvedUnresolved  ResolutionState = "unresolved"
)

// Override is an explicit manual identity mapping for a chassis ID.
type Override struct {
	Subtype      uint8
	RawHex       string
	CanonicalKey string // manual:<value>
}

// Options configures a Registry.
type Options struct {
	AllowNetworkAddressChassis bool
	Rules                      []Rule
	Overrides                  []Override
	ClassificationOverrides    []ClassificationOverride
	Now                        func() time.Time
}

// Registry is an in-memory identity store for M2/M3.
type Registry struct {
	allowNetAddr            bool
	classifier              *Classifier
	overrides               []Override
	classificationOverrides map[string]Classification
	byKey                   map[string]*Device
	byAddr                  map[netip.Addr]*Device
	devices                 map[model.DevRef]*Device
	nextRef                 model.DevRef
	now                     func() time.Time
}

// New builds a Registry.
func New(o Options) (*Registry, error) {
	classes, err := compileClassificationOverrides(o.ClassificationOverrides)
	if err != nil {
		return nil, err
	}
	seen := map[string]string{}
	strongOwners := map[string]string{}
	for _, override := range o.Overrides {
		if !strings.HasPrefix(override.CanonicalKey, "manual:") || len(override.CanonicalKey) == len("manual:") {
			return nil, fmt.Errorf("override canonical key must be manual:<value>")
		}
		b, err := hex.DecodeString(override.RawHex)
		if err != nil || len(b) == 0 || len(b) > 255 || override.Subtype < 1 || override.Subtype > 7 {
			return nil, fmt.Errorf("invalid override chassis")
		}
		match := fmt.Sprintf("%d:%x", override.Subtype, b)
		if previous, ok := seen[match]; ok && previous != override.CanonicalKey {
			return nil, fmt.Errorf("conflicting identity overrides")
		}
		seen[match] = override.CanonicalKey
		if key, strong := StrongKey(override.Subtype, b, o.AllowNetworkAddressChassis); strong {
			if previous, ok := strongOwners[override.CanonicalKey]; ok && previous != key {
				return nil, fmt.Errorf("manual mapping cannot merge inconsistent strong chassis")
			}
			strongOwners[override.CanonicalKey] = key
		}
	}
	c, err := NewClassifier(o.Rules)
	if err != nil {
		return nil, err
	}
	now := o.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Registry{
		allowNetAddr:            o.AllowNetworkAddressChassis,
		classifier:              c,
		classificationOverrides: classes,
		overrides:               o.Overrides,
		byKey:                   map[string]*Device{},
		byAddr:                  map[netip.Addr]*Device{},
		devices:                 map[model.DevRef]*Device{},
		now:                     now,
	}, nil
}

// DirectResult is the outcome of resolving a directly collected snapshot.
type DirectResult struct {
	Device *Device
	State  ResolutionState
	Issues []model.Issue
}

// AdvertisedResult is the outcome of resolving an advertised neighbor row.
type AdvertisedResult struct {
	Device *Device
	State  ResolutionState
	Issues []model.Issue
}

// ResolveDirect resolves a successfully collected snapshot to a device,
// applying the upgrade and conflict rules of section 4.2.
func (r *Registry) ResolveDirect(snap *model.DeviceSnapshot) DirectResult {
	now := r.now()
	target := snap.Device.Target.Unmap()
	chassis := snap.Device.Chassis
	key, strong := r.identityKey(chassis)
	configuredKey := key
	matched, ambiguous := r.knownChassis(chassis)
	if ambiguous {
		return DirectResult{State: ResolvedConflict, Issues: []model.Issue{{Code: "IDENTITY_CONFLICT", Component: "identity", Message: "normalized MAC has multiple device owners"}}}
	}
	if matched != nil && matched.StrongKey != "" {
		key = matched.StrongKey
		strong = true
	}
	class := r.classifier.Classify(snap.Device.SysObjectID, snap.Device.SysDescription,
		snap.Device.CapSupported, snap.Device.CapEnabled)
	if override, ok := r.classificationOverrides[key]; strong && ok {
		class = override
	}
	// A persisted device may retain an older primary identity. Explicit chassis
	// mappings still govern classification without replacing that device's ID.
	if override, ok := r.classificationOverrides[configuredKey]; strong && ok {
		class = override
	}
	if owner, ok := r.byAddr[target]; ok {
		for _, a := range owner.Addresses {
			if a.Addr == target && a.State == AddrConflict {
				return r.conflict(owner, target, "ADDRESS_CONFLICT", "conflicted address requires manual retirement before reuse")
			}
		}
	}

	if strong {
		// Known strong identity: same device, add/refresh verified address.
		if dev, ok := r.byKey[key]; ok {
			if other, ok := r.byAddr[target]; ok && other != dev {
				dev.State = StateConflict
				code := "ADDRESS_CONFLICT"
				if other.StrongKey == "" {
					code = "IDENTITY_CONFLICT"
				}
				return r.conflict(other, target, code,
					fmt.Sprintf("identity %s is owned by device %d while address %s is held by device %d",
						key, dev.Ref, target, other.Ref))
			}
			r.upsertAddress(dev, target, AddrVerified, "seed")
			dev.State = StateVerified
			dev.Chassis = chassis
			applySnapshot(dev, snap, class, now)
			r.bindChassis(dev, chassis)
			return DirectResult{Device: dev, State: Resolved}
		}

		// Strong identity not owned yet.
		if dev, ok := r.byAddr[target]; ok {
			if dev.StrongKey == "" {
				// IP temporary device gains its unique strong identity: upgrade
				// in place and preserve the device ref (I04).
				r.upgrade(dev, key, chassis, class, now)
				applySnapshot(dev, snap, class, now)
				return DirectResult{Device: dev, State: Resolved}
			}
			// Address is bound to another strong device: conflict, do not rebind.
			return r.conflict(dev, target, "ADDRESS_CONFLICT",
				fmt.Sprintf("address %s is bound to device %d with a different identity", target, dev.Ref))
		}

		dev := r.newDevice(key, chassis, class, StateVerified, now)
		r.upsertAddress(dev, target, AddrVerified, "seed")
		applySnapshot(dev, snap, class, now)
		r.bindChassis(dev, chassis)
		return DirectResult{Device: dev, State: Resolved}
	}

	// Weak or absent strong identity: an IP temporary device keyed only by
	// address. Chassis bytes are preserved but never merge devices.
	if dev, ok := r.byAddr[target]; ok {
		applySnapshot(dev, snap, class, now)
		return DirectResult{Device: dev, State: ResolvedProvisional}
	}
	dev := r.newDevice("", chassis, class, StateProvisional, now)
	r.upsertAddress(dev, target, AddrVerified, "seed")
	applySnapshot(dev, snap, class, now)
	return DirectResult{Device: dev, State: ResolvedProvisional}
}

// applySnapshot records the descriptive (non-identity) attributes from the most
// recent direct collection.
func applySnapshot(dev *Device, snap *model.DeviceSnapshot, class Classification, now time.Time) {
	dev.LastSeen = now
	dev.SysName = snap.Device.SysName
	dev.SysObjectID = snap.Device.SysObjectID
	dev.Classification = class
}

// ResolveAdvertised resolves an advertised neighbor. Advertised management
// addresses are candidates only and are never bound as verified. Without a
// known strong identity the result is unresolved.
func (r *Registry) ResolveAdvertised(n model.LLDPNeighbor) AdvertisedResult {
	if d, ambiguous := r.knownChassis(n.Chassis); ambiguous {
		return AdvertisedResult{State: ResolvedConflict, Issues: []model.Issue{{Code: "IDENTITY_CONFLICT", Component: "identity", Message: "normalized MAC has multiple device owners"}}}
	} else if d != nil {
		r.bindChassis(d, n.Chassis)
		return AdvertisedResult{Device: d, State: Resolved}
	}
	key, strong := r.identityKey(n.Chassis)
	if !strong {
		// An omitted chassis does not erase an already SNMP-verified address
		// association. Never use an arbitrary different weak chassis or a name
		// to merge identities, and reject advertisements naming two owners.
		if n.Chassis.Subtype == 0 || len(n.Chassis.Raw) == 0 {
			var owner *Device
			for _, ip := range n.MgmtAddresses {
				dev := r.byAddr[ip.Unmap()]
				if dev == nil || dev.State != StateVerified {
					continue
				}
				verified := false
				for _, addr := range dev.Addresses {
					if addr.Addr == ip.Unmap() && addr.State == AddrVerified {
						verified = true
					}
				}
				if !verified {
					continue
				}
				if owner != nil && owner != dev {
					return AdvertisedResult{State: ResolvedConflict, Issues: []model.Issue{{Code: "IDENTITY_CONFLICT", Component: "identity", Message: "advertised management addresses belong to different verified devices"}}}
				}
				owner = dev
			}
			if owner != nil {
				return AdvertisedResult{Device: owner, State: Resolved}
			}
		}
		return AdvertisedResult{State: ResolvedUnresolved, Issues: []model.Issue{{
			Code: "IDENTITY_UNRESOLVED", Component: "identity",
			Message: "advertised chassis has no strong identity; not claiming a device",
		}}}
	}
	if dev, ok := r.byKey[key]; ok {
		return AdvertisedResult{Device: dev, State: Resolved}
	}
	return AdvertisedResult{State: ResolvedUnresolved, Issues: []model.Issue{{
		Code: "IDENTITY_UNRESOLVED", Component: "identity",
		Message: "advertised strong identity is not yet directly collected",
	}}}
}

// EnsureAdvertised returns the device for an advertised strong identity. When
// the strong key is new it creates an unscanned (provisional) device so the
// coordinator can enqueue it for collection; weak or absent identities return
// false and are never turned into formal devices (section 4.2).
func (r *Registry) EnsureAdvertised(n model.LLDPNeighbor) (*Device, bool) {
	if d, ambiguous := r.knownChassis(n.Chassis); ambiguous {
		return nil, false
	} else if d != nil {
		r.bindChassis(d, n.Chassis)
		return d, true
	}
	key, strong := r.identityKey(n.Chassis)
	if !strong {
		return nil, false
	}
	if dev, ok := r.byKey[key]; ok {
		return dev, true
	}
	class := r.ClassifyNeighbor(n)
	d := r.newDevice(key, n.Chassis, class, StateProvisional, r.now())
	r.bindChassis(d, n.Chassis)
	return d, true
}

func (r *Registry) Matches(ref model.DevRef, chassis model.TypedID) bool {
	d, ok := r.ByRef(ref)
	if !ok {
		return false
	}
	owner, ambiguous := r.knownChassis(chassis)
	return !ambiguous && owner == d
}

// EvidenceKey applies the same explicit mappings and normalization as discovery,
// without admitting a device or binding an address.
func (r *Registry) EvidenceKey(chassis model.TypedID) (string, bool) { return r.identityKey(chassis) }
func (r *Registry) EvidenceOwner(chassis model.TypedID) (*Device, bool) {
	return r.knownChassis(chassis)
}
func (r *Registry) ClassifyFacts(d model.DeviceInfo) Classification {
	key, _ := r.identityKey(d.Chassis)
	if c, ok := r.classificationOverrides[key]; ok {
		return c
	}
	return r.classifier.Classify(d.SysObjectID, d.SysDescription, d.CapSupported, d.CapEnabled)
}

// ClassifyNeighbor classifies an advertised neighbor using its description and
// capabilities. sysObjectID is unavailable until the peer is collected, so a
// bridge advertisement is only a candidate here.
func (r *Registry) ClassifyNeighbor(n model.LLDPNeighbor) Classification {
	if d, ambiguous := r.knownChassis(n.Chassis); !ambiguous && d != nil && d.State != StateConflict && d.Classification.Managed() {
		return d.Classification
	}
	return r.classifier.ClassifyAdvertisement(n.SysDescription, n.CapSupported, n.CapEnabled)
}

// IsStrong reports whether the chassis yields a usable strong identity key
// (including manual overrides). Used by the coordinator to decide whether a new
// device may be admitted from an advertisement.
func (r *Registry) IsStrong(chassis model.TypedID) bool {
	_, ok := r.identityKey(chassis)
	return ok
}

func (r *Registry) identityKey(chassis model.TypedID) (string, bool) {
	rawHex := hex.EncodeToString(chassis.Raw)
	for _, o := range r.overrides {
		if o.Subtype == chassis.Subtype && strings.EqualFold(o.RawHex, rawHex) && o.CanonicalKey != "" {
			return o.CanonicalKey, true
		}
	}
	return NormalizedKey(chassis, r.allowNetAddr)
}

func (r *Registry) newDevice(key string, chassis model.TypedID, class Classification, state IdentityState, now time.Time) *Device {
	r.nextRef++
	dev := &Device{
		Ref:            r.nextRef,
		State:          state,
		StrongKey:      key,
		Chassis:        chassis,
		Classification: class,
		FirstSeen:      now,
		LastSeen:       now,
	}
	r.devices[dev.Ref] = dev
	if key != "" {
		r.byKey[key] = dev
	}
	return dev
}

func (r *Registry) upgrade(dev *Device, key string, chassis model.TypedID, class Classification, now time.Time) {
	dev.StrongKey = key
	dev.Chassis = chassis
	dev.State = StateVerified
	dev.Classification = class
	dev.LastSeen = now
	r.byKey[key] = dev
}

func (r *Registry) upsertAddress(dev *Device, addr netip.Addr, state AddressState, source string) {
	for i := range dev.Addresses {
		if dev.Addresses[i].Addr == addr {
			if dev.Addresses[i].State != AddrConflict {
				dev.Addresses[i].State = state
			}
			return
		}
	}
	dev.Addresses = append(dev.Addresses, Address{Addr: addr, State: state, Source: source})
	r.byAddr[addr] = dev
}

// conflict marks the contested address as conflict (keeping the original
// association for audit) and returns a conflict result. The owner device's
// identity is never overwritten.
func (r *Registry) conflict(owner *Device, target netip.Addr, code, msg string) DirectResult {
	owner.State = StateConflict
	for i := range owner.Addresses {
		if owner.Addresses[i].Addr == target {
			owner.Addresses[i].State = AddrConflict
		}
	}
	return DirectResult{State: ResolvedConflict, Issues: []model.Issue{{
		Code: code, Component: "identity", Message: msg,
	}}}
}

// Devices returns all devices sorted by ref (stable).
func (r *Registry) Devices() []*Device {
	out := make([]*Device, 0, len(r.devices))
	for _, d := range r.devices {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// ByRef looks up a device by its temporary ref.
func (r *Registry) ByRef(ref model.DevRef) (*Device, bool) {
	d, ok := r.devices[ref]
	return d, ok
}

// ByKey looks up a device by strong identity key.
func (r *Registry) ByKey(key string) (*Device, bool) {
	d, ok := r.byKey[key]
	return d, ok
}

// ByAddr looks up a device by a bound address.
func (r *Registry) ByAddr(addr netip.Addr) (*Device, bool) {
	d, ok := r.byAddr[addr.Unmap()]
	return d, ok
}
