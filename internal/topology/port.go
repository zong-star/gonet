// Package topology normalizes ports and links. T202 implements the typed port
// key, local/remote port resolution, physical-interface judgement and the
// device-internal alias list. Link aggregation and evidence方向 land in T203.
package topology

import (
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"gonet/internal/model"
)

// ifType values relevant to physicality (IF-MIB / IANAifType).
const (
	IfTypeEthernetCsmacd   = 6
	IfTypeSoftwareLoopback = 24
	IfTypeTunnel           = 131
	IfTypeVlan             = 136
	IfTypeLAG              = 161
)

// PortState is the resolution state of a port.
type PortState string

const (
	PortVerified    PortState = "verified"
	PortProvisional PortState = "provisional"
	PortConflict    PortState = "conflict"
	PortUnresolved  PortState = "unresolved"
)

// PortKey is a device-local typed key: lldp:<subtype>:<hex raw bytes>.
type PortKey string

// MakePortKey builds the canonical typed key for a port.
func MakePortKey(subtype uint8, raw []byte) PortKey {
	return PortKey(fmt.Sprintf("lldp:%d:%s", subtype, hex.EncodeToString(raw)))
}

// Port is a normalized port record. Key is the stable device-local identity;
// IfIndex is only a mutable attribute of the current round.
type Port struct {
	Ref         model.PortRef `json:"ref"`
	Device      model.DevRef  `json:"device"`
	Key         PortKey       `json:"key"`
	Subtype     uint8         `json:"subtype"`
	RawID       []byte        `json:"raw_id"`
	Aliases     []PortKey     `json:"aliases"`
	DisplayName string        `json:"display_name"`
	IfIndex     *int32        `json:"if_index"`
	LLDPPortNum *uint32       `json:"lldp_port_num"`
	IfType      int32         `json:"if_type"`
	Resolution  PortState     `json:"resolution"`
	Physical    bool          `json:"physical"`
	MappingRule string        `json:"mapping_rule"`
	FirstSeen   time.Time     `json:"first_seen"`
	LastSeen    time.Time     `json:"last_seen"`
}

// PortRegistry stores ports keyed by (device, typed key).
type PortRegistry struct {
	byKey map[string]*Port
	ports map[model.PortRef]*Port
	next  model.PortRef
	now   func() time.Time
}

// NewPortRegistry builds a registry. now defaults to time.Now.
func NewPortRegistry(now func() time.Time) *PortRegistry {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &PortRegistry{
		byKey: map[string]*Port{},
		ports: map[model.PortRef]*Port{},
		now:   now,
	}
}

func compositeKey(device model.DevRef, key PortKey) string {
	return fmt.Sprintf("%d|%s", device, key)
}

// Get returns the port for (device, key), if any.
func (r *PortRegistry) Get(device model.DevRef, key PortKey) (*Port, bool) {
	p, ok := r.byKey[compositeKey(device, key)]
	return p, ok
}

// ByRef returns a port by ref.
func (r *PortRegistry) ByRef(ref model.PortRef) (*Port, bool) {
	p, ok := r.ports[ref]
	return p, ok
}

// All returns ports sorted by ref (stable).
func (r *PortRegistry) All() []*Port {
	out := make([]*Port, 0, len(r.ports))
	for _, p := range r.ports {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

func (r *PortRegistry) upsert(device model.DevRef, key PortKey, lp model.LocalPort, ifIndex *int32, ifType int32, rule string) *Port {
	ck := compositeKey(device, key)
	if p, ok := r.byKey[ck]; ok {
		// Same typed key: update mutable attributes only (L04). Never new port.
		p.IfIndex = ifIndex
		p.IfType = ifType
		p.MappingRule = rule
		p.Physical = IsPhysicalIfType(ifType)
		p.LastSeen = r.now()
		if lp.Number > 0 {
			n := lp.Number
			p.LLDPPortNum = &n
		}
		return p
	}
	r.next++
	p := &Port{
		Ref:         r.next,
		Device:      device,
		Key:         key,
		Subtype:     lp.ID.Subtype,
		RawID:       append([]byte(nil), lp.ID.Raw...),
		DisplayName: lp.Description,
		IfIndex:     ifIndex,
		IfType:      ifType,
		MappingRule: rule,
		Physical:    IsPhysicalIfType(ifType),
		FirstSeen:   r.now(),
		LastSeen:    r.now(),
	}
	if lp.Number > 0 {
		n := lp.Number
		p.LLDPPortNum = &n
	}
	r.byKey[ck] = p
	r.ports[p.Ref] = p
	return p
}

// IsPhysicalIfType is the M2 physical-interface candidate rule: ethernetCsmacd
// only. Vendor adapters may later exclude pseudo-physical interfaces.
func IsPhysicalIfType(t int32) bool {
	return t == IfTypeEthernetCsmacd
}

// IsLagIfType reports the IEEE 802.3ad link aggregation type.
func IsLagIfType(t int32) bool {
	return t == IfTypeLAG
}
