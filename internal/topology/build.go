package topology

import (
	"sort"
	"time"

	"gonet/internal/identity"
	"gonet/internal/model"
)

// UnresolvedObservation preserves an observation whose remote identity or port
// could not be resolved. It keeps the full raw row for delayed/manual resolving
// and never becomes a formal link.
type UnresolvedObservation struct {
	Observer      model.DevRef        `json:"observer"`
	LocalPort     model.PortRef       `json:"local_port,omitempty"`
	Remote        model.DevRef        `json:"remote,omitempty"`
	Row           model.NeighborIndex `json:"row"`
	Raw           model.LLDPNeighbor  `json:"raw"`
	Reason        string              `json:"reason"`
	At            time.Time           `json:"at"`
	ObservationID int64               `json:"-"`
	ReasonCodes   []string            `json:"-"`
	Conflict      bool                `json:"-"`
}

// Graph is the immutable M2 offline topology result. It is built from a fixed
// set of snapshots and contains no database state.
type Graph struct {
	SchemaVersion   int                     `json:"schema_version"`
	Devices         []*identity.Device      `json:"devices"`
	Ports           []*Port                 `json:"ports"`
	Links           []model.LinkEvidence    `json:"links"`
	Observations    []model.LinkObservation `json:"observations"`
	Unresolved      []UnresolvedObservation `json:"unresolved"`
	Conflicts       []Conflict              `json:"conflicts"`
	SelfConnections []SelfConnection        `json:"self_connections"`
	Issues          []model.Issue           `json:"issues"`
}

type entry struct {
	Device     *identity.Device
	Snapshot   *model.DeviceSnapshot
	localByNum map[uint32]model.PortRef
}

// Builder constructs an offline Graph from device snapshots. Snapshots may be
// added in any order; Build performs the second phase once all peers are known.
type Builder struct {
	registry     *identity.Registry
	resolver     *Resolver
	links        *LinkBuilder
	entries      []*entry
	byDevice     map[model.DevRef]*entry
	observations []model.LinkObservation
	unresolved   []UnresolvedObservation
	issues       []model.Issue
}

// NewBuilder creates a Builder. A nil resolver is replaced with an empty one.
func NewBuilder(reg *identity.Registry, res *Resolver) *Builder {
	if res == nil {
		res = NewResolver(nil)
	}
	return &Builder{
		registry: reg,
		resolver: res,
		links:    NewLinkBuilder(),
		byDevice: map[model.DevRef]*entry{},
	}
}

// AddSnapshot performs phase 1: resolve the device identity and register all of
// its local ports so later peers can match against them.
func (b *Builder) AddSnapshot(snap *model.DeviceSnapshot) {
	res := b.registry.ResolveDirect(snap)
	b.issues = append(b.issues, res.Issues...)
	if res.Device == nil {
		// Conflict: the snapshot cannot be attached to a device this round.
		return
	}
	e := &entry{
		Device:     res.Device,
		Snapshot:   snap,
		localByNum: map[uint32]model.PortRef{},
	}
	b.resolver.SetDeviceRule(res.Device.Ref, res.Device.Classification.RuleID)
	b.resolver.SetDeviceIdentity(res.Device.Ref, res.Device.StrongKey)
	b.resolver.SetDeviceSnapshot(res.Device.Ref, snap)
	for _, lp := range snap.LocalPorts {
		pr := b.resolver.ResolveLocalPort(res.Device.Ref, lp, snap.Interfaces)
		b.issues = append(b.issues, pr.Issues...)
		if pr.Port != nil {
			e.localByNum[lp.Number] = pr.Port.Ref
		}
	}
	b.entries = append(b.entries, e)
	b.byDevice[res.Device.Ref] = e
}

// Build performs phase 2 and freezes the graph. Output ordering is stable.
func (b *Builder) Build() *Graph {
	for _, e := range b.entries {
		for _, n := range e.Snapshot.Neighbors {
			b.processNeighbor(e, n)
		}
	}
	lr := b.links.Build()
	b.issues = append(b.issues, lr.Issues...)

	sort.Slice(b.observations, func(i, j int) bool { return lessObservation(b.observations[i], b.observations[j]) })
	sort.Slice(b.unresolved, func(i, j int) bool { return lessUnresolved(b.unresolved[i], b.unresolved[j]) })

	return &Graph{
		SchemaVersion:   model.SchemaVersion,
		Devices:         b.registry.Devices(),
		Ports:           b.resolver.Ports().All(),
		Links:           lr.Links,
		Observations:    b.observations,
		Unresolved:      b.unresolved,
		Conflicts:       lr.Conflicts,
		SelfConnections: lr.SelfConnections,
		Issues:          b.issues,
	}
}

func (b *Builder) processNeighbor(e *entry, n model.LLDPNeighbor) {
	at := e.Snapshot.CollectedAt
	localRef, ok := e.localByNum[n.Index.LocalPortNum]
	local, localOK := b.resolver.Ports().ByRef(localRef)
	if !e.Device.Classification.Managed() || !localOK || !local.Physical || local.Resolution == PortConflict {
		ok = false
	}
	if !ok {
		b.unresolved = append(b.unresolved, UnresolvedObservation{
			Observer: e.Device.Ref, Row: n.Index, Raw: n, At: at,
			Reason: "observer local port not found for localPortNum",
		})
		return
	}
	remoteDev, ok := b.resolveRemote(n)
	if ok && !remoteDev.Classification.Managed() {
		ok = false
	}
	if !ok {
		b.unresolved = append(b.unresolved, UnresolvedObservation{
			Observer: e.Device.Ref, LocalPort: localRef, Row: n.Index, Raw: n, At: at,
			Reason: "remote identity unresolved",
		})
		return
	}
	remoteRef, ok := b.resolveRemotePort(remoteDev, n)
	if !ok {
		b.unresolved = append(b.unresolved, UnresolvedObservation{
			Observer: e.Device.Ref, LocalPort: localRef, Remote: remoteDev.Ref, Row: n.Index, Raw: n, At: at,
			Reason: "remote port unresolved",
		})
		return
	}
	obs := model.LinkObservation{
		Observer:   e.Device.Ref,
		LocalPort:  localRef,
		Remote:     remoteDev.Ref,
		RemotePort: remoteRef,
		Row:        n.Index,
		At:         at,
		Raw:        n,
	}
	b.observations = append(b.observations, obs)
	b.links.Add(obs)
}

func (b *Builder) resolveRemote(n model.LLDPNeighbor) (*identity.Device, bool) {
	res := b.registry.ResolveAdvertised(n)
	if res.State == identity.Resolved && res.Device != nil {
		return res.Device, true
	}
	return nil, false
}

func (b *Builder) resolveRemotePort(remoteDev *identity.Device, n model.LLDPNeighbor) (model.PortRef, bool) {
	key := MakePortKey(n.Port.Subtype, n.Port.Raw)
	if p, ok := b.resolver.Ports().Get(remoteDev.Ref, key); ok {
		return p.Ref, p.Physical && p.Resolution != PortConflict
	}
	var remoteLocalPorts []model.LocalPort
	var remoteIfaces []model.Interface
	if e, ok := b.byDevice[remoteDev.Ref]; ok {
		remoteLocalPorts = e.Snapshot.LocalPorts
		remoteIfaces = e.Snapshot.Interfaces
	}
	res := b.resolver.ResolveRemotePort(remoteDev.Ref, n, remoteLocalPorts, remoteIfaces)
	b.issues = append(b.issues, res.Issues...)
	if res.Port != nil && res.Port.Physical && res.State != PortConflict {
		return res.Port.Ref, true
	}
	return 0, false
}

func lessObservation(a, b model.LinkObservation) bool {
	if a.Observer != b.Observer {
		return a.Observer < b.Observer
	}
	if a.LocalPort != b.LocalPort {
		return a.LocalPort < b.LocalPort
	}
	if a.Remote != b.Remote {
		return a.Remote < b.Remote
	}
	return lessIndex(a.Row, b.Row)
}

func lessUnresolved(a, b UnresolvedObservation) bool {
	if a.Observer != b.Observer {
		return a.Observer < b.Observer
	}
	if a.LocalPort != b.LocalPort {
		return a.LocalPort < b.LocalPort
	}
	return lessIndex(a.Row, b.Row)
}

func lessIndex(a, b model.NeighborIndex) bool {
	if a.TimeMark != b.TimeMark {
		return a.TimeMark < b.TimeMark
	}
	if a.LocalPortNum != b.LocalPortNum {
		return a.LocalPortNum < b.LocalPortNum
	}
	return a.RemoteIndex < b.RemoteIndex
}
