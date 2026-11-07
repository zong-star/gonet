package topology

import (
	"errors"
	"fmt"
	"sort"

	"gonet/internal/model"
)

// ErrSelfLink is returned when both endpoints are the same device.
var ErrSelfLink = errors.New("self link")

// Canonical orders the two endpoints so device A < device B, swapping ports
// with the devices. The four-tuple is the formal link key; a device pair alone
// is never sufficient (parallel physical links must stay distinct).
func Canonical(a model.DevRef, pa model.PortRef, b model.DevRef, pb model.PortRef) (model.LinkKey, error) {
	if a == b {
		return model.LinkKey{}, ErrSelfLink
	}
	if a > b {
		a, pa, b, pb = b, pb, a, pa
	}
	return model.LinkKey{A: a, PA: pa, B: b, PB: pb}, nil
}

// PortRefKey identifies one endpoint (device + port ref).
type PortRefKey struct {
	Device model.DevRef
	Port   model.PortRef
}

// SelfConnection is a same-chassis advertisement kept only as a diagnostic.
type SelfConnection struct {
	Device     model.DevRef        `json:"device"`
	Port       model.PortRef       `json:"port"`
	Remote     model.DevRef        `json:"remote"`
	RemotePort model.PortRef       `json:"remote_port"`
	Index      model.NeighborIndex `json:"index"`
}

// Conflict records one physical port claimed by multiple mutually exclusive
// remote endpoints. Conflicted observations never become active links.
type Conflict struct {
	Device  model.DevRef  `json:"device"`
	Port    model.PortRef `json:"port"`
	Remotes []PortRefKey  `json:"remotes"`
	Message string        `json:"message"`
}

// BuildResult is one round's aggregation output.
type BuildResult struct {
	Links           []model.LinkEvidence `json:"links"`
	Conflicts       []Conflict           `json:"conflicts"`
	SelfConnections []SelfConnection     `json:"self_connections"`
	Issues          []model.Issue        `json:"issues"`
}

// LinkBuilder aggregates one round of directed observations. It is not safe for
// concurrent use; the coordinator owns it.
type LinkBuilder struct {
	observations []model.LinkObservation
	endpoints    map[PortRefKey]map[endpoint]struct{}
	self         []SelfConnection
}

type endpoint struct {
	Device model.DevRef
	Port   model.PortRef
}

// NewLinkBuilder builds an empty per-round builder.
func NewLinkBuilder() *LinkBuilder {
	return &LinkBuilder{endpoints: map[PortRefKey]map[endpoint]struct{}{}}
}

// Add records one directed observation (observer sees remote at the given
// ports). Duplicate observations of the same direction do not add a direction.
func (b *LinkBuilder) Add(obs model.LinkObservation) {
	if obs.Observer == obs.Remote {
		b.self = append(b.self, SelfConnection{
			Device: obs.Observer, Port: obs.LocalPort,
			Remote: obs.Remote, RemotePort: obs.RemotePort, Index: obs.Row,
		})
		return
	}
	b.observations = append(b.observations, obs)
	addEndpoint(b.endpoints, PortRefKey{obs.Observer, obs.LocalPort}, endpoint{obs.Remote, obs.RemotePort})
	addEndpoint(b.endpoints, PortRefKey{obs.Remote, obs.RemotePort}, endpoint{obs.Observer, obs.LocalPort})
}

func addEndpoint(m map[PortRefKey]map[endpoint]struct{}, k PortRefKey, e endpoint) {
	set := m[k]
	if set == nil {
		set = map[endpoint]struct{}{}
		m[k] = set
	}
	set[e] = struct{}{}
}

// Build produces this round's links and conflicts. A port that maps to more
// than one distinct remote endpoint is conflicted; every observation touching
// it is excluded, so no last-write-wins link is written.
func (b *LinkBuilder) Build() BuildResult {
	conflicted := map[PortRefKey]bool{}
	var conflicts []Conflict
	for pk, set := range b.endpoints {
		if len(set) <= 1 {
			continue
		}
		conflicted[pk] = true
		remotes := make([]PortRefKey, 0, len(set))
		for e := range set {
			remotes = append(remotes, PortRefKey{Device: e.Device, Port: e.Port})
		}
		sort.Slice(remotes, func(i, j int) bool { return lessPortRefKey(remotes[i], remotes[j]) })
		conflicts = append(conflicts, Conflict{
			Device:  pk.Device,
			Port:    pk.Port,
			Remotes: remotes,
			Message: fmt.Sprintf("port (device %d port %d) is claimed by %d remote endpoints", pk.Device, pk.Port, len(remotes)),
		})
	}
	sort.Slice(conflicts, func(i, j int) bool {
		if conflicts[i].Device != conflicts[j].Device {
			return conflicts[i].Device < conflicts[j].Device
		}
		return conflicts[i].Port < conflicts[j].Port
	})

	byKey := map[model.LinkKey]*model.LinkEvidence{}
	for _, obs := range b.observations {
		if conflicted[PortRefKey{obs.Observer, obs.LocalPort}] || conflicted[PortRefKey{obs.Remote, obs.RemotePort}] {
			continue
		}
		key, err := Canonical(obs.Observer, obs.LocalPort, obs.Remote, obs.RemotePort)
		if err != nil {
			continue
		}
		ev := byKey[key]
		if ev == nil {
			ev = &model.LinkEvidence{Key: key, FirstAt: obs.At}
			byKey[key] = ev
		}
		// seenFromA/B are booleans, so duplicate PDUs, multiple remote indexes
		// or management addresses never increase the direction count.
		if obs.Observer == key.A {
			ev.SeenFromA = true
		} else {
			ev.SeenFromB = true
		}
		if obs.At.Before(ev.FirstAt) {
			ev.FirstAt = obs.At
		}
		if obs.At.After(ev.LastAt) {
			ev.LastAt = obs.At
		}
	}

	links := make([]model.LinkEvidence, 0, len(byKey))
	for _, ev := range byKey {
		links = append(links, *ev)
	}
	sort.Slice(links, func(i, j int) bool { return lessLinkKey(links[i].Key, links[j].Key) })

	var issues []model.Issue
	for _, c := range conflicts {
		issues = append(issues, model.Issue{Code: "TOPOLOGY_CONFLICT", Component: "topology", Message: c.Message})
	}
	for _, s := range b.self {
		issues = append(issues, model.Issue{
			Code: "TOPOLOGY_CONFLICT", Component: "topology",
			Message: fmt.Sprintf("same-chassis self connection on device %d port %d ignored", s.Device, s.Port),
		})
	}

	return BuildResult{Links: links, Conflicts: conflicts, SelfConnections: b.self, Issues: issues}
}

func lessPortRefKey(a, b PortRefKey) bool {
	if a.Device != b.Device {
		return a.Device < b.Device
	}
	return a.Port < b.Port
}

func lessLinkKey(a, b model.LinkKey) bool {
	if a.A != b.A {
		return a.A < b.A
	}
	if a.PA != b.PA {
		return a.PA < b.PA
	}
	if a.B != b.B {
		return a.B < b.B
	}
	return a.PB < b.PB
}
