package webui

import (
	"bytes"
	"gonet/internal/model"
	"slices"

	"gonet/internal/control"
	"gonet/internal/store/postgres"
)

type topologyConnection struct {
	groupA, groupB *model.AggregationGroup
	reasons        []string
	members        []postgres.ExportLink
	aggregateA     *postgres.LAGMemberEvidence
	aggregateB     *postgres.LAGMemberEvidence
	status, mode   string
	coverage       string
	weak           bool
}

type lagInterfaceKey struct {
	device int64
	index  int32
}

func topologyConnections(view *control.View, devices map[int64]control.Device) []topologyConnection {
	relations := map[lagInterfaceKey]postgres.LAGMemberEvidence{}
	counts := map[lagInterfaceKey]int{}
	complete := map[int64]bool{}
	groupComplete := map[lagInterfaceKey]bool{}
	tainted := map[lagInterfaceKey]bool{}
	var linkEvidence map[int64]postgres.PhysicalLinkEvidence
	if view.Evidence != nil {
		linkEvidence = view.Evidence.Links
		for id, facts := range view.Evidence.LAG {
			complete[id] = facts.Complete
			for _, g := range facts.Groups {
				if g.AggregateIfIndex != nil {
					groupComplete[lagInterfaceKey{id, *g.AggregateIfIndex}] = g.Complete
				}
			}
			for _, member := range facts.Members {
				key := lagInterfaceKey{id, member.MemberIfIndex}
				if _, exists := relations[key]; exists {
					member.Status = "conflict"
				}
				relations[key] = member
				counts[lagInterfaceKey{id, member.AggregateIfIndex}]++
				if member.Status != "confirmed" {
					tainted[lagInterfaceKey{id, member.AggregateIfIndex}] = true
				}
			}
		}
	}
	lookup := func(device int64, index *int32) (*postgres.LAGMemberEvidence, bool) {
		if index == nil {
			return nil, false
		}
		member, ok := relations[lagInterfaceKey{device, *index}]
		if ok {
			return &member, false
		}
		return nil, !ok && complete[device]
	}
	// A conflicting member invalidates the whole logical group, including its
	// otherwise valid members. Physical observations remain independently usable.
	peerGroups := map[lagInterfaceKey]map[lagInterfaceKey]bool{}
	for _, link := range view.Links {
		if linkVerification(link, view.LatestScanID) != "confirmed" {
			continue
		}
		ev := linkEvidence[link.ID]
		a, _ := lookup(link.DeviceAID, ev.A.IfIndex)
		b, _ := lookup(link.DeviceBID, ev.B.IfIndex)
		if a == nil || b == nil {
			continue
		}
		ka, kb := lagInterfaceKey{link.DeviceAID, a.AggregateIfIndex}, lagInterfaceKey{link.DeviceBID, b.AggregateIfIndex}
		for _, p := range [][2]lagInterfaceKey{{ka, kb}, {kb, ka}} {
			if peerGroups[p[0]] == nil {
				peerGroups[p[0]] = map[lagInterfaceKey]bool{}
			}
			peerGroups[p[0]][p[1]] = true
		}
		if a.Mode != "unknown" && b.Mode != "unknown" && a.Mode != "" && b.Mode != "" && a.Mode != b.Mode || lacpConflict(ev.LACPA, ev.LACPB) {
			tainted[ka], tainted[kb] = true, true
		}
	}
	for k, peers := range peerGroups {
		if len(peers) > 1 {
			tainted[k] = true
		}
	}
	type groupKey struct{ a, b lagInterfaceKey }
	groups := map[groupKey]int{}
	connections := []topologyConnection{}
	for _, link := range view.Links {
		_, visibleA := devices[link.DeviceAID]
		_, visibleB := devices[link.DeviceBID]
		if !visibleA || !visibleB || link.DeviceAID == link.DeviceBID || linkVerification(link, view.LatestScanID) != "confirmed" {
			continue
		}
		ev := linkEvidence[link.ID]
		a, independentA := lookup(link.DeviceAID, ev.A.IfIndex)
		b, independentB := lookup(link.DeviceBID, ev.B.IfIndex)
		weak := link.Confidence != "bidirectional"
		conflict := a != nil && (a.Status != "confirmed" || tainted[lagInterfaceKey{link.DeviceAID, a.AggregateIfIndex}]) || b != nil && (b.Status != "confirmed" || tainted[lagInterfaceKey{link.DeviceBID, b.AggregateIfIndex}]) || a != nil && independentB || b != nil && independentA
		advertised := false
		for _, ad := range ev.Advertisements {
			advertised = advertised || ad.Advertisement.Enabled
		}
		if a == nil || b == nil || conflict {
			status := "unknown"
			if a != nil || b != nil || advertised {
				status = "partial_lag"
			} else if independentA && independentB {
				status = "not_member"
			}
			if conflict || advertised && independentA && independentB {
				status = "conflict"
			}
			connections = append(connections, topologyConnection{members: []postgres.ExportLink{link}, aggregateA: a, aggregateB: b,
				status: status, mode: "unknown", coverage: "unknown", weak: weak})
			continue
		}
		key := groupKey{lagInterfaceKey{link.DeviceAID, a.AggregateIfIndex}, lagInterfaceKey{link.DeviceBID, b.AggregateIfIndex}}
		mode := a.Mode
		if mode != b.Mode {
			mode = "unknown"
		}
		if group, ok := groups[key]; ok {
			connection := &connections[group]
			connection.members = append(connection.members, link)
			connection.weak = connection.weak || weak
			if connection.mode != mode {
				connection.mode = "unknown"
			}
		} else {
			groups[key] = len(connections)
			connections = append(connections, topologyConnection{members: []postgres.ExportLink{link}, aggregateA: a, aggregateB: b,
				status: "confirmed", mode: mode, coverage: "unknown", weak: weak})
		}
	}
	for key, group := range groups {
		connection := &connections[group]
		slices.SortFunc(connection.members, func(a, b postgres.ExportLink) int { return compareID(a.ID, b.ID) })
		n := len(connection.members)
		if counts[key.a] > n || counts[key.b] > n {
			connection.coverage = "partial"
		} else if lagGroupComplete(key.a, complete, groupComplete) && lagGroupComplete(key.b, complete, groupComplete) {
			connection.coverage = "complete"
		}
	}
	slices.SortFunc(connections, func(a, b topologyConnection) int { return compareID(a.members[0].ID, b.members[0].ID) })
	return connections
}

func lagGroupComplete(k lagInterfaceKey, devices map[int64]bool, groups map[lagInterfaceKey]bool) bool {
	if v, ok := groups[k]; ok {
		return v
	}
	return devices[k.device]
}
func lacpConflict(a, b *model.LACPPort) bool {
	if a == nil || b == nil || !a.Stable || !b.Stable {
		return false
	}
	numeric := func(x, y *uint32) bool { return x != nil && y != nil && *x != 0 && *y != 0 && *x != *y }
	mac := func(x, y []byte) bool {
		return len(x) == 6 && len(y) == 6 && !bytes.Equal(x, make([]byte, 6)) && !bytes.Equal(y, make([]byte, 6)) && !bytes.Equal(x, y)
	}
	return numeric(a.ActorKey, b.PartnerKey) || numeric(b.ActorKey, a.PartnerKey) || numeric(a.ActorPort, b.PartnerPort) || numeric(b.ActorPort, a.PartnerPort) || mac(a.ActorSystem, b.PartnerSystem) || mac(b.ActorSystem, a.PartnerSystem)
}
