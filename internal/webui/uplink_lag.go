package webui

import (
	"fmt"
	"gonet/internal/control"
	"gonet/internal/store/postgres"
	"slices"
)

type unpairedLAGMember struct {
	DeviceID string `json:"device_id"`
	IfIndex  int32  `json:"if_index"`
	Reason   string `json:"reason"`
}
type aggregationDiagnostics struct {
	LocalGroup       *linkEndpoint                       `json:"local_group"`
	RemoteGroup      *linkEndpoint                       `json:"remote_group"`
	MemberDataStatus string                              `json:"member_data_status"`
	MemberLinks      []uplinkMemberV2                    `json:"member_links"`
	UnpairedMembers  []unpairedLAGMember                 `json:"unpaired_members"`
	Advertisements   []postgres.LAGAdvertisementEvidence `json:"advertisements,omitempty"`
	ReasonCodes      []string                            `json:"reason_codes"`
}

func aggregationState(status string) string {
	switch status {
	case "confirmed":
		return "confirmed"
	case "partial_lag":
		return "partial"
	case "not_member":
		return "none"
	case "conflict":
		return "conflict"
	default:
		return "unknown"
	}
}

func connectionDiagnostics(view *control.View, c topologyConnection, from int64) *aggregationDiagnostics {
	d := &aggregationDiagnostics{MemberDataStatus: "partial", MemberLinks: []uplinkMemberV2{}, UnpairedMembers: []unpairedLAGMember{}, ReasonCodes: []string{}}
	first := c.members[0]
	a, b := c.aggregateA, c.aggregateB
	if a != nil {
		x := projectLinkEndpoint(first.DeviceAID, a.Endpoint)
		d.LocalGroup = &x
	}
	if b != nil {
		x := projectLinkEndpoint(first.DeviceBID, b.Endpoint)
		d.RemoteGroup = &x
	}
	if first.DeviceAID != from {
		d.LocalGroup, d.RemoteGroup = d.RemoteGroup, d.LocalGroup
	}
	membership := "confirmed"
	if a == nil {
		membership = "remote_only"
	}
	if b == nil {
		membership = "local_only"
	}
	if first.DeviceAID != from {
		if membership == "local_only" {
			membership = "remote_only"
		} else if membership == "remote_only" {
			membership = "local_only"
		}
	}
	state := aggregationState(c.status)
	if state == "unknown" {
		d.MemberDataStatus = "unknown"
		d.MemberLinks = nil
		d.ReasonCodes = append(d.ReasonCodes, "SOURCE_UNAVAILABLE")
	}
	if state == "partial" {
		d.ReasonCodes = append(d.ReasonCodes, "MEMBERSHIP_INCOMPLETE")
		if a == nil && b == nil {
			d.MemberDataStatus = "unknown"
			d.MemberLinks = nil
			d.ReasonCodes = append(d.ReasonCodes, "GROUP_INDEX_UNMAPPED")
		}
	}
	if state == "conflict" {
		membership = "conflict"
		d.ReasonCodes = append(d.ReasonCodes, "MEMBERSHIP_CONFLICT")
	}
	// List observed pairs related to a known endpoint group without promoting
	// one-sided membership into a confirmed logical connection.
	links := c.members
	if view.Evidence != nil && (a != nil || b != nil) && state != "confirmed" {
		links = nil
		for _, link := range view.Links {
			if link.DeviceAID != first.DeviceAID || link.DeviceBID != first.DeviceBID || linkVerification(link, view.LatestScanID) != "confirmed" {
				continue
			}
			ev := view.Evidence.Links[link.ID]
			belongs := func(device int64, index *int32, group *postgres.LAGMemberEvidence) bool {
				if group == nil || index == nil {
					return false
				}
				for _, m := range view.Evidence.LAG[device].Members {
					if m.MemberIfIndex == *index && m.AggregateIfIndex == group.AggregateIfIndex {
						return true
					}
				}
				return false
			}
			if belongs(link.DeviceAID, ev.A.IfIndex, a) || belongs(link.DeviceBID, ev.B.IfIndex, b) {
				links = append(links, link)
			}
		}
	}
	slices.SortFunc(links, func(a, b postgres.ExportLink) int { return compareID(a.ID, b.ID) })
	matched := map[lagInterfaceKey]bool{}
	for _, link := range links {
		var ev postgres.PhysicalLinkEvidence
		if view.Evidence != nil {
			ev = view.Evidence.Links[link.ID]
		}
		if ev.A.IfIndex != nil {
			matched[lagInterfaceKey{link.DeviceAID, *ev.A.IfIndex}] = true
		}
		if ev.B.IfIndex != nil {
			matched[lagInterfaceKey{link.DeviceBID, *ev.B.IfIndex}] = true
		}
		m := uplinkMemberV2{LinkID: idString(link.ID), MembershipStatus: membership, From: projectLinkEndpoint(link.DeviceAID, ev.A), To: projectLinkEndpoint(link.DeviceBID, ev.B), linkStatusV2: physicalLinkStatus(link, view.LatestScanID)}
		if link.DeviceAID != from {
			m.From, m.To = m.To, m.From
		}
		if d.MemberDataStatus != "unknown" {
			d.MemberLinks = append(d.MemberLinks, m)
		}
		d.Advertisements = append(d.Advertisements, ev.Advertisements...)
	}
	if view.Evidence != nil {
		for _, side := range []struct {
			id int64
			g  *postgres.LAGMemberEvidence
		}{{first.DeviceAID, a}, {first.DeviceBID, b}} {
			if side.g == nil {
				continue
			}
			for _, r := range view.Evidence.LAG[side.id].Members {
				if r.AggregateIfIndex == side.g.AggregateIfIndex && !matched[lagInterfaceKey{side.id, r.MemberIfIndex}] {
					d.UnpairedMembers = append(d.UnpairedMembers, unpairedLAGMember{idString(side.id), r.MemberIfIndex, "MEMBER_UNPAIRED"})
				}
			}
		}
	}
	if len(d.UnpairedMembers) > 0 {
		d.ReasonCodes = append(d.ReasonCodes, "MEMBER_UNPAIRED")
	}
	if state == "confirmed" && c.coverage == "complete" && len(d.UnpairedMembers) == 0 {
		d.MemberDataStatus = "complete"
	}
	if state == "none" {
		d.MemberDataStatus = "complete"
		d.MemberLinks = []uplinkMemberV2{}
	}
	return d
}

func projectUplinkV3(view *control.View, c topologyConnection, from int64, hop int) uplinkEdgeV2 {
	if c.mode != "static" && c.mode != "lacp" {
		c.mode = "unknown"
	}
	edge := projectUplinkEdge(view, c, from, hop)
	d := connectionDiagnostics(view, c, from)
	a := &aggregationV2{Status: edge.AggregationStatus, Mode: c.mode, MemberDataStatus: d.MemberDataStatus, MemberLinks: d.MemberLinks, LocalGroup: d.LocalGroup, RemoteGroup: d.RemoteGroup, UnpairedMembers: d.UnpairedMembers, ReasonCodes: d.ReasonCodes, KnownMemberLinkCount: len(d.MemberLinks), ReturnedMemberLinkCount: len(d.MemberLinks)}
	a.Advertisements = d.Advertisements
	if edge.Kind == "aggregate" {
		a.AggregateID = fmt.Sprintf("aggregate:%d:%d:%d:%d:%d", view.LatestScanID, c.members[0].DeviceAID, c.aggregateA.AggregateIfIndex, c.members[0].DeviceBID, c.aggregateB.AggregateIfIndex)
		edge.EdgeID = a.AggregateID
	}
	edge.Aggregation = a
	edge.AggregationDiagnostics = nil
	return edge
}
