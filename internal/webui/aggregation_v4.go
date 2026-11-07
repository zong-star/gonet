package webui

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"gonet/internal/control"
	"gonet/internal/model"
	"gonet/internal/store/postgres"
	"gonet/internal/topology"
)

func visibleAggregationDevices(view *control.View) map[int64]control.Device {
	out := map[int64]control.Device{}
	for _, d := range view.Devices {
		if d.IdentityState != "conflict" {
			out[d.ID] = d
		}
	}
	return out
}

func topologyConnectionsV4(view *control.View, devices map[int64]control.Device) []topologyConnection {
	if view.Evidence == nil || view.LatestScanID == 0 {
		return topologyConnections(view, devices)
	}
	ds := []topology.AggregationDevice{}
	ms := []topology.AggregationMember{}
	ls := []topology.AggregationLink{}
	byLink := map[int64]postgres.ExportLink{}
	for id, d := range devices {
		ds = append(ds, topology.AggregationDevice{ID: id, SysObjectID: d.SysObjectID, ClassificationRule: d.ClassificationRule, Verified: d.IdentityState == "verified"})
		facts := view.Evidence.LAG[id]
		for _, m := range facts.Members {
			complete := facts.Complete
			for _, g := range facts.Groups {
				if g.AggregateIfIndex != nil && *g.AggregateIfIndex == m.AggregateIfIndex {
					complete = g.Complete
					break
				}
			}
			name := m.AggregateName
			if m.Endpoint.IfName != nil {
				name = *m.Endpoint.IfName
			} else if name == "" && m.Endpoint.Name != nil {
				name = *m.Endpoint.Name
			}
			ms = append(ms, topology.AggregationMember{DeviceID: id, LAGMember: m.LAGMember, Name: name, Complete: complete})
		}
	}
	for _, l := range view.Links {
		if _, ok := devices[l.DeviceAID]; !ok {
			continue
		}
		if _, ok := devices[l.DeviceBID]; !ok {
			continue
		}
		if linkVerification(l, view.LatestScanID) != "confirmed" {
			continue
		}
		ev := view.Evidence.Links[l.ID]
		x := topology.AggregationLink{ID: l.ID, DeviceA: l.DeviceAID, DeviceB: l.DeviceBID, PortA: l.PortAID, PortB: l.PortBID, ProtocolConflict: lacpConflict(ev.LACPA, ev.LACPB)}
		if ev.A.IfIndex != nil {
			x.IfA = *ev.A.IfIndex
		}
		if ev.B.IfIndex != nil {
			x.IfB = *ev.B.IfIndex
		}
		ls = append(ls, x)
		byLink[l.ID] = l
	}
	// Normalize input order before resolving any representative group metadata.
	slices.SortFunc(ms, func(a, b topology.AggregationMember) int {
		if a.DeviceID != b.DeviceID {
			return compareID(a.DeviceID, b.DeviceID)
		}
		return int(a.MemberIfIndex - b.MemberIfIndex)
	})
	derived := topology.BuildAggregationConnections(view.LatestScanID, ds, ms, ls)
	staleAfter := view.InferenceStaleAfter
	if staleAfter == 0 {
		staleAfter = 72 * time.Hour
	}
	stale := view.LatestScanFinishedAt == nil || time.Now().Before(*view.LatestScanFinishedAt) || time.Since(*view.LatestScanFinishedAt) >= staleAfter
	for i := range derived {
		c := &derived[i]
		for _, g := range []*model.AggregationGroup{c.GroupA, c.GroupB} {
			if g != nil && g.AggregationSource == "peer_inferred" {
				g.InferredAt = view.LatestScanFinishedAt
				if stale {
					g.InferenceStatus = "stale"
					if c.Status != "conflict" {
						c.Status = "partial"
						c.Reasons = append(c.Reasons, "PEER_INFERENCE_STALE")
					}
				}
			}
		}
	}
	out := []topologyConnection{}
	for _, d := range derived {
		c := topologyConnection{status: d.Status, mode: d.Mode, coverage: d.Coverage, groupA: d.GroupA, groupB: d.GroupB, reasons: d.Reasons}
		if c.status == "partial" {
			c.status = "partial_lag"
		}
		for _, id := range d.LinkIDs {
			l := byLink[id]
			c.members = append(c.members, l)
			c.weak = c.weak || l.Confidence != "bidirectional"
		}
		first := c.members[0]
		for _, side := range []struct {
			id    int64
			group *model.AggregationGroup
			dest  **postgres.LAGMemberEvidence
		}{{first.DeviceAID, c.groupA, &c.aggregateA}, {first.DeviceBID, c.groupB, &c.aggregateB}} {
			if side.group == nil || side.group.AggregateIfIndex == nil {
				continue
			}
			for _, m := range view.Evidence.LAG[side.id].Members {
				if m.AggregateIfIndex == *side.group.AggregateIfIndex {
					x := m
					*side.dest = &x
					break
				}
			}
		}
		out = append(out, c)
	}
	return out
}

func aggregationID(view *control.View, c topologyConnection) string {
	if c.groupA == nil || c.groupB == nil || (c.status != "confirmed" && c.status != "inferred") {
		return ""
	}
	keys := []string{c.groupA.GroupID, c.groupB.GroupID}
	slices.Sort(keys)
	return fmt.Sprintf("lag:%d:%s", view.LatestScanID, strings.Join(keys, ":"))
}

func projectGroupEndpoint(group *model.AggregationGroup) linkEndpoint {
	if group == nil {
		return linkEndpoint{IfIndexStatus: "unknown"}
	}
	out := linkEndpoint{DeviceID: idString(group.DeviceID), IfIndex: group.AggregateIfIndex, InterfaceName: group.InterfaceName, IfIndexStatus: "unknown", DisplayName: group.DisplayName}
	if out.IfIndex != nil {
		out.IfIndexStatus = "known"
	}
	if out.InterfaceName != nil {
		source := "if_name"
		out.InterfaceNameSource = &source
	}
	return out
}

func projectUplinkV4(view *control.View, c topologyConnection, from int64, hop int) uplinkEdgeV2 {
	// Use the existing physical/diagnostic projection, then attach the v4 groups.
	edge := projectUplinkV3(view, c, from, hop)
	state := aggregationState(c.status)
	if c.status == "inferred" {
		state = "inferred"
	}
	edge.AggregationStatus = state
	edge.Aggregation.Status = state
	edge.Aggregation.LocalGroupV4, edge.Aggregation.RemoteGroupV4 = c.groupA, c.groupB
	if c.members[0].DeviceAID != from {
		edge.Aggregation.LocalGroupV4, edge.Aggregation.RemoteGroupV4 = c.groupB, c.groupA
	}
	edge.Aggregation.ReasonCodes = append(edge.Aggregation.ReasonCodes, c.reasons...)
	slices.Sort(edge.Aggregation.ReasonCodes)
	edge.Aggregation.ReasonCodes = slices.Compact(edge.Aggregation.ReasonCodes)
	if c.status == "inferred" || c.status == "confirmed" {
		if c.status == "inferred" {
			edge.Aggregation.ReasonCodes = slices.DeleteFunc(edge.Aggregation.ReasonCodes, func(s string) bool { return s == "SOURCE_UNAVAILABLE" })
		}
		edge.Kind = "aggregate"
		edge.LinkID = nil
		edge.EdgeID = aggregationID(view, c)
		edge.Aggregation.AggregateID = edge.EdgeID
		edge.From = projectGroupEndpoint(edge.Aggregation.LocalGroupV4)
		edge.To = projectGroupEndpoint(edge.Aggregation.RemoteGroupV4)
		edge.Aggregation.MemberLinks = []uplinkMemberV2{}
		for _, l := range c.members {
			ev := view.Evidence.Links[l.ID]
			m := uplinkMemberV2{LinkID: idString(l.ID), MembershipStatus: state, From: projectLinkEndpoint(l.DeviceAID, ev.A), To: projectLinkEndpoint(l.DeviceBID, ev.B), linkStatusV2: physicalLinkStatus(l, view.LatestScanID), Observations: observationRefs(ev)}
			if l.DeviceAID != from {
				m.From, m.To = m.To, m.From
			}
			edge.Aggregation.MemberLinks = append(edge.Aggregation.MemberLinks, m)
		}
		edge.Aggregation.MemberDataStatus = "partial"
		if c.status == "confirmed" && c.coverage == "complete" && len(edge.Aggregation.UnpairedMembers) == 0 {
			edge.Aggregation.MemberDataStatus = "complete"
		}
		edge.Aggregation.KnownMemberLinkCount = len(c.members)
		edge.Aggregation.ReturnedMemberLinkCount = len(c.members)
	}
	for i := range edge.Aggregation.MemberLinks {
		for _, l := range c.members {
			if idString(l.ID) == edge.Aggregation.MemberLinks[i].LinkID {
				edge.Aggregation.MemberLinks[i].Observations = observationRefs(view.Evidence.Links[l.ID])
				break
			}
		}
	}
	aggregationOperStatus(&edge, c.members, view.LatestScanID)
	return edge
}

type neighborAggregationV4 struct {
	AggregateID          *string                 `json:"aggregate_id"`
	Status               string                  `json:"status"`
	Local                *model.AggregationGroup `json:"local_group"`
	Remote               *model.AggregationGroup `json:"remote_group"`
	KnownMemberLinkCount int                     `json:"known_member_link_count"`
}

type aggregationConnectionV4 struct {
	AggregateID   string                  `json:"aggregate_id"`
	Status        string                  `json:"status"`
	GroupA        *model.AggregationGroup `json:"group_a"`
	GroupB        *model.AggregationGroup `json:"group_b"`
	MemberLinkIDs []string                `json:"member_link_ids"`
}

func graphAggregationsV4(view *control.View) []aggregationConnectionV4 {
	out := []aggregationConnectionV4{}
	for _, c := range topologyConnectionsV4(view, visibleAggregationDevices(view)) {
		id := aggregationID(view, c)
		if id == "" {
			if c.groupA == nil && c.groupB == nil {
				continue
			}
			id = fmt.Sprintf("lag-diagnostic:%d:%d", view.LatestScanID, c.members[0].ID)
		}
		x := aggregationConnectionV4{AggregateID: id, Status: c.status, GroupA: c.groupA, GroupB: c.groupB, MemberLinkIDs: []string{}}
		for _, l := range c.members {
			x.MemberLinkIDs = append(x.MemberLinkIDs, idString(l.ID))
		}
		out = append(out, x)
	}
	return out
}

type topologyStateV4 struct {
	*control.View
	InferencePolicyVersion string                    `json:"inference_policy_version"`
	AggregateConnections   []aggregationConnectionV4 `json:"aggregate_connections"`
	Graph                  currentTopologyGraph      `json:"graph"`
}

// currentTopologyGraph is the sole input for the main, focus and mini canvases.
// The surrounding View deliberately retains historical list/detail data.
type currentTopologyGraph struct {
	SnapshotID             int64                     `json:"snapshot_id"`
	SnapshotStatus         string                    `json:"snapshot_status"`
	SnapshotFinishedAt     *time.Time                `json:"snapshot_finished_at"`
	LatestAttempt          *postgres.ScanState       `json:"latest_attempt"`
	DeviceIDs              []int64                   `json:"device_ids"`
	Links                  []postgres.ExportLink     `json:"links"`
	Candidates             []control.Candidate       `json:"neighbor_candidates"`
	AggregateConnections   []aggregationConnectionV4 `json:"aggregate_connections"`
	InferencePolicyVersion string                    `json:"inference_policy_version"`
	Coverage               coverageV2                `json:"coverage"`
}

func projectCurrentTopologyGraph(view *control.View) currentTopologyGraph {
	current := control.CurrentGraphView(view)
	graph := currentTopologyGraph{SnapshotID: view.LatestScanID, SnapshotStatus: view.LatestScanStatus,
		SnapshotFinishedAt: view.LatestScanFinishedAt, DeviceIDs: []int64{}, Links: current.Links,
		Candidates: current.Candidates, AggregateConnections: graphAggregationsV4(current),
		InferencePolicyVersion: topology.AggregationInferencePolicy, Coverage: networkCoverage(current)}
	for _, d := range current.Devices {
		graph.DeviceIDs = append(graph.DeviceIDs, d.ID)
	}
	if view.Evidence != nil {
		graph.LatestAttempt = view.Evidence.LatestScan
	}
	return graph
}
