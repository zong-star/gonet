package webui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"gonet/internal/control"
	"gonet/internal/model"
	"gonet/internal/store/postgres"
	"gonet/internal/topology"
)

type uplinkNodeV2 struct {
	DeviceID    string  `json:"device_id"`
	DisplayName *string `json:"display_name"`
	Role        string  `json:"role"`
}

type uplinkMemberV2 struct {
	Observations     []apiObservationRef `json:"observations,omitempty"`
	MembershipStatus string              `json:"membership_status,omitempty"`
	LinkID           string              `json:"link_id"`
	From             linkEndpoint        `json:"from"`
	To               linkEndpoint        `json:"to"`
	linkStatusV2
}

type aggregationV2 struct {
	LocalGroupV4, RemoteGroupV4 *model.AggregationGroup             `json:"-"`
	Advertisements              []postgres.LAGAdvertisementEvidence `json:"advertisements,omitempty"`
	Status                      string                              `json:"status,omitempty"`
	Mode                        string                              `json:"mode,omitempty"`
	LocalGroup                  *linkEndpoint                       `json:"local_group,omitempty"`
	RemoteGroup                 *linkEndpoint                       `json:"remote_group,omitempty"`
	KnownMemberLinkCount        int                                 `json:"known_member_link_count,omitempty"`
	ReturnedMemberLinkCount     int                                 `json:"returned_member_link_count,omitempty"`
	UnpairedMembers             []unpairedLAGMember                 `json:"unpaired_members,omitempty"`
	ReasonCodes                 []string                            `json:"reason_codes,omitempty"`
	AggregateID                 string                              `json:"aggregate_id"`
	MemberDataStatus            string                              `json:"member_data_status"`
	MemberLinks                 []uplinkMemberV2                    `json:"member_links"`
}

type uplinkEdgeV2 struct {
	AggregationStatus      string                  `json:"aggregation_status"`
	AggregationDiagnostics *aggregationDiagnostics `json:"aggregation_diagnostics,omitempty"`
	EdgeID                 string                  `json:"edge_id"`
	LinkID                 *string                 `json:"link_id"`
	Hop                    int                     `json:"hop"`
	Kind                   string                  `json:"kind"`
	From                   linkEndpoint            `json:"from"`
	To                     linkEndpoint            `json:"to"`
	linkStatusV2
	Aggregation *aggregationV2 `json:"aggregation"`
}

type uplinkPathV2 struct {
	TargetCoreDeviceID string         `json:"target_core_device_id"`
	HopCount           int            `json:"hop_count"`
	Nodes              []uplinkNodeV2 `json:"nodes"`
	Edges              []uplinkEdgeV2 `json:"edges"`
}

type uplinkDataV2 struct {
	topologyV2
	SourceDeviceID       string              `json:"source_device_id"`
	Target               string              `json:"target"`
	MaxHops              int                 `json:"max_hops"`
	PathStatus           string              `json:"path_status"`
	Path                 *uplinkPathV2       `json:"path"`
	Reason               string              `json:"reason,omitempty"`
	CandidateLinks       *[]candidateLinkDTO `json:"candidate_links,omitempty"`
	CandidateObserverIDs []string            `json:"candidate_observer_device_ids,omitempty"`
	CandidateDataReason  string              `json:"candidate_data_reason,omitempty"`
}

func (s *Server) writeUplinkV2(ctx context.Context, w http.ResponseWriter, view *control.View, sourceID int64, requestID string, query corePathQuery) {
	devices := map[int64]control.Device{}
	for _, device := range view.Devices {
		devices[device.ID] = device
	}
	source, visible := devices[sourceID]
	if !visible {
		apiError(w, 404, "DEVICE_NOT_FOUND", "设备不存在或不在可见范围内")
		return
	}
	cores := map[int64]bool{}
	for _, id := range view.CoreIDs {
		if device, ok := devices[id]; ok && device.IdentityState != "conflict" {
			cores[id] = true
		}
	}
	meta := compactMetadata(view, "active", requestID)
	data := uplinkDataV2{SourceDeviceID: idString(sourceID), Target: "core", MaxHops: query.maxHops, PathStatus: "not_found"}
	switch {
	case cores[sourceID]:
		name := source.Name
		data.PathStatus = "found"
		data.Path = &uplinkPathV2{TargetCoreDeviceID: idString(sourceID), Nodes: []uplinkNodeV2{{idString(sourceID), &name, "source_core"}}, Edges: []uplinkEdgeV2{}}
	case len(cores) == 0:
		data.Reason = "no_visible_core"
		if len(s.backend.Settings().Seeds) == 0 {
			data.PathStatus, data.Reason = "no_core_configured", "no_core_configured"
		}
	case view.LatestScanID == 0:
		data.Reason = "no_scan_data"
	default:
		eligible := make(map[int64]control.Device, len(devices))
		for id, device := range devices {
			if device.IdentityState != "conflict" {
				eligible[id] = device
			}
		}
		connections := topologyConnections(view, eligible)
		if query.version == 4 {
			connections = topologyConnectionsV4(view, eligible)
		}
		edges := make([]topology.PathEdge, 0, len(connections))
		byID := map[int64]topologyConnection{}
		for _, connection := range connections {
			first := connection.members[0]
			edges = append(edges, topology.PathEdge{ID: first.ID, A: first.DeviceAID, B: first.DeviceBID, Weak: connection.weak})
			byID[first.ID] = connection
		}
		paths, truncated, err := topology.FindCorePaths(ctx, edges, cores, sourceID, 1, query.maxHops)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				apiError(w, 504, "READ_TIMEOUT", "读取拓扑数据超时")
			}
			return
		}
		if truncated {
			apiError(w, 422, "SEARCH_BUDGET_EXCEEDED", "路径搜索超出预算，无法确定路径")
			return
		}
		data.Reason = "no_confirmed_path_within_bound"
		if len(paths) > 0 {
			selected := paths[0]
			data.Path = &uplinkPathV2{TargetCoreDeviceID: idString(selected.Nodes[len(selected.Nodes)-1]), HopCount: len(selected.Edges), Nodes: []uplinkNodeV2{}, Edges: []uplinkEdgeV2{}}
			for i, id := range selected.Nodes {
				name, role := devices[id].Name, "transit"
				if i == 0 {
					role = "source"
				} else if i == len(selected.Nodes)-1 {
					role = "core"
				}
				data.Path.Nodes = append(data.Path.Nodes, uplinkNodeV2{idString(id), &name, role})
			}
			for i, edgeID := range selected.Edges {
				edge := projectUplinkEdge(view, byID[edgeID], selected.Nodes[i], i+1)
				if query.version == 3 {
					edge = projectUplinkV3(view, byID[edgeID], selected.Nodes[i], i+1)
				}
				if query.version == 4 {
					edge = projectUplinkV4(view, byID[edgeID], selected.Nodes[i], i+1)
				}
				data.Path.Edges = append(data.Path.Edges, edge)
			}
			data.PathStatus, data.Reason = "found", ""
		}
	}
	if data.Path != nil && !validUplinkPath(data.Path, data.SourceDeviceID) {
		apiError(w, 500, "INTERNAL_ERROR", "无法生成有效的上联路径")
		return
	}
	coverage := deviceCoreCoverage(view, sourceID, query.maxHops, cores)
	data.topologyV2 = topologyQuality(view, meta.GeneratedAt, s.topologyStaleAfter, networkCoverage(view), coverage)
	if query.version >= 3 {
		data.SchemaVersion = query.version
	}
	if query.version == 4 {
		data.InferencePolicyVersion = topology.AggregationInferencePolicy
	}
	if query.candidates {
		legacy := corePathData{SourceDevice: pathNode{DeviceID: data.SourceDeviceID}}
		data.CandidateObserverIDs = []string{data.SourceDeviceID}
		if data.Path != nil {
			path := pathDTO{Nodes: []pathNode{}}
			for _, node := range data.Path.Nodes {
				path.Nodes = append(path.Nodes, pathNode{DeviceID: node.DeviceID})
				data.CandidateObserverIDs = append(data.CandidateObserverIDs, node.DeviceID)
			}
			legacy.Paths = []pathDTO{path}
		}
		slices.Sort(data.CandidateObserverIDs)
		data.CandidateObserverIDs = slices.Compact(data.CandidateObserverIDs)
		var candidates []candidateLinkDTO
		if view.LatestScanID == 0 || view.Evidence == nil {
			data.CandidateDataReason = "candidate_data_unavailable"
		} else {
			candidates, meta.CandidatesTruncated = pathCandidates(view, devices, legacy)
		}
		data.CandidateLinks = &candidates
	}
	writeTopologyResponse(w, apiResponse{Data: &data, Meta: meta}, maxCompactAPIBytes, func(meta *apiMeta) bool {
		if data.CandidateLinks == nil || len(*data.CandidateLinks) == 0 {
			return false
		}
		candidates := *data.CandidateLinks
		candidates = candidates[:len(candidates)-1]
		if len(candidates) == 0 {
			candidates, data.CandidateDataReason = nil, "response_budget_exceeded"
		}
		data.CandidateLinks, meta.CandidatesTruncated = &candidates, true
		return true
	})
}

func projectUplinkEdge(view *control.View, connection topologyConnection, from int64, hop int) uplinkEdgeV2 {
	first := connection.members[0]
	edge := uplinkEdgeV2{AggregationStatus: aggregationState(connection.status), EdgeID: "physical:" + idString(first.ID), LinkID: nullableID(first.ID), Hop: hop, Kind: "physical",
		linkStatusV2: physicalLinkStatus(first, view.LatestScanID)}
	var facts postgres.PhysicalLinkEvidence
	if view.Evidence != nil {
		facts = view.Evidence.Links[first.ID]
	}
	edge.From, edge.To = projectLinkEndpoint(first.DeviceAID, facts.A), projectLinkEndpoint(first.DeviceBID, facts.B)
	if connection.status == "confirmed" && connection.aggregateA != nil && connection.aggregateB != nil {
		a, b := connection.aggregateA, connection.aggregateB
		edge.EdgeID = fmt.Sprintf("aggregate:%d:%d:%d:%d", first.DeviceAID, a.AggregateIfIndex, first.DeviceBID, b.AggregateIfIndex)
		edge.Kind, edge.LinkID = "aggregate", nil
		edge.From, edge.To = projectLinkEndpoint(first.DeviceAID, a.Endpoint), projectLinkEndpoint(first.DeviceBID, b.Endpoint)
		edge.Aggregation = &aggregationV2{AggregateID: edge.EdgeID, MemberDataStatus: connection.coverage, MemberLinks: []uplinkMemberV2{}}
		// Confirmed known members with unproven total coverage are a partial list.
		if edge.Aggregation.MemberDataStatus != "complete" {
			edge.Aggregation.MemberDataStatus = "partial"
		}
		for _, link := range connection.members {
			var memberFacts postgres.PhysicalLinkEvidence
			if view.Evidence != nil {
				memberFacts = view.Evidence.Links[link.ID]
			}
			member := uplinkMemberV2{LinkID: idString(link.ID), From: projectLinkEndpoint(link.DeviceAID, memberFacts.A), To: projectLinkEndpoint(link.DeviceBID, memberFacts.B),
				linkStatusV2: physicalLinkStatus(link, view.LatestScanID)}
			if link.DeviceAID != from {
				member.From, member.To = member.To, member.From
			}
			edge.Aggregation.MemberLinks = append(edge.Aggregation.MemberLinks, member)
		}
	}
	if first.DeviceAID != from {
		edge.From, edge.To = edge.To, edge.From
	}
	if edge.AggregationStatus == "partial" || edge.AggregationStatus == "conflict" {
		edge.AggregationDiagnostics = connectionDiagnostics(view, connection, from)
	}
	aggregationOperStatus(&edge, connection.members, view.LatestScanID)
	return edge
}

func validUplinkPath(path *uplinkPathV2, source string) bool {
	if path == nil || len(path.Nodes) == 0 || path.HopCount != len(path.Edges) || len(path.Nodes) != len(path.Edges)+1 ||
		path.Nodes[0].DeviceID != source || path.Nodes[len(path.Nodes)-1].DeviceID != path.TargetCoreDeviceID {
		return false
	}
	nodes, edges := map[string]bool{}, map[string]bool{}
	for i, node := range path.Nodes {
		if node.DeviceID == "" || nodes[node.DeviceID] {
			return false
		}
		role := "transit"
		switch {
		case len(path.Nodes) == 1:
			role = "source_core"
		case i == 0:
			role = "source"
		case i == len(path.Nodes)-1:
			role = "core"
		}
		if node.Role != role {
			return false
		}
		nodes[node.DeviceID] = true
	}
	for i, edge := range path.Edges {
		if edge.EdgeID == "" || edges[edge.EdgeID] || edge.Hop != i+1 || edge.From.DeviceID != path.Nodes[i].DeviceID ||
			edge.To.DeviceID != path.Nodes[i+1].DeviceID || edge.VerificationStatus != "confirmed" || edge.TopologyStatus != "active" {
			return false
		}
		edges[edge.EdgeID] = true
		switch edge.Kind {
		case "physical":
			if edge.LinkID == nil || *edge.LinkID == "" || edge.Aggregation != nil && (edge.Aggregation.Status == "" || edge.Aggregation.Status == "confirmed" || edge.Aggregation.AggregateID != "") {
				return false
			}
		case "aggregate":
			if edge.Aggregation == nil || edge.Aggregation.AggregateID == "" {
				return false
			}
			members := map[string]bool{}
			for _, member := range edge.Aggregation.MemberLinks {
				if member.LinkID == "" || members[member.LinkID] || member.From.DeviceID != edge.From.DeviceID || member.To.DeviceID != edge.To.DeviceID {
					return false
				}
				members[member.LinkID] = true
			}
		default:
			return false
		}
	}
	return true
}

// v2 keeps its original null/string contract; v3 explicitly distinguishes an
// unknown aggregate identity from a confirmed logical edge.
func (a aggregationV2) MarshalJSON() ([]byte, error) {
	type plain aggregationV2
	if a.Status == "" {
		return json.Marshal(plain(a))
	}
	var local, remote any = a.LocalGroup, a.RemoteGroup
	if a.LocalGroupV4 != nil {
		local = a.LocalGroupV4
	}
	if a.RemoteGroupV4 != nil {
		remote = a.RemoteGroupV4
	}
	return json.Marshal(struct {
		plain
		AggregateID *string             `json:"aggregate_id"`
		Local       any                 `json:"local_group"`
		Remote      any                 `json:"remote_group"`
		Unpaired    []unpairedLAGMember `json:"unpaired_members"`
		Known       int                 `json:"known_member_link_count"`
		Returned    int                 `json:"returned_member_link_count"`
	}{plain(a), nullableString(a.AggregateID), local, remote, a.UnpairedMembers, a.KnownMemberLinkCount, a.ReturnedMemberLinkCount})
}
func nullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
