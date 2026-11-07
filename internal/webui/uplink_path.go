package webui

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"time"

	"gonet/internal/control"
	"gonet/internal/model"
	"gonet/internal/store/postgres"
	"gonet/internal/topology"
)

type corePathQuery struct {
	version           int
	maxPaths, maxHops int
	candidates        bool
}

type pathNode struct {
	DeviceID     string  `json:"device_id"`
	Name         string  `json:"name"`
	ManagementIP *string `json:"management_ip"`
	DeviceKind   string  `json:"device_kind"`
	Role         string  `json:"role,omitempty"`
}

type pathEndpoint struct {
	DeviceID         string        `json:"device_id"`
	Interface        *apiInterface `json:"interface,omitempty"`
	LogicalInterface *apiInterface `json:"logical_interface,omitempty"`
}

type pathMember struct {
	LinkID             string     `json:"link_id"`
	AInterface         string     `json:"a_interface"`
	BInterface         string     `json:"b_interface"`
	AIfIndex           *int32     `json:"a_if_index,omitempty"`
	BIfIndex           *int32     `json:"b_if_index,omitempty"`
	Confidence         string     `json:"confidence,omitempty"`
	VerificationStatus string     `json:"verification_status"`
	ScanID             *string    `json:"scan_id"`
	FirstSeenAt        *time.Time `json:"first_seen_at"`
	LastSeenAt         *time.Time `json:"last_seen_at"`
}

type pathHop struct {
	ConnectionID       string       `json:"connection_id,omitempty"`
	ConnectionType     string       `json:"connection_type"`
	VerificationStatus string       `json:"verification_status"`
	Confidence         string       `json:"confidence"`
	DiscoverySource    string       `json:"discovery_source"`
	LAGStatus          string       `json:"lag_status"`
	LAGMode            string       `json:"lag_mode,omitempty"`
	MemberCoverage     string       `json:"member_coverage,omitempty"`
	EndpointA          pathEndpoint `json:"endpoint_a"`
	EndpointB          pathEndpoint `json:"endpoint_b"`
	MemberLinks        []pathMember `json:"member_links"`
}

type pathDTO struct {
	PathID   string     `json:"path_id"`
	HopCount int        `json:"hop_count"`
	Nodes    []pathNode `json:"nodes"`
	Links    []pathHop  `json:"links"`
}

type candidateIdentifier struct {
	Subtype uint8  `json:"subtype"`
	Raw     []byte `json:"raw"`
}

type candidateLinkDTO struct {
	ObservationID      *string              `json:"observation_id"`
	ScanID             *string              `json:"scan_id"`
	ObserverID         string               `json:"observer_device_id"`
	LocalPortNumber    uint32               `json:"local_lldp_port_number"`
	RemoteDeviceID     *string              `json:"remote_device_id"`
	RemoteManagementIP *string              `json:"remote_management_ip"`
	RemoteChassisID    *candidateIdentifier `json:"remote_chassis_id"`
	RemotePortID       *candidateIdentifier `json:"remote_port_id"`
	ObservedAt         *time.Time           `json:"observed_at"`
	ReasonCodes        []string             `json:"reason_codes"`
	VerificationStatus string               `json:"verification_status"`
	DiscoverySource    string               `json:"discovery_source"`
}

type corePathData struct {
	SourceDevice   pathNode            `json:"source_device"`
	PathFound      bool                `json:"path_found"`
	Paths          []pathDTO           `json:"paths"`
	Reason         string              `json:"reason,omitempty"`
	CandidateLinks *[]candidateLinkDTO `json:"candidate_links,omitempty"`
}

func parseCorePathQuery(raw string) (corePathQuery, error) {
	query := corePathQuery{maxPaths: 3, maxHops: 16}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return query, err
	}
	for key, list := range values {
		if len(list) != 1 || list[0] == "" {
			return query, errors.New("duplicate or empty parameter")
		}
		switch key {
		case "target":
			if list[0] != "core" {
				return query, errors.New("invalid target")
			}
		case "max_paths":
			query.maxPaths, err = parseAPILimit(list[0], 3)
		case "max_hops":
			query.maxHops, err = parseAPILimit(list[0], 16)
		case "include_unverified":
			if list[0] != "true" && list[0] != "false" {
				return query, errors.New("invalid include_unverified")
			}
			query.candidates = list[0] == "true"
		default:
			return query, errors.New("unknown parameter")
		}
		if err != nil {
			return query, err
		}
	}
	return query, nil
}

func writeCorePaths(ctx context.Context, w http.ResponseWriter, view *control.View, sourceID int64, requestID string, query corePathQuery) {
	devices := make(map[int64]control.Device, len(view.Devices))
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
		if _, visible := devices[id]; visible {
			cores[id] = true
		}
	}
	data := corePathData{SourceDevice: makePathNode(source, cores[sourceID]), Paths: []pathDTO{}}
	meta := compactMetadata(view, "active", requestID)
	truncated := false
	meta.SearchTruncated = &truncated
	switch {
	case view.LatestScanID == 0:
		data.Reason = "no_scan_data"
	case len(cores) == 0:
		data.Reason = "no_visible_core"
	default:
		connections := topologyConnections(view, devices)
		edges := make([]topology.PathEdge, 0, len(connections))
		byID := make(map[int64]topologyConnection, len(connections))
		for _, connection := range connections {
			first := connection.members[0]
			edges = append(edges, topology.PathEdge{ID: first.ID, A: first.DeviceAID, B: first.DeviceBID, Weak: connection.weak})
			byID[first.ID] = connection
		}
		paths, limitReached, err := topology.FindCorePaths(ctx, edges, cores, sourceID, query.maxPaths, query.maxHops)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				apiError(w, 504, "READ_TIMEOUT", "读取拓扑数据超时")
			}
			return
		}
		truncated = limitReached
		for _, path := range paths {
			digest := sha256.New()
			fmt.Fprintf(digest, "%d:%d", view.LatestScanID, sourceID)
			result := pathDTO{Nodes: []pathNode{}, Links: []pathHop{}, HopCount: len(path.Edges)}
			for _, id := range path.Nodes {
				result.Nodes = append(result.Nodes, makePathNode(devices[id], cores[id]))
			}
			for i, edge := range path.Edges {
				fmt.Fprintf(digest, ":%d", edge)
				result.Links = append(result.Links, projectPathHop(view.Evidence, byID[edge], path.Nodes[i]))
			}
			result.PathID = hex.EncodeToString(digest.Sum(nil)[:12])
			data.Paths = append(data.Paths, result)
		}
		data.PathFound = len(data.Paths) > 0
		if !data.PathFound {
			data.Reason = "no_confirmed_path_to_core"
			if truncated {
				data.Reason = "search_budget_exceeded"
			}
		}
	}
	if query.candidates {
		candidates, limited := pathCandidates(view, devices, data)
		data.CandidateLinks, meta.CandidatesTruncated = &candidates, limited
	}
	writeTopologyResponse(w, apiResponse{Data: &data, Meta: meta}, maxCompactAPIBytes, func(meta *apiMeta) bool {
		if data.CandidateLinks != nil && len(*data.CandidateLinks) > 0 {
			*data.CandidateLinks = (*data.CandidateLinks)[:len(*data.CandidateLinks)-1]
			meta.CandidatesTruncated = true
			return true
		}
		if len(data.Paths) > 1 {
			data.Paths = data.Paths[:len(data.Paths)-1]
			return true
		}
		return false
	})
}

func makePathNode(device control.Device, core bool) pathNode {
	out := pathNode{DeviceID: idString(device.ID), Name: device.Name, ManagementIP: managementIP(device.AccessAddresses), DeviceKind: device.Kind}
	if core {
		out.Role = "core"
	}
	return out
}

func projectPathHop(evidence *postgres.TopologyEvidence, connection topologyConnection, from int64) pathHop {
	first := connection.members[0]
	result := pathHop{ConnectionType: "physical", VerificationStatus: "confirmed", Confidence: "bidirectional",
		DiscoverySource: "lldp", LAGStatus: connection.status,
		EndpointA:   pathEndpoint{DeviceID: idString(first.DeviceAID), LogicalInterface: aggregateInterface(connection.aggregateA)},
		EndpointB:   pathEndpoint{DeviceID: idString(first.DeviceBID), LogicalInterface: aggregateInterface(connection.aggregateB)},
		MemberLinks: make([]pathMember, 0, len(connection.members))}
	if connection.weak {
		result.Confidence = "single_sided"
	}
	if connection.status == "confirmed" && connection.aggregateA != nil && connection.aggregateB != nil {
		result.ConnectionType = "lag"
		result.ConnectionID = fmt.Sprintf("lag:%d:%d:%d:%d", first.DeviceAID, connection.aggregateA.AggregateIfIndex, first.DeviceBID, connection.aggregateB.AggregateIfIndex)
		result.LAGMode, result.MemberCoverage = connection.mode, connection.coverage
	}
	reverse := first.DeviceAID != from
	if reverse {
		result.EndpointA, result.EndpointB = result.EndpointB, result.EndpointA
	}
	for _, link := range connection.members {
		var facts postgres.PhysicalLinkEvidence
		if evidence != nil {
			facts = evidence.Links[link.ID]
		}
		a := physicalInterface(link.PortAID, link.PortAName, facts.A)
		b := physicalInterface(link.PortBID, link.PortBName, facts.B)
		if reverse {
			a, b = b, a
		}
		member := pathMember{LinkID: idString(link.ID), AInterface: a.Name, BInterface: b.Name, VerificationStatus: "confirmed",
			ScanID: linkScanID(link), FirstSeenAt: normalizedTime(link.FirstSeenAt), LastSeenAt: normalizedTime(link.LastSeenAt)}
		if result.ConnectionType == "physical" {
			// Path member IDs identify links. The oriented interfaces need only
			// their names and per-scan IfIndex here.
			a.PortID, b.PortID = nil, nil
			result.EndpointA.Interface, result.EndpointB.Interface = &a, &b
		} else {
			member.AIfIndex, member.BIfIndex, member.Confidence = a.IfIndex, b.IfIndex, link.Confidence
		}
		result.MemberLinks = append(result.MemberLinks, member)
	}
	return result
}

func aggregateInterface(member *postgres.LAGMemberEvidence) *apiInterface {
	if member == nil {
		return nil
	}
	return &apiInterface{Name: member.AggregateName, Kind: "aggregate", IfIndex: &member.AggregateIfIndex}
}

func pathCandidates(view *control.View, devices map[int64]control.Device, data corePathData) ([]candidateLinkDTO, bool) {
	allowed := map[string]bool{data.SourceDevice.DeviceID: true}
	for _, path := range data.Paths {
		for _, node := range path.Nodes {
			allowed[node.DeviceID] = true
		}
	}
	var candidates []topology.PendingLink
	if view.LatestScanID != 0 {
		for _, candidate := range view.CandidateLinks {
			_, remoteVisible := devices[int64(candidate.RemoteDevice)]
			if allowed[idString(int64(candidate.LocalDevice))] && (candidate.RemoteDevice == 0 || remoteVisible) {
				candidates = append(candidates, candidate)
			}
		}
	}
	slices.SortFunc(candidates, func(a, b topology.PendingLink) int {
		if a.LocalDevice != b.LocalDevice {
			return compareID(int64(a.LocalDevice), int64(b.LocalDevice))
		}
		if a.LocalPortNum != b.LocalPortNum {
			return compareID(int64(a.LocalPortNum), int64(b.LocalPortNum))
		}
		return compareID(a.ObservationID, b.ObservationID)
	})
	items := make([]candidateLinkDTO, 0, min(20, len(candidates)))
	for _, candidate := range candidates[:min(20, len(candidates))] {
		status := "pending"
		if candidate.Conflict || candidate.Status == "identity_conflict" {
			status = "unknown"
		}
		port := candidate.RemotePort
		if candidate.OriginalPort != nil {
			port = *candidate.OriginalPort
		}
		items = append(items, candidateLinkDTO{ObservationID: nullableID(candidate.ObservationID), ScanID: nullableID(view.LatestScanID),
			ObserverID: idString(int64(candidate.LocalDevice)), LocalPortNumber: candidate.LocalPortNum,
			RemoteDeviceID: nullableID(int64(candidate.RemoteDevice)), RemoteManagementIP: managementIP(devices[int64(candidate.RemoteDevice)].AccessAddresses),
			RemoteChassisID: rawCandidateID(candidate.Chassis), RemotePortID: rawCandidateID(port), ObservedAt: normalizedTime(candidate.ObservedAt),
			ReasonCodes: append([]string{}, candidate.ReasonCodes...), VerificationStatus: status, DiscoverySource: "lldp"})
	}
	return items, len(candidates) > 20
}

func rawCandidateID(id model.TypedID) *candidateIdentifier {
	if id.Subtype == 0 || len(id.Raw) == 0 {
		return nil
	}
	return &candidateIdentifier{Subtype: id.Subtype, Raw: id.Raw}
}
