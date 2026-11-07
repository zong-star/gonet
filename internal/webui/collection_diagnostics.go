package webui

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"gonet/internal/control"
	"gonet/internal/store/postgres"
)

type collectionSummary struct {
	Scope              string         `json:"scope"`
	DeviceCounts       map[string]int `json:"device_counts"`
	RecordedOutcomes   map[string]int `json:"recorded_outcomes"`
	ReasonCounts       map[string]int `json:"reason_counts"`
	TerminationReasons []string       `json:"termination_reasons"`
	DetailsURL         string         `json:"details_url"`
}

func uniqueCodes(codes []string) []string {
	slices.Sort(codes)
	return slices.Compact(codes)
}

func deviceCoverageReasons(view *control.View, scan postgres.DeviceScanCoverage) []string {
	codes := []string{}
	switch scan.Outcome {
	case "failed":
		codes = append(codes, "device_collection_failed")
	case "unscanned":
		codes = append(codes, "device_unscanned")
	case "partial":
		codes = append(codes, "collection_incomplete")
	}
	if scan.AbsenceEligible {
		return codes
	}
	if scan.Outcome == "success" {
		codes = append(codes, "absence_evidence_unverified")
	}
	if scan.Components != nil {
		if !scan.SnapshotStable && scan.Outcome != "unscanned" && scan.Outcome != "failed" {
			codes = append(codes, "snapshot_stability_unverified")
		}
		for _, name := range []string{"system", "lldp_local", "lldp_rem", "if_mib", "snmp_view", "lldp_receive"} {
			if c, ok := scan.Components[name]; ok && (!c.Supported || !c.WalkComplete || !c.DecodeComplete || c.Skipped) {
				codes = append(codes, name+"_incomplete")
			}
		}
	}
	if view.Evidence != nil && view.Evidence.Collection != nil && !view.Evidence.Collection.ViewVerified {
		codes = append(codes, "snmp_view_unverified")
	}
	for _, issue := range scan.Issues {
		if issue.Code != "" {
			codes = append(codes, issue.Code)
		}
	}
	if len(codes) == 0 {
		codes = append(codes, "device_collection_evidence_unavailable")
	}
	return uniqueCodes(codes)
}

func collectionOverview(view *control.View) *collectionSummary {
	if view.Evidence == nil || view.Evidence.Collection == nil {
		return nil
	}
	result := &collectionSummary{Scope: "configured_discovery_run", DeviceCounts: map[string]int{}, RecordedOutcomes: map[string]int{"success": 0, "partial": 0, "failed": 0, "unscanned": 0, "not_recorded": 0}, ReasonCounts: map[string]int{},
		TerminationReasons: append([]string{}, view.Evidence.Collection.TerminationReasons...),
		DetailsURL:         "/api/v1/topology/collection?schema_version=2&snapshot_id=" + idString(view.LatestScanID)}
	// Run counters distinguish targets from identities. They are not an inventory denominator.
	for _, key := range []string{"devices_discovered", "devices_collected", "devices_failed", "devices_unscanned", "truncated_branches", "unresolved_observations"} {
		result.DeviceCounts[key] = view.Evidence.Collection.Counts[key]
	}
	for _, issue := range view.Evidence.Collection.Issues {
		if issue.Code != "" {
			result.ReasonCounts[issue.Code]++
		}
	}
	for _, device := range view.Devices {
		if scan, ok := view.Evidence.DeviceCoverage[device.ID]; ok {
			result.RecordedOutcomes[scan.Outcome]++
		} else {
			result.RecordedOutcomes["not_recorded"]++
		}
	}
	return result
}

// Evaluate all visible active branches reachable within the query bound. A core
// is terminal. Finding one path never supplies missing coverage evidence.
func deviceCoreCoverage(view *control.View, source int64, maxHops int, cores map[int64]bool) coverageV2 {
	result := coverageV2{Scope: "device_to_core_query", DeviceID: idString(source), Status: "covered", ReasonCodes: []string{},
		MaxHops: maxHops, Definition: "visible_active_branches_within_max_hops_core_terminal"}
	if view.LatestScanID == 0 {
		result.Status = "unknown"
		result.ReasonCodes = []string{"no_scan_data"}
		return result
	}
	if len(cores) == 0 {
		result.Status = "unknown"
		result.ReasonCodes = []string{"no_visible_core"}
		return result
	}
	devices := map[int64]bool{}
	for _, d := range view.Devices {
		devices[d.ID] = true
	}
	type step struct {
		id    int64
		depth int
	}
	queue := []step{{source, 0}}
	seen := map[int64]bool{source: true}
	adj := map[int64][]postgres.ExportLink{}
	for _, link := range view.Links {
		if link.DiscoveryState != "active" || !devices[link.DeviceAID] || !devices[link.DeviceBID] {
			continue
		}
		adj[link.DeviceAID] = append(adj[link.DeviceAID], link)
		adj[link.DeviceBID] = append(adj[link.DeviceBID], link)
	}
	affected := []int64{}
	for pos := 0; pos < len(queue); pos++ {
		node := queue[pos]
		coverage := deviceNeighborCoverage(view, node.id, "active")
		result.EvaluatedDeviceCount++
		if coverage.Status != "covered" {
			affected = append(affected, node.id)
			result.ReasonCodes = append(result.ReasonCodes, coverage.ReasonCodes...)
			if coverage.Status == "gap" || result.Status == "covered" {
				result.Status = coverage.Status
			}
		}
		if cores[node.id] || node.depth >= maxHops {
			continue
		}
		for _, link := range adj[node.id] {
			if link.LastSeenScanID == nil || *link.LastSeenScanID != view.LatestScanID {
				result.Status = "gap"
				result.ReasonCodes = append(result.ReasonCodes, "branch_link_not_observed_in_snapshot")
				affected = append(affected, node.id)
			}
			peer := link.DeviceAID
			if peer == node.id {
				peer = link.DeviceBID
			}
			if !seen[peer] {
				seen[peer] = true
				queue = append(queue, step{peer, node.depth + 1})
			}
		}
	}
	slices.Sort(affected)
	affected = slices.Compact(affected)
	result.AffectedDevicesTruncated = len(affected) > 10
	for _, id := range affected[:min(10, len(affected))] {
		result.AffectedDeviceIDs = append(result.AffectedDeviceIDs, idString(id))
	}
	result.ReasonCodes = uniqueCodes(result.ReasonCodes)
	return result
}

type collectionItem struct {
	Kind                 string     `json:"kind"`
	Key                  string     `json:"key"`
	DeviceID             *string    `json:"device_id"`
	Name                 string     `json:"name"`
	Addresses            []string   `json:"addresses"`
	Status               string     `json:"status"`
	CoverageStatus       string     `json:"coverage_status"`
	ReasonCodes          []string   `json:"reason_codes"`
	IncompleteComponents []string   `json:"incomplete_components"`
	CollectedAt          *time.Time `json:"collected_at"`
}

func collectionItems(view *control.View) []collectionItem {
	items := []collectionItem{}
	for _, device := range view.Devices {
		item := collectionItem{Kind: "device", Key: "device:" + idString(device.ID), DeviceID: nullableID(device.ID), Name: device.Name,
			Addresses: append([]string{}, device.AccessAddresses...), Status: "not_recorded", IncompleteComponents: []string{}}
		coverage := deviceNeighborCoverage(view, device.ID, "active")
		item.CoverageStatus, item.ReasonCodes = coverage.Status, coverage.ReasonCodes
		if view.Evidence != nil {
			if scan, ok := view.Evidence.DeviceCoverage[device.ID]; ok {
				item.Status, item.CollectedAt = scan.Outcome, scan.CollectedAt
				if scan.TargetIP != "" && !slices.Contains(item.Addresses, scan.TargetIP) {
					item.Addresses = append(item.Addresses, scan.TargetIP)
				}
				for name, component := range scan.Components {
					if !component.Skipped && (!component.Supported || !component.WalkComplete || !component.DecodeComplete) {
						item.IncompleteComponents = append(item.IncompleteComponents, name)
					}
				}
				slices.Sort(item.IncompleteComponents)
			}
		}
		items = append(items, item)
	}
	for _, candidate := range view.Candidates {
		addresses := []string{}
		for _, addr := range candidate.ManagementAddresses {
			addresses = append(addresses, addr.String())
		}
		codes := []string{"unresolved_observations"}
		if candidate.Verification.FailureCode != "" {
			codes = append(codes, candidate.Verification.FailureCode)
		}
		items = append(items, collectionItem{Kind: "neighbor_candidate", Key: candidate.Key, Name: candidate.Name, Addresses: addresses,
			Status: candidate.Verification.Status, CoverageStatus: "gap", ReasonCodes: uniqueCodes(codes), IncompleteComponents: []string{}})
	}
	if view.Evidence != nil && view.Evidence.Collection != nil {
		for _, target := range view.Evidence.Collection.Targets {
			// Formal device rows above already describe final per-identity results;
			// an address attempt may fail before another address succeeds.
			if target.DeviceID != 0 {
				continue
			}
			items = append(items, collectionItem{Kind: "target_attempt", Key: "target:" + target.Address, Addresses: []string{target.Address},
				Status: target.Status, CoverageStatus: "gap", ReasonCodes: []string{target.ReasonCode}, IncompleteComponents: []string{}})
		}
	}
	slices.SortFunc(items, func(a, b collectionItem) int {
		if a.Key < b.Key {
			return -1
		}
		if a.Key > b.Key {
			return 1
		}
		return 0
	})
	return items
}

type collectionQuery struct {
	limit    int
	cursor   string
	snapshot int64
	device   int64
}

func parseCollectionQuery(raw string) (collectionQuery, error) {
	q := collectionQuery{limit: 10}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return q, err
	}
	for key, values := range v {
		if len(values) != 1 || values[0] == "" {
			return q, errors.New("invalid collection query")
		}
		switch key {
		case "schema_version":
			if values[0] != "2" {
				return q, errors.New("invalid schema version")
			}
		case "cursor":
			q.cursor = values[0]
			if len(q.cursor) > 1024 {
				return q, errors.New("invalid cursor")
			}
		case "limit":
			q.limit, err = strconv.Atoi(values[0])
			if err != nil || q.limit < 1 || q.limit > 50 {
				return q, errors.New("invalid limit")
			}
		case "snapshot_id", "device_id":
			id, e := parseDeviceID(values[0], nil)
			if e != nil {
				return q, e
			}
			if key == "snapshot_id" {
				q.snapshot = id
			} else {
				q.device = id
			}
		default:
			return q, errors.New("unknown collection query")
		}
	}
	return q, nil
}

func (s *Server) writeCollection(w http.ResponseWriter, view *control.View, requestID string, q collectionQuery) {
	if q.snapshot != 0 && q.snapshot != view.LatestScanID {
		apiError(w, 409, "SNAPSHOT_CHANGED", "快照已变化，请从最新摘要重新查询")
		return
	}
	items := collectionItems(view)
	if q.device != 0 {
		items = slices.DeleteFunc(items, func(item collectionItem) bool { return item.DeviceID == nil || *item.DeviceID != idString(q.device) })
	}
	raw, _ := json.Marshal(struct {
		Scan   int64
		Limit  int
		Device int64
		Items  []collectionItem
	}{view.LatestScanID, q.limit, q.device, items})
	hash := sha256.Sum256(raw)
	fingerprint := hex.EncodeToString(hash[:])
	start := 0
	if q.cursor != "" {
		cursor, err := s.decodeNeighborCursor(q.cursor)
		if err != nil {
			apiError(w, 400, "INVALID_CURSOR", "采集明细游标无效")
			return
		}
		if cursor.Fingerprint != fingerprint {
			apiError(w, 409, "CURSOR_STALE", "快照或查询范围已变化，请重新查询")
			return
		}
		start = cursor.Offset
		if start >= len(items) {
			apiError(w, 400, "INVALID_CURSOR", "采集明细游标超出范围")
			return
		}
	}
	meta := compactMetadata(view, "all", requestID)
	data := struct {
		topologyV2
		Total      int              `json:"total"`
		Items      []collectionItem `json:"items"`
		HasMore    bool             `json:"has_more"`
		NextCursor *string          `json:"next_cursor"`
	}{topologyV2: topologyQuality(view, meta.GeneratedAt, s.topologyStaleAfter, networkCoverage(view)), Total: len(items), Items: items[start:min(start+q.limit, len(items))]}
	update := func() {
		data.HasMore = start+len(data.Items) < len(items)
		data.NextCursor = nil
		if data.HasMore {
			cursor := s.encodeNeighborCursor(neighborCursor{Fingerprint: fingerprint, Offset: start + len(data.Items)})
			data.NextCursor = &cursor
		}
	}
	update()
	writeTopologyResponse(w, apiResponse{Data: &data, Meta: meta}, maxCompactAPIBytes, func(_ *apiMeta) bool {
		if len(data.Items) <= 1 {
			return false
		}
		data.Items = data.Items[:len(data.Items)-1]
		update()
		return true
	})
}
