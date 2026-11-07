package webui

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"gonet/internal/control"
	"gonet/internal/model"
	"gonet/internal/store/postgres"
)

const defaultTopologyStaleAfter = 72 * time.Hour

type scanStateV2 struct {
	ScanID string `json:"scan_id"`
	Status string `json:"status"`
}

type coverageV2 struct {
	Scope                    string   `json:"scope"`
	Status                   string   `json:"status"`
	ReasonCodes              []string `json:"reason_codes"`
	DeviceID                 string   `json:"device_id,omitempty"`
	State                    string   `json:"state,omitempty"`
	EvaluatedDeviceCount     int      `json:"evaluated_device_count,omitempty"`
	AffectedDeviceIDs        []string `json:"affected_device_ids,omitempty"`
	AffectedDevicesTruncated bool     `json:"affected_devices_truncated,omitempty"`
	MaxHops                  int      `json:"max_hops,omitempty"`
	Definition               string   `json:"definition,omitempty"`
}

type dataQualityV2 struct {
	SnapshotStatus    string             `json:"snapshot_status"`
	Collection        *collectionSummary `json:"collection,omitempty"`
	SnapshotID        *string            `json:"snapshot_id"`
	SnapshotAt        *time.Time         `json:"snapshot_at"`
	AsOf              time.Time          `json:"as_of"`
	DataAgeSeconds    *int64             `json:"data_age_seconds"`
	LatestScan        *scanStateV2       `json:"latest_scan"`
	StaleAfterSeconds int64              `json:"stale_after_seconds"`
	Stale             *bool              `json:"stale"`
	Coverage          []coverageV2       `json:"coverage"`
	DiagnosticCodes   []string           `json:"diagnostic_codes,omitempty"`
}

type topologyV2 struct {
	InferencePolicyVersion string        `json:"inference_policy_version,omitempty"`
	SchemaVersion          int           `json:"schema_version"`
	DataQuality            dataQualityV2 `json:"data_quality"`
}

type countDefinitionV2 struct {
	Scope       string `json:"scope"`
	Unit        string `json:"unit"`
	DedupKey    string `json:"dedup_key"`
	StateFilter string `json:"state_filter"`
}

type deviceV2 struct {
	topologyV2
	Device            deviceDTO         `json:"device"`
	AdjacentLinkCount int               `json:"adjacent_link_count"`
	CountDefinition   countDefinitionV2 `json:"count_definition"`
}

type summaryV2 struct {
	topologyV2
	summaryDTO
	CountDefinitions map[string]countDefinitionV2 `json:"count_definitions"`
}

type linkStatusV2 struct {
	VerificationStatus string     `json:"verification_status"`
	TopologyStatus     string     `json:"topology_status"`
	OperStatus         string     `json:"oper_status"`
	OperObservedAt     *time.Time `json:"oper_observed_at,omitempty"`
}

type neighborV2Item struct {
	*model.LinkInterfaceStatus
	Aggregation *neighborAggregationV4 `json:"aggregation,omitempty"`
	LinkID      string                 `json:"link_id"`
	Local       linkEndpoint           `json:"local"`
	Remote      linkEndpoint           `json:"remote"`
	linkStatusV2
	Observations []apiObservationRef `json:"observations"`
}

type neighborsV2 struct {
	NextCursor        *string `json:"next_cursor"`
	HasMore           bool    `json:"has_more"`
	ResponseTruncated bool    `json:"response_truncated"`
	topologyV2
	DeviceID                    string           `json:"device_id"`
	State                       string           `json:"state"`
	Limit                       int              `json:"limit"`
	MatchingLinkCount           int              `json:"matching_link_count"`
	ReturnedLinkCount           int              `json:"returned_link_count"`
	ReturnedUniqueNeighborCount int              `json:"returned_unique_neighbor_count"`
	Truncated                   bool             `json:"truncated"`
	Items                       []neighborV2Item `json:"items"`
}

func topologyQueryVersion(raw string) (string, bool, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", false, err
	}
	versions, ok := values["schema_version"]
	if !ok {
		return raw, false, nil
	}
	if len(versions) != 1 || (versions[0] != "2" && versions[0] != "3" && versions[0] != "4") {
		return "", false, errors.New("invalid schema_version")
	}
	values.Del("schema_version")
	return values.Encode(), true, nil
}

func parseTopologyStaleAfter(raw string) (time.Duration, error) {
	if raw == "" {
		return defaultTopologyStaleAfter, nil
	}
	duration, err := time.ParseDuration(raw)
	if err != nil || duration < time.Second || duration%time.Second != 0 {
		return 0, errors.New("GONET_TOPOLOGY_STALE_AFTER must be a positive duration in whole seconds")
	}
	return duration, nil
}

func topologyQuality(view *control.View, now time.Time, staleAfter time.Duration, coverage ...coverageV2) topologyV2 {
	quality := dataQualityV2{SnapshotID: nullableID(view.LatestScanID), AsOf: now.UTC(),
		StaleAfterSeconds: int64(staleAfter / time.Second), Coverage: append([]coverageV2{}, coverage...)}
	quality.SnapshotStatus = view.LatestScanStatus
	quality.Collection = collectionOverview(view)
	if quality.SnapshotID != nil && view.LatestScanFinishedAt != nil {
		quality.SnapshotAt = normalizedTime(*view.LatestScanFinishedAt)
		if quality.SnapshotAt != nil && !now.Before(*quality.SnapshotAt) {
			age := now.Sub(*quality.SnapshotAt)
			seconds, stale := int64(age/time.Second), age >= staleAfter
			quality.DataAgeSeconds, quality.Stale = &seconds, &stale
		} else if quality.SnapshotAt != nil {
			quality.DiagnosticCodes = []string{"snapshot_time_in_future"}
		}
	}
	if quality.SnapshotID == nil {
		quality.DiagnosticCodes = []string{"snapshot_unavailable"}
	} else if quality.SnapshotAt == nil {
		quality.DiagnosticCodes = []string{"snapshot_time_unavailable"}
	}
	if view.Evidence != nil && view.Evidence.LatestScan != nil {
		latest := view.Evidence.LatestScan
		quality.LatestScan = &scanStateV2{ScanID: idString(latest.ID), Status: latest.Status}
	}
	return topologyV2{SchemaVersion: 2, DataQuality: quality}
}

func networkCoverage(view *control.View) coverageV2 {
	coverage := coverageV2{Scope: "network", Status: "unknown", ReasonCodes: []string{}}
	switch {
	case view.LatestScanID == 0:
		coverage.ReasonCodes = append(coverage.ReasonCodes, "no_scan_data")
	case view.LatestScanStatus == "partial":
		coverage.Status, coverage.ReasonCodes = "gap", []string{"collection_incomplete"}
	case view.CoverageGap:
		coverage.Status, coverage.ReasonCodes = "gap", []string{"topology_evidence_incomplete"}
	case view.LatestScanStatus == "completed" && view.Evidence != nil && view.Evidence.Collection != nil && !view.Evidence.Collection.ViewVerified:
		coverage.ReasonCodes = []string{"snmp_view_unverified"}
	case view.LatestScanStatus == "completed":
		coverage.Status = "covered"
	default:
		coverage.ReasonCodes = []string{"snapshot_coverage_evidence_unavailable"}
	}
	return coverage
}

func deviceNeighborCoverage(view *control.View, deviceID int64, state string) coverageV2 {
	coverage := coverageV2{Scope: "device_neighbors", Status: "unknown", ReasonCodes: []string{}, DeviceID: idString(deviceID), State: state}
	coverage.EvaluatedDeviceCount = 1
	if view.LatestScanID == 0 {
		coverage.ReasonCodes = []string{"no_scan_data"}
		return coverage
	}
	if view.Evidence == nil {
		coverage.ReasonCodes = []string{"device_collection_evidence_unavailable"}
		return coverage
	}
	scan, found := view.Evidence.DeviceCoverage[deviceID]
	if !found {
		coverage.ReasonCodes = []string{"device_not_recorded_in_snapshot"}
	} else {
		coverage.ReasonCodes = deviceCoverageReasons(view, scan)
		switch {
		case scan.Outcome == "partial" || scan.Outcome == "failed" || scan.Outcome == "unscanned":
			coverage.Status = "gap"
		case scan.AbsenceEligible:
			coverage.Status = "covered"
		case scan.Outcome == "success" && (!scan.SnapshotStable || !scan.CollectionComplete) && scan.Components != nil:
			coverage.Status = "gap"
		}
	}
	for _, candidate := range view.CandidateLinks {
		if int64(candidate.LocalDevice) == deviceID {
			coverage.Status = "gap"
			coverage.ReasonCodes = append(coverage.ReasonCodes, "unresolved_observations")
		}
	}
	coverage.ReasonCodes = uniqueCodes(coverage.ReasonCodes)
	return coverage
}

func physicalLinkStatus(link postgres.ExportLink, scanID int64) linkStatusV2 {
	status := linkStatusV2{VerificationStatus: "unknown", TopologyStatus: "unknown", OperStatus: "unknown"}
	if linkVerification(link, scanID) == "confirmed" {
		status.VerificationStatus = "confirmed"
	}
	switch link.DiscoveryState {
	case "active":
		status.TopologyStatus = "active"
	case "suspect_stale", "stale":
		status.TopologyStatus = "inactive"
	}
	if link.LinkOperStatus != "" {
		switch link.LinkOperStatus {
		case "up", "down", "degraded":
			status.OperStatus = link.LinkOperStatus
			status.OperObservedAt = link.StatusCollectedAt
		case "admin_down":
			status.OperStatus = "down"
			status.OperObservedAt = link.StatusCollectedAt
		}

	}
	return status
}

func (s *Server) writeTopologyV2(w http.ResponseWriter, view *control.View, kind string, deviceID int64, state, requestID string, limit int) {
	meta := compactMetadata(view, state, requestID)
	if kind == "neighbors" {
		writeNeighborsV2(w, view, deviceID, state, limit, meta, s.topologyStaleAfter)
		return
	}
	graph := projectAPI(view, state)
	if kind == "summary" {
		data := summaryV2{topologyQuality(view, meta.GeneratedAt, s.topologyStaleAfter, networkCoverage(view)), graph.Summary, map[string]countDefinitionV2{
			"device_count":            {"network", "device", "device_id", "all"},
			"collected_device_count":  {"network", "device", "device_id", "collected"},
			"historical_device_count": {"network", "device", "device_id", "historical"},
			"device_kinds":            {"network", "device", "device_id", "all"},
			"link_count":              {"network", "physical_link", "link_id", state},
			"pending_neighbor_count":  {"network", "pending_neighbor_entry", "candidate_key", "pending"},
		}}
		writeTopologyResponse(w, apiResponse{Data: data, Meta: meta}, maxCompactAPIBytes, nil)
		return
	}
	for _, device := range graph.Devices {
		if device.ID == idString(deviceID) {
			data := deviceV2{topologyQuality(view, meta.GeneratedAt, s.topologyStaleAfter), device, device.LinkCount,
				countDefinitionV2{"device_adjacency", "physical_link", "link_id", state}}
			writeTopologyResponse(w, apiResponse{Data: data, Meta: meta}, maxCompactAPIBytes, nil)
			return
		}
	}
	apiError(w, 404, "DEVICE_NOT_FOUND", "设备不存在或不在可见范围内")
}

func writeNeighborsV2(w http.ResponseWriter, view *control.View, deviceID int64, state string, limit int, meta apiMeta, staleAfter time.Duration) {
	devices := make(map[int64]control.Device, len(view.Devices))
	for _, device := range view.Devices {
		devices[device.ID] = device
	}
	if _, visible := devices[deviceID]; !visible {
		apiError(w, 404, "DEVICE_NOT_FOUND", "设备不存在或不在可见范围内")
		return
	}
	links, _, _ := matchingNeighborLinks(view, devices, deviceID, state)
	result := neighborsV2{topologyV2: topologyQuality(view, meta.GeneratedAt, staleAfter, networkCoverage(view), deviceNeighborCoverage(view, deviceID, state)),
		DeviceID: idString(deviceID), State: state, Limit: limit, MatchingLinkCount: len(links), Items: []neighborV2Item{}}
	for _, entry := range links[:min(limit, len(links))] {
		link := entry.link
		var evidence postgres.PhysicalLinkEvidence
		if view.Evidence != nil {
			evidence = view.Evidence.Links[link.ID]
		}
		a, b := projectLinkEndpoint(link.DeviceAID, evidence.A), projectLinkEndpoint(link.DeviceBID, evidence.B)
		if link.DeviceBID == deviceID {
			a, b = b, a
		}
		result.Items = append(result.Items, neighborV2Item{LinkInterfaceStatus: orientedLinkStatus(link, deviceID), LinkID: idString(link.ID), Local: a, Remote: b,
			linkStatusV2: physicalLinkStatus(link, view.LatestScanID), Observations: observationRefs(evidence)})
	}
	updateCounts := func() {
		seen := map[string]bool{}
		for _, item := range result.Items {
			seen[item.Remote.DeviceID] = true
		}
		result.ReturnedLinkCount = len(result.Items)
		result.ReturnedUniqueNeighborCount = len(seen)
		result.Truncated = result.ReturnedLinkCount < result.MatchingLinkCount
	}
	updateCounts()
	writeTopologyResponse(w, apiResponse{Data: &result, Meta: meta}, maxCompactAPIBytes, func(_ *apiMeta) bool {
		if len(result.Items) <= 1 {
			return false
		}
		result.Items = result.Items[:len(result.Items)-1]
		updateCounts()
		return true
	})
}
