package webui

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"gonet/internal/auth"
	"gonet/internal/control"
	"gonet/internal/model"
	"gonet/internal/store/postgres"
	"gonet/internal/topology"
)

const maxAPIDevices = 2000
const maxAPILinks = 10000
const maxAPIBytes = 8 << 20
const maxCompactAPIBytes = 12 << 10

type deviceDTO struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	SysName          string     `json:"sys_name"`
	Area             string     `json:"area"`
	Vendor           string     `json:"vendor"`
	Model            string     `json:"model"`
	Kind             string     `json:"device_kind"`
	AccessAddresses  []string   `json:"access_addresses"`
	ChassisMAC       string     `json:"chassis_mac"`
	IdentityState    string     `json:"identity_state"`
	CollectionStatus string     `json:"collection_status"`
	DiscoveryDepth   *int       `json:"discovery_depth"`
	LinkCount        int        `json:"link_count"`
	LastSeenAt       *time.Time `json:"last_seen_at"`
}
type linkDTO struct {
	model.LinkInterfaceStatus
	Aggregation         *neighborAggregationV4 `json:"aggregation,omitempty"`
	ID                  string                 `json:"id"`
	DeviceAID           string                 `json:"device_a_id"`
	DeviceAName         string                 `json:"device_a_name"`
	PortAID             string                 `json:"port_a_id"`
	PortAName           string                 `json:"port_a_name"`
	DeviceBID           string                 `json:"device_b_id"`
	DeviceBName         string                 `json:"device_b_name"`
	PortBID             string                 `json:"port_b_id"`
	PortBName           string                 `json:"port_b_name"`
	Confidence          string                 `json:"confidence"`
	DiscoveryState      string                 `json:"discovery_state"`
	Fresh               bool                   `json:"fresh"`
	CoverageGap         bool                   `json:"coverage_gap"`
	MissedCompleteScans int                    `json:"missed_complete_scans"`
	FirstSeenAt         *time.Time             `json:"first_seen_at"`
	LastSeenAt          *time.Time             `json:"last_seen_at"`
	LastSeenScanID      *string                `json:"last_seen_scan_id"`
}
type candidateDTO struct {
	Key           string     `json:"key"`
	SystemName    string     `json:"system_name"`
	DeviceKind    string     `json:"device_kind"`
	Model         string     `json:"model"`
	Status        string     `json:"status"`
	ObservedByIDs []string   `json:"observed_by_ids"`
	ObservedAt    *time.Time `json:"observed_at"`
}
type summaryDTO struct {
	DeviceCount           int            `json:"device_count"`
	LinkCount             int            `json:"link_count"`
	CollectedDeviceCount  int            `json:"collected_device_count"`
	HistoricalDeviceCount int            `json:"historical_device_count"`
	PendingNeighborCount  int            `json:"pending_neighbor_count"`
	DeviceKinds           map[string]int `json:"device_kinds"`
}
type topologyData struct {
	Summary    summaryDTO     `json:"summary"`
	CoreIDs    []string       `json:"core_ids"`
	Devices    []deviceDTO    `json:"devices"`
	Links      []linkDTO      `json:"links"`
	Candidates []candidateDTO `json:"neighbor_candidates"`
}
type apiMeta struct {
	SchemaVersion        string     `json:"schema_version"`
	RequestID            string     `json:"request_id"`
	GeneratedAt          time.Time  `json:"generated_at"`
	LatestScanID         *string    `json:"latest_scan_id"`
	LatestScanStatus     string     `json:"latest_scan_status"`
	LatestScanFinishedAt *time.Time `json:"latest_scan_finished_at"`
	DataAgeSeconds       *int64     `json:"data_age_seconds"`
	Fresh                bool       `json:"fresh"`
	CoverageGap          bool       `json:"coverage_gap"`
	State                string     `json:"state"`
	ResponseTruncated    bool       `json:"response_truncated,omitempty"`
	SearchTruncated      *bool      `json:"search_truncated,omitempty"`
	CandidatesTruncated  bool       `json:"candidates_truncated,omitempty"`
}
type apiResponse struct {
	Data any     `json:"data"`
	Meta apiMeta `json:"meta"`
}
type neighborItem struct {
	Neighbor deviceDTO `json:"neighbor"`
	Link     linkDTO   `json:"link"`
}
type neighborsData struct {
	DeviceID      string         `json:"device_id"`
	NeighborCount int            `json:"neighbor_count"`
	LinkCount     int            `json:"link_count"`
	Items         []neighborItem `json:"items"`
}

func topologyRoute(path string) (string, string, bool) {
	switch path {
	case "/api/v1/topology":
		return "topology", "", true
	case "/api/v1/topology/summary":
		return "summary", "", true
	case "/api/v1/topology/collection":
		return "collection", "", true
	case "/api/v1/devices":
		return "search", "", true
	}
	if !strings.HasPrefix(path, "/api/v1/devices/") {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(path, "/api/v1/devices/"), "/")
	if len(parts) == 1 && parts[0] != "" {
		return "device", parts[0], true
	}
	if len(parts) == 2 && parts[0] != "" {
		switch parts[1] {
		case "interfaces":
			return "interfaces", parts[0], true
		case "neighbors":
			return "neighbors", parts[0], true
		case "uplink-path":
			return "path", parts[0], true
		}
	}
	return "", "", false
}
func apiRequestID(w http.ResponseWriter) string {
	if id := w.Header().Get("X-Request-ID"); id != "" {
		return id
	}
	id := rand.Text()
	w.Header().Set("X-Request-ID", id)
	return id
}
func apiError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}, "meta": map[string]string{"request_id": apiRequestID(w)}})
}
func (s *Server) topologyAPI(w http.ResponseWriter, r *http.Request, kind, rawID string) {
	started := time.Now()
	audit := &topologyAuditWriter{ResponseWriter: w}
	w = audit
	id := apiRequestID(w)
	caller := "unauthenticated"
	deviceID, idErr := parseDeviceID(rawID, nil)
	if idErr != nil {
		deviceID = 0
	}
	defer func() { s.logTopologyRequest(id, caller, kind, deviceID, audit.status, audit.count, started) }()
	allow := "GET, HEAD"
	if kind == "search" || kind == "path" {
		allow = "GET"
	}
	if r.Method != "GET" && !(r.Method == "HEAD" && allow == "GET, HEAD") {
		w.Header().Set("Allow", allow)
		message := "仅支持 GET"
		if allow == "GET, HEAD" {
			message = "仅支持 GET 和 HEAD"
		}
		apiError(w, 405, "METHOD_NOT_ALLOWED", message)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.apiReadTimeout)
	defer cancel()
	compact := false
	authorization := r.Header.Values("Authorization")
	if len(authorization) > 0 {
		hash, valid := auth.BearerDigest(authorization)
		if !valid {
			w.Header().Set("WWW-Authenticate", "Bearer")
			apiError(w, 401, "AUTH_UNAUTHENTICATED", "只读凭据无效")
			return
		}
		grant, err := s.apiKeys.LookupAPIKey(ctx, hash)
		if errors.Is(err, pgx.ErrNoRows) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			apiError(w, 401, "AUTH_UNAUTHENTICATED", "只读凭据无效")
			return
		}
		if err != nil {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				apiError(w, 504, "READ_TIMEOUT", "读取 API Key 超时")
			} else if r.Context().Err() == nil {
				apiError(w, 503, "DATABASE_UNAVAILABLE", "暂时无法验证 API Key")
			}
			return
		}
		caller = "key:" + idString(grant.ID)
		if !containsIP(grant.AllowedIPs, s.requestIP(r)) {
			apiError(w, 403, "IP_NOT_ALLOWED", "请求来源 IP 不在白名单内")
			return
		}
		if !grant.Profile.AllowsTopologyRoute(kind) {
			apiError(w, 403, "API_ROUTE_NOT_ALLOWED", "此 API Key 无权访问该接口")
			return
		}
		compact = grant.Profile == auth.APITopologyCompact
		if compact && r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			apiError(w, 405, "METHOD_NOT_ALLOWED", "仅支持 GET")
			return
		}
	} else if session, ok := s.session(r); !ok {
		w.Header().Set("WWW-Authenticate", "Bearer")
		apiError(w, 401, "AUTH_UNAUTHENTICATED", "请提供登录会话或只读凭据")
		return
	} else {
		caller = "admin:" + session.Username
	}
	var search deviceSearchQuery
	var collection collectionQuery
	var path corePathQuery
	var state string
	var pending bool
	var neighborLimit int
	var neighborPage neighborPageQuery
	var err error
	rawQuery, v2 := r.URL.RawQuery, false
	if r.Method == "GET" && (kind == "device" || kind == "neighbors" || kind == "summary" || kind == "path" || kind == "topology" && r.URL.Query().Get("schema_version") == "4") {
		rawQuery, v2, err = topologyQueryVersion(rawQuery)
		if err != nil {
			apiError(w, 400, "INVALID_ARGUMENT", "查询参数或设备 ID 无效")
			return
		}
	}
	version := 2
	if r.URL.Query().Get("schema_version") == "4" {
		version = 4
		if kind != "neighbors" && kind != "path" && kind != "topology" {
			apiError(w, 400, "INVALID_ARGUMENT", "版本 4 适用于拓扑、邻居与路径查询")
			return
		}
	}
	if r.URL.Query().Get("schema_version") == "3" {
		version = 3
		if kind != "neighbors" && kind != "path" {
			apiError(w, 400, "INVALID_ARGUMENT", "版本 3 适用于邻居与路径查询")
			return
		}
	}
	switch kind {
	case "collection":
		collection, err = parseCollectionQuery(r.URL.RawQuery)
		state = "all"
	case "search":
		search, err = parseDeviceSearch(r.URL.RawQuery)
		state = "all"
	case "neighbors":
		if v2 {
			neighborPage, err = parseNeighborPage(rawQuery)
			state, neighborLimit = neighborPage.state, neighborPage.limit
		} else {
			state, neighborLimit, err = parseNeighborQuery(rawQuery, compact)
		}
	case "path":
		path, err = parseCorePathQuery(rawQuery)
		if v2 && err == nil {
			values, _ := url.ParseQuery(rawQuery)
			if values.Has("max_paths") && path.maxPaths != 1 {
				err = errors.New("schema 2 returns one path")
			}
			path.maxPaths = 1
		}
		path.version = version
		state = "active"
	default:
		state, pending, err = topologyQuery(rawQuery, kind == "topology")
	}
	if err != nil || (rawID != "" && idErr != nil) {
		apiError(w, 400, "INVALID_ARGUMENT", "查询参数或设备 ID 无效")
		return
	}
	read := s.backend.Read
	if backend, ok := s.backend.(interface {
		ReadTopologyEvidence(context.Context) (*control.View, error)
	}); ok && (v2 || neighborLimit > 0 || kind == "path" || kind == "topology" || kind == "neighbors" || kind == "collection") {
		read = backend.ReadTopologyEvidence
	}
	view, err := read(ctx)
	if err != nil || view == nil || ctx.Err() != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			apiError(w, 504, "READ_TIMEOUT", "读取拓扑数据超时")
		} else if errors.Is(r.Context().Err(), context.Canceled) {
			return
		} else {
			apiError(w, 503, "DATABASE_UNAVAILABLE", "暂时无法读取拓扑数据")
		}
		return
	}
	if kind == "collection" {
		s.writeCollection(w, view, id, collection)
		return
	}
	if kind == "interfaces" {
		writeDeviceInterfaces(w, view, deviceID, id)
		return
	}
	if kind == "search" {
		result := findDevices(view.Devices, search)
		meta := compactMetadata(view, state, id)
		writeTopologyResponse(w, apiResponse{Data: &result, Meta: meta}, maxCompactAPIBytes, func(_ *apiMeta) bool {
			if len(result.Items) <= 1 {
				return false
			}
			result.Items = result.Items[:len(result.Items)-1]
			return true
		})
		return
	}
	if v2 {
		if kind == "topology" && version == 4 {
			graph := projectAPI(view, state)
			if len(graph.Devices) > maxAPIDevices || len(graph.Links) > maxAPILinks {
				apiError(w, 422, "RESULT_TOO_LARGE", "拓扑超出完整结果容量限制")
				return
			}
			if !pending {
				graph.Candidates = []candidateDTO{}
			}
			data := struct {
				topologyData
				SchemaVersion          int                       `json:"schema_version"`
				InferencePolicyVersion string                    `json:"inference_policy_version"`
				AggregateConnections   []aggregationConnectionV4 `json:"aggregate_connections"`
			}{graph, 4, topology.AggregationInferencePolicy, graphAggregationsV4(view)}
			writeTopologyResponse(w, apiResponse{Data: data, Meta: metadata(view, state, id, time.Now().UTC())}, maxAPIBytes, nil)
			return
		}
		if kind == "path" {
			s.writeUplinkV2(ctx, w, view, deviceID, id, path)
			return
		}
		if kind == "neighbors" {
			s.writeNeighborPage(w, view, deviceID, id, neighborPage, version)
			return
		}
		s.writeTopologyV2(w, view, kind, deviceID, state, id, neighborLimit)
		return
	}
	if neighborLimit > 0 {
		writeCompactNeighbors(w, view, deviceID, state, id, neighborLimit)
		return
	}
	if kind == "path" {
		writeCorePaths(ctx, w, view, deviceID, id, path)
		return
	}
	graph := projectAPI(view, state)
	var data any
	switch kind {
	case "topology":
		if len(graph.Devices) > maxAPIDevices || len(graph.Links) > maxAPILinks {
			apiError(w, 422, "RESULT_TOO_LARGE", "拓扑超出完整结果容量限制")
			return
		}
		if !pending {
			graph.Candidates = []candidateDTO{}
		}
		data = graph
	case "summary":
		data = graph.Summary
	case "device", "neighbors":
		target := strconv.FormatInt(deviceID, 10)
		index := slices.IndexFunc(graph.Devices, func(d deviceDTO) bool { return d.ID == target })
		if index < 0 {
			apiError(w, 404, "DEVICE_NOT_FOUND", "设备不存在或不在可见范围内")
			return
		}
		if kind == "device" {
			data = struct {
				Device deviceDTO `json:"device"`
			}{graph.Devices[index]}
			break
		}
		byID := make(map[string]deviceDTO, len(graph.Devices))
		for _, d := range graph.Devices {
			byID[d.ID] = d
		}
		result := neighborsData{DeviceID: target, Items: []neighborItem{}}
		neighbors := map[string]bool{}
		for _, link := range graph.Links {
			other := ""
			if link.DeviceAID == target {
				other = link.DeviceBID
			} else if link.DeviceBID == target {
				other = link.DeviceAID
			}
			if other != "" {
				result.Items = append(result.Items, neighborItem{Neighbor: byID[other], Link: link})
				neighbors[other] = true
			}
		}
		result.NeighborCount = len(neighbors)
		result.LinkCount = len(result.Items)
		data = result
	}
	response := apiResponse{Data: data, Meta: metadata(view, state, id, time.Now().UTC())}
	budget := maxAPIBytes
	if compact {
		budget = maxCompactAPIBytes
		response.Meta.CoverageGap = response.Meta.CoverageGap || view.LatestScanStatus == "partial"
	}
	writeTopologyResponse(w, response, budget, nil)
}

func writeTopologyResponse(w http.ResponseWriter, response apiResponse, budget int, trim func(*apiMeta) bool) {
	for {
		payload, err := json.Marshal(response)
		if err != nil {
			apiError(w, 500, "INTERNAL_ERROR", "无法生成拓扑响应")
			return
		}
		if len(payload)+1 <= budget {
			if audit, ok := w.(*topologyAuditWriter); ok {
				audit.count = topologyResultCount(response.Data)
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Content-Length", strconv.Itoa(len(payload)+1))
			w.WriteHeader(200)
			_, _ = w.Write(append(payload, '\n'))
			return
		}
		if trim == nil || !trim(&response.Meta) {
			apiError(w, 422, "RESULT_TOO_LARGE", "响应超出容量限制")
			return
		}
		response.Meta.ResponseTruncated = true
	}
}
func parseDeviceID(raw string, previous error) (int64, error) {
	if previous != nil {
		return 0, previous
	}
	if raw == "" || raw[0] < '1' || raw[0] > '9' {
		return 0, errors.New("invalid id")
	}
	for _, ch := range raw {
		if ch < '0' || ch > '9' {
			return 0, errors.New("invalid id")
		}
	}
	return strconv.ParseInt(raw, 10, 64)
}
func topologyQuery(raw string, allowPending bool) (string, bool, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", false, err
	}
	state, pending := "all", true
	for key, list := range values {
		if len(list) != 1 || list[0] == "" {
			return "", false, errors.New("duplicate or empty parameter")
		}
		switch key {
		case "state":
			if list[0] != "all" && list[0] != "active" {
				return "", false, errors.New("invalid state")
			}
			state = list[0]
		case "include_pending":
			if !allowPending || (list[0] != "true" && list[0] != "false") {
				return "", false, errors.New("invalid pending")
			}
			pending = list[0] == "true"
		default:
			return "", false, errors.New("unknown parameter")
		}
	}
	return state, pending, nil
}
func normalizedTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	v := t.UTC()
	return &v
}
func idString(id int64) string { return strconv.FormatInt(id, 10) }
func nullableID(id int64) *string {
	if id == 0 {
		return nil
	}
	v := idString(id)
	return &v
}
func metadata(view *control.View, state, id string, now time.Time) apiMeta {
	m := apiMeta{SchemaVersion: "1.0", RequestID: id, GeneratedAt: now, LatestScanID: nullableID(view.LatestScanID), LatestScanStatus: view.LatestScanStatus, Fresh: view.Fresh, CoverageGap: view.CoverageGap, State: state}
	if view.LatestScanFinishedAt != nil {
		m.LatestScanFinishedAt = normalizedTime(*view.LatestScanFinishedAt)
	}
	if m.LatestScanFinishedAt != nil {
		age := max(int64(0), int64(now.Sub(*m.LatestScanFinishedAt).Seconds()))
		m.DataAgeSeconds = &age
	}
	return m
}

func compactMetadata(view *control.View, state, id string) apiMeta {
	meta := metadata(view, state, id, time.Now().UTC())
	meta.CoverageGap = meta.CoverageGap || view.LatestScanStatus == "partial"
	return meta
}

// Only the already scope-projected View enters here. These explicit DTOs cannot
// serialize internal identities, raw payloads, configuration or task controls.
func projectAPI(view *control.View, state string) topologyData {
	aggregations := physicalAggregations(view)
	graph := topologyData{CoreIDs: []string{}, Devices: []deviceDTO{}, Links: []linkDTO{}, Candidates: []candidateDTO{}, Summary: summaryDTO{DeviceKinds: map[string]int{"switch": 0, "router": 0, "wireless_controller": 0}}}
	devices := slices.Clone(view.Devices)
	slices.SortFunc(devices, func(a, b control.Device) int { return compareID(a.ID, b.ID) })
	visible := map[int64]bool{}
	for _, d := range devices {
		visible[d.ID] = true
	}
	links := []postgres.ExportLink{}
	counts := map[int64]int{}
	for _, link := range view.Links {
		if !visible[link.DeviceAID] || !visible[link.DeviceBID] || (state == "active" && link.DiscoveryState != "active") {
			continue
		}
		links = append(links, link)
		counts[link.DeviceAID]++
		if link.DeviceBID != link.DeviceAID {
			counts[link.DeviceBID]++
		}
	}
	slices.SortFunc(links, func(a, b postgres.ExportLink) int {
		for _, pair := range [][2]int64{{a.DeviceAID, b.DeviceAID}, {a.PortAID, b.PortAID}, {a.DeviceBID, b.DeviceBID}, {a.PortBID, b.PortBID}, {a.ID, b.ID}} {
			if c := compareID(pair[0], pair[1]); c != 0 {
				return c
			}
		}
		return 0
	})
	for _, d := range devices {
		graph.Devices = append(graph.Devices, apiDevice(d, counts[d.ID]))
		if _, ok := graph.Summary.DeviceKinds[d.Kind]; ok {
			graph.Summary.DeviceKinds[d.Kind]++
		}
		if d.Status == "collected" {
			graph.Summary.CollectedDeviceCount++
		} else if d.Status == "historical" {
			graph.Summary.HistoricalDeviceCount++
		}
	}
	for _, l := range links {
		x := apiLink(l)
		x.Aggregation = aggregations[l.ID]
		graph.Links = append(graph.Links, x)
	}
	core := slices.Clone(view.CoreIDs)
	slices.Sort(core)
	core = slices.Compact(core)
	for _, id := range core {
		if visible[id] {
			graph.CoreIDs = append(graph.CoreIDs, idString(id))
		}
	}
	candidates := slices.Clone(view.Candidates)
	slices.SortFunc(candidates, func(a, b control.Candidate) int { return strings.Compare(a.Key, b.Key) })
	for _, candidate := range candidates {
		observers := []string{}
		ids := slices.Clone(candidate.ObserverIDs)
		slices.Sort(ids)
		ids = slices.Compact(ids)
		for _, id := range ids {
			if visible[id] {
				observers = append(observers, idString(id))
			}
		}
		if len(observers) == 0 {
			continue
		}
		graph.Candidates = append(graph.Candidates, candidateDTO{Key: candidate.Key, SystemName: candidate.Name, DeviceKind: candidate.Kind, Model: candidate.Model, Status: candidate.Status, ObservedByIDs: observers, ObservedAt: normalizedTime(candidate.ObservedAt)})
	}
	graph.Summary.DeviceCount = len(graph.Devices)
	graph.Summary.LinkCount = len(graph.Links)
	graph.Summary.PendingNeighborCount = len(graph.Candidates)
	return graph
}

func apiDevice(d control.Device, linkCount int) deviceDTO {
	return deviceDTO{ID: idString(d.ID), Name: d.Name, SysName: d.SysName, Area: d.Area, Vendor: d.Vendor, Model: d.Model,
		Kind: d.Kind, AccessAddresses: append([]string{}, d.AccessAddresses...), ChassisMAC: d.MAC, IdentityState: d.IdentityState,
		CollectionStatus: d.Status, DiscoveryDepth: d.DiscoveryDepth, LinkCount: linkCount, LastSeenAt: normalizedTime(d.LastSeenAt)}
}

func apiLink(l postgres.ExportLink) linkDTO {
	return linkDTO{LinkInterfaceStatus: l.LinkInterfaceStatus, ID: idString(l.ID), DeviceAID: idString(l.DeviceAID), DeviceAName: l.DeviceAName, PortAID: idString(l.PortAID), PortAName: l.PortAName,
		DeviceBID: idString(l.DeviceBID), DeviceBName: l.DeviceBName, PortBID: idString(l.PortBID), PortBName: l.PortBName, Confidence: l.Confidence,
		DiscoveryState: l.DiscoveryState, Fresh: l.Fresh, CoverageGap: l.CoverageGap, MissedCompleteScans: l.MissedCompleteScans,
		FirstSeenAt: normalizedTime(l.FirstSeenAt), LastSeenAt: normalizedTime(l.LastSeenAt), LastSeenScanID: linkScanID(l)}
}

func linkScanID(l postgres.ExportLink) *string {
	if l.LastSeenScanID == nil {
		return nil
	}
	return nullableID(*l.LastSeenScanID)
}

func compareID(a, b int64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
