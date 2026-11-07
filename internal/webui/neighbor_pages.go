package webui

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"gonet/internal/control"
	"gonet/internal/store/postgres"
	"gonet/internal/topology"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

type neighborPageQuery struct {
	state  string
	limit  int
	peer   int64
	cursor string
}
type neighborCursor struct {
	Fingerprint string `json:"f"`
	Offset      int    `json:"o"`
}

func parseNeighborPage(raw string) (neighborPageQuery, error) {
	q := neighborPageQuery{}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return q, err
	}
	for _, key := range []string{"neighbor_device_id", "cursor"} {
		if values, ok := v[key]; ok {
			if len(values) != 1 || values[0] == "" {
				return q, errors.New("invalid page parameter")
			}
			if key == "cursor" {
				if len(values[0]) > 1024 {
					return q, errors.New("invalid cursor")
				}
				q.cursor = values[0]
			} else {
				q.peer, err = parseDeviceID(values[0], nil)
				if err != nil {
					return q, err
				}
			}
			v.Del(key)
		}
	}
	q.state, q.limit, err = parseNeighborQuery(v.Encode(), true)
	return q, err
}
func (s *Server) encodeNeighborCursor(c neighborCursor) string {
	b, _ := json.Marshal(c)
	m := hmac.New(sha256.New, s.cursorKey[:])
	m.Write(b)
	return base64.RawURLEncoding.EncodeToString(b) + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func (s *Server) decodeNeighborCursor(raw string) (neighborCursor, error) {
	var c neighborCursor
	parts := strings.Split(raw, ".")
	if len(parts) != 2 {
		return c, errors.New("invalid cursor")
	}
	b, e := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if e != nil {
		return c, e
	}
	sig, e := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if e != nil {
		return c, e
	}
	m := hmac.New(sha256.New, s.cursorKey[:])
	m.Write(b)
	if !hmac.Equal(sig, m.Sum(nil)) {
		return c, errors.New("invalid cursor signature")
	}
	if e = json.Unmarshal(b, &c); e != nil || c.Offset <= 0 {
		return c, errors.New("invalid cursor position")
	}
	return c, nil
}
func (s *Server) writeNeighborPage(w http.ResponseWriter, view *control.View, id int64, requestID string, q neighborPageQuery, version int) {
	devices := map[int64]control.Device{}
	for _, d := range view.Devices {
		devices[d.ID] = d
	}
	if _, ok := devices[id]; !ok {
		apiError(w, 404, "DEVICE_NOT_FOUND", "设备不存在或不在可见范围内")
		return
	}
	links, _, _ := matchingNeighborLinks(view, devices, id, q.state)
	connections := map[int64]topologyConnection{}
	if version == 4 {
		for _, c := range topologyConnectionsV4(view, visibleAggregationDevices(view)) {
			for _, l := range c.members {
				connections[l.ID] = c
			}
		}
	}
	if q.peer != 0 {
		if _, ok := devices[q.peer]; !ok {
			apiError(w, 404, "DEVICE_NOT_FOUND", "设备不存在或不在可见范围内")
			return
		}
		links = slices.DeleteFunc(links, func(l neighborLink) bool { return l.other != q.peer })
	}
	// Keep v2's established order. The fingerprint binds the complete ordered
	// result and all visible endpoint facts, so offsets cannot skip changed data.
	b, _ := json.Marshal(struct {
		ID, Peer, Scan int64
		State          string
		Limit, Version int
		Devices        []control.Device
		Links          []neighborLinkFingerprint
	}{id, q.peer, view.LatestScanID, q.state, q.limit, version, view.Devices, neighborFingerprints(view, links)})
	if version == 4 {
		// Membership changes can affect a group outside the requested page/peer.
		lagFacts := map[int64]postgres.DeviceLAGEvidence{}
		if view.Evidence != nil {
			for device := range devices {
				lagFacts[device] = view.Evidence.LAG[device]
			}
		}
		allLinks := []neighborLink{}
		for _, link := range view.Links {
			if _, ok := devices[link.DeviceAID]; !ok {
				continue
			}
			if _, ok := devices[link.DeviceBID]; !ok {
				continue
			}
			allLinks = append(allLinks, neighborLink{link: link})
		}
		facts, _ := json.Marshal(struct {
			Policy string
			LAG    map[int64]postgres.DeviceLAGEvidence
			Links  []neighborLinkFingerprint
		}{topology.AggregationInferencePolicy, lagFacts, neighborFingerprints(view, allLinks)})
		b = append(b, facts...)
	}
	hash := sha256.Sum256(b)
	fingerprint := hex.EncodeToString(hash[:])
	start := 0
	if q.cursor != "" {
		c, e := s.decodeNeighborCursor(q.cursor)
		if e != nil {
			apiError(w, 400, "INVALID_CURSOR", "邻居游标无效，请重新查询")
			return
		}
		if c.Fingerprint != fingerprint {
			apiError(w, 409, "CURSOR_STALE", "拓扑快照或可见范围已变化，请重新查询")
			return
		}
		start = c.Offset
		if start >= len(links) {
			apiError(w, 400, "INVALID_CURSOR", "邻居游标超出结果范围")
			return
		}
	}
	meta := compactMetadata(view, q.state, requestID)
	data := neighborsV2{topologyV2: topologyQuality(view, meta.GeneratedAt, s.topologyStaleAfter, networkCoverage(view), deviceNeighborCoverage(view, id, q.state)), DeviceID: idString(id), State: q.state, Limit: q.limit, MatchingLinkCount: len(links), Items: []neighborV2Item{}}
	data.SchemaVersion = version
	if version == 4 {
		data.InferencePolicyVersion = topology.AggregationInferencePolicy
	}
	for _, entry := range links[start:min(start+q.limit, len(links))] {
		link := entry.link
		var facts postgres.PhysicalLinkEvidence
		if view.Evidence != nil {
			facts = view.Evidence.Links[link.ID]
		}
		a, b := projectLinkEndpoint(link.DeviceAID, facts.A), projectLinkEndpoint(link.DeviceBID, facts.B)
		if link.DeviceAID != id {
			a, b = b, a
		}
		item := neighborV2Item{LinkInterfaceStatus: orientedLinkStatus(link, id), LinkID: idString(link.ID), Local: a, Remote: b, linkStatusV2: physicalLinkStatus(link, view.LatestScanID), Observations: observationRefs(facts)}
		if c, ok := connections[link.ID]; version == 4 && ok {
			local, remote := c.groupA, c.groupB
			if link.DeviceAID != id {
				local, remote = remote, local
			}
			status := aggregationState(c.status)
			if c.status == "inferred" {
				status = "inferred"
			}
			item.Aggregation = &neighborAggregationV4{AggregateID: nullableString(aggregationID(view, c)), Status: status, Local: local, Remote: remote, KnownMemberLinkCount: len(c.members)}
		}
		data.Items = append(data.Items, item)
	}
	counts := func() {
		seen := map[string]bool{}
		for _, item := range data.Items {
			seen[item.Remote.DeviceID] = true
		}
		data.ReturnedLinkCount = len(data.Items)
		data.ReturnedUniqueNeighborCount = len(seen)
		data.HasMore = start+len(data.Items) < len(links)
		data.NextCursor = nil
		if data.HasMore {
			x := s.encodeNeighborCursor(neighborCursor{fingerprint, start + len(data.Items)})
			data.NextCursor = &x
		}
		data.Truncated = data.ResponseTruncated || version == 2 && data.HasMore
	}
	counts()
	writeTopologyResponse(w, apiResponse{Data: &data, Meta: meta}, maxCompactAPIBytes, func(meta *apiMeta) bool {
		if len(data.Items) <= 1 {
			return false
		}
		data.Items = data.Items[:len(data.Items)-1]
		data.ResponseTruncated = true
		meta.ResponseTruncated = true
		counts()
		return true
	})
}

type neighborLinkFingerprint struct {
	Link     postgres.ExportLink
	Evidence postgres.PhysicalLinkEvidence
}

func neighborFingerprints(view *control.View, links []neighborLink) []neighborLinkFingerprint {
	result := make([]neighborLinkFingerprint, 0, len(links))
	for _, l := range links {
		var ev postgres.PhysicalLinkEvidence
		if view.Evidence != nil {
			ev = view.Evidence.Links[l.link.ID]
		}
		result = append(result, neighborLinkFingerprint{l.link, ev})
	}
	return result
}
