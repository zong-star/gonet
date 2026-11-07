package webui

import (
	"errors"
	"net/http"
	"net/url"
	"slices"

	"gonet/internal/control"
	"gonet/internal/store/postgres"
)

type apiInterface struct {
	Name    string  `json:"name"`
	Kind    string  `json:"kind"`
	PortID  *string `json:"port_id,omitempty"`
	IfIndex *int32  `json:"if_index"`
}

type neighborEndpoint struct {
	DeviceID   string       `json:"device_id"`
	DeviceName string       `json:"device_name"`
	Interface  apiInterface `json:"interface"`
}

type apiObservationRef struct {
	ObservationID string `json:"observation_id"`
	ObserverID    string `json:"observer_device_id"`
}

type compactNeighborItem struct {
	neighborItem
	Local              neighborEndpoint    `json:"local"`
	Remote             neighborEndpoint    `json:"remote"`
	VerificationStatus string              `json:"verification_status"`
	DiscoverySource    string              `json:"discovery_source"`
	Observations       []apiObservationRef `json:"observations"`
}

type compactNeighborsData struct {
	DeviceID          string                `json:"device_id"`
	NeighborCount     int                   `json:"neighbor_count"`
	LinkCount         int                   `json:"link_count"`
	ReturnedLinkCount int                   `json:"returned_link_count"`
	Truncated         bool                  `json:"truncated"`
	Items             []compactNeighborItem `json:"items"`
}

func parseNeighborQuery(raw string, compact bool) (string, int, error) {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return "", 0, err
	}
	limit := 0
	if list, ok := values["limit"]; ok {
		if len(list) != 1 {
			return "", 0, errors.New("duplicate limit")
		}
		limit, err = parseAPILimit(list[0], 20)
		if err != nil {
			return "", 0, err
		}
		values.Del("limit")
	} else if compact {
		limit = 20
	}
	state, _, err := topologyQuery(values.Encode(), false)
	if limit > 0 && !values.Has("state") {
		state = "active"
	}
	return state, limit, err
}

func linkVerification(link postgres.ExportLink, scanID int64) string {
	if scanID != 0 && link.DiscoveryState == "active" && link.LastSeenScanID != nil && *link.LastSeenScanID == scanID {
		return "confirmed"
	}
	return "historical"
}

func physicalInterface(portID int64, name string, evidence postgres.LinkEndpointEvidence) apiInterface {
	if evidence.Name != nil {
		name = *evidence.Name
	}
	return apiInterface{Name: name, Kind: "physical", PortID: nullableID(portID), IfIndex: evidence.IfIndex}
}

func observationRefs(evidence postgres.PhysicalLinkEvidence) []apiObservationRef {
	refs := make([]apiObservationRef, 0, len(evidence.Observations))
	for _, ref := range evidence.Observations {
		refs = append(refs, apiObservationRef{ObservationID: idString(ref.ID), ObserverID: idString(ref.ObserverID)})
	}
	return refs
}

type neighborLink struct {
	link  postgres.ExportLink
	other int64
}

func matchingNeighborLinks(view *control.View, devices map[int64]control.Device, deviceID int64, state string) ([]neighborLink, map[int64]int, int) {
	links := []neighborLink{}
	counts := map[int64]int{}
	neighbors := map[int64]bool{}
	for _, link := range view.Links {
		_, a := devices[link.DeviceAID]
		_, b := devices[link.DeviceBID]
		if !a || !b || (state == "active" && link.DiscoveryState != "active") {
			continue
		}
		counts[link.DeviceAID]++
		if link.DeviceBID != link.DeviceAID {
			counts[link.DeviceBID]++
		}
		var other int64
		switch deviceID {
		case link.DeviceAID:
			other = link.DeviceBID
		case link.DeviceBID:
			other = link.DeviceAID
		default:
			continue
		}
		links = append(links, neighborLink{link: link, other: other})
		neighbors[other] = true
	}
	slices.SortFunc(links, func(a, b neighborLink) int {
		av, bv := linkVerification(a.link, view.LatestScanID), linkVerification(b.link, view.LatestScanID)
		if av != bv {
			if av == "confirmed" {
				return -1
			}
			return 1
		}
		if a.link.Confidence != b.link.Confidence {
			if a.link.Confidence == "bidirectional" {
				return -1
			}
			if b.link.Confidence == "bidirectional" {
				return 1
			}
		}
		if a.other != b.other {
			return compareID(a.other, b.other)
		}
		return compareID(a.link.ID, b.link.ID)
	})
	return links, counts, len(neighbors)
}

func writeCompactNeighbors(w http.ResponseWriter, view *control.View, deviceID int64, state, requestID string, limit int) {
	devices := make(map[int64]control.Device, len(view.Devices))
	for _, device := range view.Devices {
		devices[device.ID] = device
	}
	if _, ok := devices[deviceID]; !ok {
		apiError(w, 404, "DEVICE_NOT_FOUND", "设备不存在或不在可见范围内")
		return
	}
	links, counts, neighborCount := matchingNeighborLinks(view, devices, deviceID, state)
	result := compactNeighborsData{DeviceID: idString(deviceID), NeighborCount: neighborCount, LinkCount: len(links), Items: []compactNeighborItem{}}
	for _, entry := range links[:min(limit, len(links))] {
		link := entry.link
		var evidence postgres.PhysicalLinkEvidence
		if view.Evidence != nil {
			evidence = view.Evidence.Links[link.ID]
		}
		a := neighborEndpoint{idString(link.DeviceAID), devices[link.DeviceAID].Name, physicalInterface(link.PortAID, link.PortAName, evidence.A)}
		b := neighborEndpoint{idString(link.DeviceBID), devices[link.DeviceBID].Name, physicalInterface(link.PortBID, link.PortBName, evidence.B)}
		if link.DeviceBID == deviceID {
			a, b = b, a
		}
		result.Items = append(result.Items, compactNeighborItem{
			neighborItem: neighborItem{Neighbor: apiDevice(devices[entry.other], counts[entry.other]), Link: apiLink(link)},
			Local:        a, Remote: b, VerificationStatus: linkVerification(link, view.LatestScanID), DiscoverySource: "lldp", Observations: observationRefs(evidence),
		})
	}
	result.ReturnedLinkCount = len(result.Items)
	result.Truncated = result.ReturnedLinkCount < result.LinkCount
	writeTopologyResponse(w, apiResponse{Data: &result, Meta: compactMetadata(view, state, requestID)}, maxCompactAPIBytes, func(_ *apiMeta) bool {
		if len(result.Items) <= 1 {
			return false
		}
		result.Items = result.Items[:len(result.Items)-1]
		result.ReturnedLinkCount = len(result.Items)
		result.Truncated = true
		return true
	})
}
