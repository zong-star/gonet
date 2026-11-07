package webui

import (
	"gonet/internal/control"
	"gonet/internal/model"
	"gonet/internal/store/postgres"
	"net/http"
	"time"
)

func writeDeviceInterfaces(w http.ResponseWriter, view *control.View, id int64, requestID string) {
	for _, d := range view.Devices {
		if d.ID == id {
			items := d.Interfaces
			if items == nil {
				items = []model.Interface{}
			}
			writeTopologyResponse(w, apiResponse{Data: struct {
				DeviceID              string            `json:"device_id"`
				Interfaces            []model.Interface `json:"interfaces"`
				StatusCollectionState string            `json:"status_collection_state"`
				StatusAttemptedAt     *time.Time        `json:"status_attempted_at"`
				StatusError           string            `json:"status_error,omitempty"`
			}{idString(id), items, d.InterfaceCollectionState, d.InterfaceAttemptedAt, d.InterfaceStatusError}, Meta: compactMetadata(view, "all", requestID)}, maxAPIBytes, nil)
			return
		}
	}
	apiError(w, 404, "DEVICE_NOT_FOUND", "设备不存在或不在可见范围内")
}
func physicalAggregations(view *control.View) map[int64]*neighborAggregationV4 {
	out := map[int64]*neighborAggregationV4{}
	if view.Evidence == nil {
		return out
	}
	for _, c := range topologyConnectionsV4(view, visibleAggregationDevices(view)) {
		id := aggregationID(view, c)
		var ptr *string
		if id != "" {
			ptr = &id
		}
		if c.groupA == nil && c.groupB == nil {
			continue
		}
		for _, m := range c.members {
			out[m.ID] = &neighborAggregationV4{AggregateID: ptr, Status: c.status, Local: c.groupA, Remote: c.groupB, KnownMemberLinkCount: len(c.members)}
		}
	}
	return out
}
func orientedLinkStatus(l postgres.ExportLink, from int64) *model.LinkInterfaceStatus {
	r := l.LinkInterfaceStatus
	if r.LinkOperStatus == "" {
		return nil
	}
	if from == l.DeviceBID {
		r.SourceAdminStatus, r.TargetAdminStatus = r.TargetAdminStatus, r.SourceAdminStatus
		r.SourceOperStatus, r.TargetOperStatus = r.TargetOperStatus, r.SourceOperStatus
		r.SourceCollectionState, r.TargetCollectionState = r.TargetCollectionState, r.SourceCollectionState
		r.SourceStatusCollectedAt, r.TargetStatusCollectedAt = r.TargetStatusCollectedAt, r.SourceStatusCollectedAt
	}
	return &r
}

// Keep the existing oper_status enum stable; the new link_oper_status carries
// admin_down and stale separately. A logical LAG never inherits its first member.
func aggregationOperStatus(edge *uplinkEdgeV2, members []postgres.ExportLink, scan int64) {
	if edge.Kind != "aggregate" || len(members) == 0 {
		return
	}
	counts := map[string]int{}
	var at *time.Time
	for _, l := range members {
		s := physicalLinkStatus(l, scan)
		counts[s.OperStatus]++
		if s.OperObservedAt != nil && (at == nil || s.OperObservedAt.Before(*at)) {
			at = s.OperObservedAt
		}
	}
	edge.OperStatus = "unknown"
	edge.OperObservedAt = nil
	if counts["unknown"] > 0 {
		return
	}
	edge.OperObservedAt = at
	switch {
	case counts["up"] == len(members):
		edge.OperStatus = "up"
	case counts["down"] == len(members):
		edge.OperStatus = "down"
	default:
		edge.OperStatus = "degraded"
	}
}
