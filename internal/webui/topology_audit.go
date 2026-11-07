package webui

import (
	"net/http"
	"time"
)

type topologyAuditWriter struct {
	http.ResponseWriter
	status, count int
}

func (w *topologyAuditWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (s *Server) logTopologyRequest(requestID, caller, route string, deviceID int64, status, count int, started time.Time) {
	target := ""
	if deviceID > 0 {
		target = idString(deviceID)
	}
	if status == 0 {
		status = 499 // The client closed the request before GoNet wrote a response.
	}
	s.auditLogger.Info("topology API request",
		"request_id", requestID, "caller", caller, "route", route, "device_id", target,
		"status", status, "result_count", count, "duration_ms", time.Since(started).Milliseconds())
}

func topologyResultCount(data any) int {
	switch result := data.(type) {
	case *deviceSearchData:
		return len(result.Items)
	case *corePathData:
		return len(result.Paths)
	case *compactNeighborsData:
		return result.ReturnedLinkCount
	case *neighborsV2:
		return result.ReturnedLinkCount
	case *uplinkDataV2:
		if result.Path != nil {
			return 1
		}
		return 0
	case neighborsData:
		return len(result.Items)
	case topologyData:
		return len(result.Devices)
	default:
		return 1
	}
}
