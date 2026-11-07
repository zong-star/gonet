package model

import "time"

// LastChange is TimeTicks since SNMP agent initialization, never Unix seconds.
type InterfaceStatus struct {
	AdminStatus           string     `json:"admin_status"`
	OperStatus            string     `json:"oper_status"`
	LastChange            *uint32    `json:"last_change"`
	LastChangeAt          *time.Time `json:"last_change_at"`
	LastChangeState       string     `json:"last_change_state"`
	SysUpTime             uint32     `json:"sys_up_time"`
	StatusCollectedAt     *time.Time `json:"status_collected_at"`
	StatusCollectionState string     `json:"status_collection_state"`
	StatusAttemptedAt     *time.Time `json:"status_attempted_at"`
	StatusError           string     `json:"status_error,omitempty"`
}

type LinkInterfaceStatus struct {
	SourceAdminStatus       string     `json:"source_admin_status"`
	SourceOperStatus        string     `json:"source_oper_status"`
	TargetAdminStatus       string     `json:"target_admin_status"`
	TargetOperStatus        string     `json:"target_oper_status"`
	SourceCollectionState   string     `json:"source_collection_state"`
	TargetCollectionState   string     `json:"target_collection_state"`
	LinkOperStatus          string     `json:"link_oper_status"`
	StatusCollectedAt       *time.Time `json:"status_collected_at"`
	SourceStatusCollectedAt *time.Time `json:"source_status_collected_at"`
	TargetStatusCollectedAt *time.Time `json:"target_status_collected_at"`
}

func LinkStatus(a, b InterfaceStatus, now time.Time, staleAfter time.Duration) LinkInterfaceStatus {
	norm := func(s string) string {
		if s == "" {
			return "unknown"
		}
		return s
	}
	r := LinkInterfaceStatus{SourceAdminStatus: norm(a.AdminStatus), SourceOperStatus: norm(a.OperStatus), TargetAdminStatus: norm(b.AdminStatus), TargetOperStatus: norm(b.OperStatus), SourceCollectionState: norm(a.StatusCollectionState), TargetCollectionState: norm(b.StatusCollectionState), SourceStatusCollectedAt: a.StatusCollectedAt, TargetStatusCollectedAt: b.StatusCollectedAt, LinkOperStatus: "unknown"}
	if a.StatusCollectedAt == nil || b.StatusCollectedAt == nil {
		return r
	}
	r.StatusCollectedAt = a.StatusCollectedAt
	if b.StatusCollectedAt.Before(*r.StatusCollectedAt) {
		r.StatusCollectedAt = b.StatusCollectedAt
	}
	switch {
	case now.Before(*a.StatusCollectedAt) || now.Before(*b.StatusCollectedAt) || now.Sub(*r.StatusCollectedAt) >= staleAfter:
		r.LinkOperStatus = "stale"
	case a.StatusCollectionState != "success" || b.StatusCollectionState != "success":
		r.LinkOperStatus = "unknown"
	case a.AdminStatus == "down" || b.AdminStatus == "down":
		r.LinkOperStatus = "admin_down"
	case a.OperStatus == "testing" || b.OperStatus == "testing" || a.OperStatus == "dormant" || b.OperStatus == "dormant":
	case a.OperStatus == "unknown" || b.OperStatus == "unknown" || a.OperStatus == "" || b.OperStatus == "":
	case a.OperStatus == "up" && b.OperStatus == "up":
		r.LinkOperStatus = "up"
	case a.OperStatus == "up" || b.OperStatus == "up":
		r.LinkOperStatus = "degraded"
	default:
		r.LinkOperStatus = "down"
	}
	return r
}
