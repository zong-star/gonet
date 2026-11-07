package model

import (
	"testing"
	"time"
)

func TestLinkInterfaceStatus(t *testing.T) {
	now := time.Now().UTC()
	old := now.Add(-13 * time.Minute)
	a := InterfaceStatus{AdminStatus: "up", OperStatus: "up", StatusCollectionState: "success", StatusCollectedAt: &now}
	for _, tt := range []struct {
		name               string
		admin, oper, state string
		at                 *time.Time
		want               string
	}{
		{"up", "up", "up", "success", &now, "up"}, {"one_down", "up", "down", "success", &now, "degraded"}, {"admin", "down", "down", "success", &now, "admin_down"}, {"failed", "up", "up", "failed", &now, "unknown"}, {"expired", "up", "up", "success", &old, "stale"}, {"no_sample", "up", "up", "failed", nil, "unknown"}, {"unknown", "up", "unknown", "success", &now, "unknown"}, {"testing", "up", "testing", "success", &now, "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			b := a
			b.AdminStatus = tt.admin
			b.OperStatus = tt.oper
			b.StatusCollectionState = tt.state
			b.StatusCollectedAt = tt.at
			if r := LinkStatus(a, b, now, 12*time.Minute); r.LinkOperStatus != tt.want {
				t.Fatalf("%+v", r)
			}
		})
	}
	a.OperStatus = "down"
	if r := LinkStatus(a, a, now, 12*time.Minute); r.LinkOperStatus != "down" {
		t.Fatal(r)
	}
}
