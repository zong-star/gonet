package control

import "gonet/internal/store/postgres"

// CurrentGraphView derives a current-only copy without modifying inventory or
// lifecycle history. A committed empty snapshot stays empty.
func CurrentGraphView(v *View) *View {
	out := *v
	out.Links = []postgres.ExportLink{}
	out.Devices = []Device{}
	out.CoreIDs = []int64{}
	out.Candidates = []Candidate{}
	visible := map[int64]bool{}
	for _, d := range v.Devices {
		visible[d.ID] = true
	}
	keep := map[int64]bool{}
	valid := v.LatestScanID > 0 && v.LatestScanFinishedAt != nil && (v.LatestScanStatus == "completed" || v.LatestScanStatus == "partial")
	if valid {
		for _, l := range v.Links {
			if l.DiscoveryState == "active" && l.LastSeenScanID != nil && *l.LastSeenScanID == v.LatestScanID && visible[l.DeviceAID] && visible[l.DeviceBID] {
				out.Links = append(out.Links, l)
				keep[l.DeviceAID], keep[l.DeviceBID] = true, true
			}
		}
		for _, d := range v.Devices {
			collected := d.Status == "collected"
			if v.Evidence != nil && v.Evidence.DeviceCoverage != nil {
				coverage := v.Evidence.DeviceCoverage[d.ID]
				collected = coverage.Outcome == "success" || coverage.Outcome == "partial"
			}
			if collected {
				keep[d.ID] = true
			}
		}
		out.Candidates = append(out.Candidates, v.Candidates...)
	}
	for _, id := range v.CoreIDs {
		if visible[id] {
			out.CoreIDs = append(out.CoreIDs, id)
			keep[id] = true
		}
	}
	for _, d := range v.Devices {
		if keep[d.ID] {
			out.Devices = append(out.Devices, d)
		}
	}
	return &out
}
