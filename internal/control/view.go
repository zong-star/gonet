package control

import (
	"encoding/hex"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/preprobe"
	"gonet/internal/store/postgres"
	"gonet/internal/topology"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Device struct {
	postgres.ExportDevice
	Name      string `json:"inventory_name"`
	Area      string `json:"area"`
	Vendor    string `json:"vendor"`
	Model     string `json:"model"`
	Status    string `json:"collection_status"`
	MAC       string `json:"chassis_mac"`
	LinkCount int    `json:"link_count"`
	Source    string `json:"discovery_source"`
}

// LabelModels adds display labels from the exact rule that classified a device.
// Inventory labels take precedence and no address-based identity is introduced.
func LabelModels(v *View, rules []identity.Rule) {
	labels := map[string]identity.Rule{}
	for _, rule := range rules {
		labels[rule.ID] = rule
	}
	for i := range v.Devices {
		d := &v.Devices[i]
		if rule, ok := labels[d.ClassificationRule]; ok && d.Source != "inventory" {
			if rule.Model != "" {
				d.Model = rule.Model
			}
			if rule.Vendor != "" {
				d.Vendor = rule.Vendor
			}
		}
	}
	deviceModels := map[int64]string{}
	for _, d := range v.Devices {
		if d.Model != "" && d.Model != "待补充" {
			deviceModels[d.ID] = d.Model
		}
	}
	for i := range v.ProbePool {
		p := &v.ProbePool[i]
		if rule, ok := labels[p.Rule]; ok {
			p.Model = rule.Model
		}
		// Reuse an already verified device association, never an IP/name match.
		if p.Model == "" && !p.Conflict && p.MatchedDeviceID != nil {
			p.Model = deviceModels[*p.MatchedDeviceID]
		}
	}

	classifier, err := identity.NewClassifier(rules)
	if err != nil {
		return
	}
	v.Counts.PendingRouters, v.Counts.PendingControllers = 0, 0
	for i := range v.Candidates {
		n := &v.Candidates[i]
		c := classifier.ClassifyAdvertisement(n.Description, nil, nil)
		n.Kind = c.CandidateKind
		if c.Managed() {
			n.Kind = c.Result
		}
		if label, ok := labels[c.RuleID]; ok {
			n.Model = label.Model
		}
		if n.Kind == "router" {
			v.Counts.PendingRouters++
		}
		if n.Kind == "wireless_controller" {
			v.Counts.PendingControllers++
		}
	}
}

func KindLabel(kind string) string {
	switch kind {
	case "router":
		return "路由器"
	case "wireless_controller":
		return "无线 AC"
	case "switch", "":
		return "交换机"
	default:
		return "待识别"
	}
}

type Counts struct {
	Inventory          int `json:"inventory"`
	Confirmed          int `json:"confirmed"`
	Collected          int `json:"collected_this_scan"`
	Historical         int `json:"historical_only"`
	Unconfirmed        int `json:"unconfirmed"`
	Neighbors          int `json:"unconfirmed_neighbor_records"`
	Switches           int `json:"switches"`
	Routers            int `json:"routers"`
	Controllers        int `json:"wireless_controllers"`
	PendingRouters     int `json:"pending_routers"`
	PendingControllers int `json:"pending_wireless_controllers"`
}
type InventoryStatus struct {
	Row      int    `json:"row"`
	Area     string `json:"area"`
	Name     string `json:"name"`
	Address  string `json:"address"`
	Model    string `json:"model"`
	DeviceID *int64 `json:"device_id"`
	Observed bool   `json:"observed_this_scan"`
	Status   string `json:"status"`
}
type Candidate struct {
	Verification        model.VerificationDetails `json:"verification"`
	ManagementAddresses []netip.Addr              `json:"reported_management_addresses,omitempty"`
	Key                 string                    `json:"key"`
	Name                string                    `json:"system_name"`
	Subtype             uint8                     `json:"chassis_subtype"`
	RawHex              string                    `json:"chassis_hex"`
	ObservedBy          []string                  `json:"observed_by"`
	ObservedAt          time.Time                 `json:"observed_at"`
	Status              string                    `json:"status"`
	Kind                string                    `json:"device_kind,omitempty"`
	Model               string                    `json:"model,omitempty"`
	Description         string                    `json:"system_description,omitempty"`
	ObserverIDs         []int64                   `json:"observed_by_ids"`
}
type View struct {
	InferenceStaleAfter  time.Duration              `json:"-"`
	ProbePool            []Probe                    `json:"probe_pool"`
	ProbeSummary         preprobe.Summary           `json:"probe_summary"`
	SchemaVersion        int                        `json:"schema_version"`
	GeneratedAt          time.Time                  `json:"generated_at"`
	LatestScanID         int64                      `json:"latest_scan_id"`
	LatestScanStatus     string                     `json:"latest_scan_status"`
	LatestScanFinishedAt *time.Time                 `json:"latest_scan_finished_at,omitempty"`
	Fresh                bool                       `json:"fresh"`
	CoverageGap          bool                       `json:"coverage_gap"`
	Devices              []Device                   `json:"devices"`
	Links                []postgres.ExportLink      `json:"links"`
	PendingNodes         []topology.PendingNode     `json:"pending_nodes"`
	PendingLinks         []topology.PendingLink     `json:"pending_links"`
	Candidates           []Candidate                `json:"neighbor_candidates"`
	Counts               Counts                     `json:"device_counts"`
	Inventory            []InventoryStatus          `json:"inventory_devices"`
	CoreIDs              []int64                    `json:"core_ids"`
	Evidence             *postgres.TopologyEvidence `json:"-"`
	CandidateLinks       []topology.PendingLink     `json:"-"`
}

func Project(exp *postgres.TopologyExport, s Scope) *View {
	v := &View{SchemaVersion: 1, GeneratedAt: exp.GeneratedAt, LatestScanID: exp.LatestScanID, LatestScanStatus: exp.LatestScanStatus, LatestScanFinishedAt: exp.LatestScanFinishedAt, Fresh: exp.Fresh, CoverageGap: exp.CoverageGap, Devices: []Device{}, Links: []postgres.ExportLink{}, PendingNodes: []topology.PendingNode{}, PendingLinks: []topology.PendingLink{}, Candidates: []Candidate{}, Inventory: []InventoryStatus{}, CoreIDs: []int64{}}
	v.ProbePool = projectProbes(exp, s)
	v.ProbeSummary = exp.ProbeSummary
	rows := map[string]InventoryRow{}
	excluded := s.ExcludedKeys()
	for _, r := range s.Rows {
		if r.Included {
			v.Counts.Inventory++
			for _, k := range r.IdentityKeys {
				rows[k] = r
			}
		}
	}
	kept := map[int64]*Device{}
	found := map[int]Device{}
	modelLabels := map[string]InventoryRow{}
	for _, d := range exp.Devices {
		for _, k := range d.IdentityKeys {
			if row, ok := rows[k]; ok && row.Model != "" {
				modelLabels[d.ClassificationRule] = row
			}
		}
	}
	for _, d := range exp.Devices {
		deny := false
		var row InventoryRow
		for _, k := range d.IdentityKeys {
			deny = deny || excluded[k]
			if r, ok := rows[k]; ok {
				row = r
			}
		}
		allowed := false
		for _, raw := range d.AccessAddresses {
			if a, e := netip.ParseAddr(raw); e == nil && s.Settings.Allows(a) {
				allowed = true
			}
		}
		if deny || !allowed {
			continue
		}
		x := Device{ExportDevice: d, Name: d.SysName, Area: "自动发现", Vendor: "未知", Model: "待补充", Status: "historical", Source: "lldp"}
		if x.Kind == "" {
			x.Kind = "switch"
		}
		switch x.Kind {
		case "switch":
			v.Counts.Switches++
		case "router":
			v.Counts.Routers++
		case "wireless_controller":
			v.Counts.Controllers++
		}
		if row.Name != "" {
			x.Name = row.Name
			x.Area = row.Area
			x.Vendor = row.Vendor
			x.Model = row.Model
			x.Source = "inventory"
		}
		if row.Name == "" {
			if label, ok := modelLabels[d.ClassificationRule]; ok {
				x.Model = label.Model
				x.Vendor = label.Vendor
			}
		}
		if x.Name == "" || x.Name == "(none)" {
			x.Name = "交换机 #" + strconv.FormatInt(d.ID, 10)
		}
		if d.DiscoveryDepth != nil {
			x.Status = "collected"
			v.Counts.Collected++
		} else {
			v.Counts.Historical++
		}
		for _, k := range d.IdentityKeys {
			p := strings.Split(k, ":")
			if len(p) == 3 && (p[1] == "4" || p[1] == "7") && len(p[2]) == 12 {
				x.MAC = p[2]
				break
			}
		}
		if x.Vendor == "未知" {
			if strings.Contains(d.SysObjectID, ".25506.") {
				x.Vendor = "H3C"
			}
			if strings.Contains(d.SysObjectID, ".2011.") {
				x.Vendor = "Huawei"
			}
			if strings.HasSuffix(d.SysObjectID, ".45577") {
				x.Vendor = "Sundray"
			}
		}
		v.Devices = append(v.Devices, x)
		if row.Row != 0 {
			found[row.Row] = x
		}
	}
	for i := range v.Devices {
		d := &v.Devices[i]
		kept[d.ID] = d
		for _, addr := range d.AccessAddresses {
			for _, seed := range s.Settings.Seeds {
				if addr == seed {
					v.CoreIDs = append(v.CoreIDs, d.ID)
				}
			}
		}
	}
	for _, l := range exp.Links {
		if kept[l.DeviceAID] != nil && kept[l.DeviceBID] != nil {
			l.DeviceAName = kept[l.DeviceAID].Name
			l.DeviceBName = kept[l.DeviceBID].Name
			v.Links = append(v.Links, l)
			kept[l.DeviceAID].LinkCount++
			kept[l.DeviceBID].LinkCount++
		}
	}
	for _, p := range exp.PendingLinks {
		if kept[int64(p.LocalDevice)] != nil && kept[int64(p.RemoteDevice)] != nil {
			v.PendingLinks = append(v.PendingLinks, p)
		}
		if exp.Evidence != nil && !excluded[p.RemoteKey] && kept[int64(p.LocalDevice)] != nil &&
			(p.RemoteDevice == 0 || kept[int64(p.RemoteDevice)] != nil) {
			v.CandidateLinks = append(v.CandidateLinks, p)
		}
	}
	if exp.Evidence != nil {
		v.Evidence = &postgres.TopologyEvidence{Links: map[int64]postgres.PhysicalLinkEvidence{}, LAG: map[int64]postgres.DeviceLAGEvidence{},
			LatestScan: exp.Evidence.LatestScan, Collection: exp.Evidence.Collection, DeviceCoverage: map[int64]postgres.DeviceScanCoverage{}}
		if exp.Evidence.Collection != nil {
			collection := *exp.Evidence.Collection
			collection.Targets = []postgres.CollectionTarget{}
			for _, target := range exp.Evidence.Collection.Targets {
				address, err := netip.ParseAddr(target.Address)
				if err != nil || !s.Settings.Allows(address) || (target.DeviceID != 0 && kept[target.DeviceID] == nil) {
					continue
				}
				collection.Targets = append(collection.Targets, target)
			}
			v.Evidence.Collection = &collection
		}
		for _, link := range v.Links {
			if evidence, ok := exp.Evidence.Links[link.ID]; ok {
				v.Evidence.Links[link.ID] = evidence
			}
		}
		for id := range kept {
			if evidence, ok := exp.Evidence.LAG[id]; ok {
				v.Evidence.LAG[id] = evidence
			}
			if coverage, ok := exp.Evidence.DeviceCoverage[id]; ok {
				v.Evidence.DeviceCoverage[id] = coverage
			}
		}
	}
	for _, n := range exp.PendingNodes {
		if excluded[n.Key] {
			continue
		}
		sources := map[string]bool{}
		sourceIDs := map[int64]bool{}
		var at time.Time
		for _, p := range exp.PendingLinks {
			if p.RemoteKey == n.Key && kept[int64(p.LocalDevice)] != nil {
				sources[kept[int64(p.LocalDevice)].Name] = true
				sourceIDs[int64(p.LocalDevice)] = true
				if p.ObservedAt.After(at) {
					at = p.ObservedAt
				}
			}
		}
		if len(sources) == 0 {
			continue
		}
		ids := []int64{}
		for id := range sourceIDs {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		v.Candidates = append(v.Candidates, Candidate{Verification: n.Verification, ManagementAddresses: n.ManagementAddresses, Key: n.Key, Name: n.SystemName, Subtype: n.Chassis.Subtype, RawHex: hex.EncodeToString(n.Chassis.Raw), ObservedBy: SortedKeys(sources), ObservedAt: at, Status: n.Status, Description: n.SystemDescription, ObserverIDs: ids})
	}
	for _, r := range s.Rows {
		if !r.Included {
			continue
		}
		d, ok := found[r.Row]
		x := InventoryStatus{Row: r.Row, Area: r.Area, Name: r.Name, Address: r.Address, Model: r.Model, Status: "unconfirmed"}
		if ok {
			x.DeviceID = &d.ID
			x.Status = d.Status
			x.Observed = d.DiscoveryDepth != nil
		} else {
			v.Counts.Unconfirmed++
		}
		v.Inventory = append(v.Inventory, x)
	}
	sort.Slice(v.CoreIDs, func(i, j int) bool { return v.CoreIDs[i] < v.CoreIDs[j] })
	v.Counts.Confirmed = len(v.Devices)
	v.Counts.Neighbors = len(v.Candidates)
	return v
}
