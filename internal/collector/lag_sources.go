package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/gosnmp/gosnmp"
	"gonet/internal/collector/lldp"
	"gonet/internal/collector/oidutil"
	"gonet/internal/collector/snmp"
	"gonet/internal/model"
	"gonet/internal/topology"
)

const HuaweiLAGAdapter = "huawei_s5735_qa2_v200r023_lag"
const H3CLAGAdapter = "h3c_s5560_6628p47_lag"
const LLDPDot3LAGAdapter = "lldp_dot3_lag"
const hwTrunkIfIndex = "1.3.6.1.4.1.2011.5.25.41.1.3.3.1.4"
const hwTrunkValid = "1.3.6.1.4.1.2011.5.25.41.1.4.1.1.2"
const hh3cMode = "1.3.6.1.4.1.25506.8.25.1.1.1.3"
const hh3cMembers = "1.3.6.1.4.1.25506.8.25.1.1.1.4"
const hh3cSelected = "1.3.6.1.4.1.25506.8.25.1.1.1.6"
const locLinkAgg = "1.0.8802.1.1.2.1.5.4623.1.2.3"
const remLinkAgg = "1.0.8802.1.1.2.1.5.4623.1.3.3"

func (c *Collector) lagWalk(sess *snmp.Session, ctx context.Context, snap *model.DeviceSnapshot, source, adapter, root string) ([]gosnmp.SnmpPDU, snmp.WalkSummary, error) {
	start := time.Now()
	rows, sum, err := c.walk(sess, ctx, root)
	status := componentStatus(sum, err, err == nil, len(rows) > 0)
	status.State = "observed"
	if len(rows) == 0 {
		status.State = "empty_unverified"
	}
	if err != nil {
		status.State = "unavailable"
	}
	status.Requests, status.VarbindCount, status.ElapsedMS = sum.Requests, len(rows), time.Since(start).Milliseconds()
	facts := make([]model.LAGFact, 0, len(rows))
	retained := 0
	for _, source := range snap.LAGEvidence {
		b, _ := json.Marshal(source.Facts)
		retained += len(b)
	}
	for _, p := range rows {
		fact := model.LAGFact{OID: p.Name, Type: p.Type.String(), Value: p.Value}
		b, _ := json.Marshal(fact)
		retained += len(b)
		if retained > 1<<20 {
			err = fmt.Errorf("COLLECTION_BUDGET_EXCEEDED: LAG evidence exceeds 1 MiB")
			rows = nil
			status.State = "unavailable"
			status.WalkComplete = false
			status.Issues = append(status.Issues, model.Issue{Code: "COLLECTION_BUDGET_EXCEEDED", Component: source, Message: "LAG evidence exceeds 1 MiB"})
			break
		}
		facts = append(facts, fact)
	}
	snap.LAGEvidence = append(snap.LAGEvidence, model.LAGEvidence{Source: source, AdapterID: adapter, Root: root, CollectedAt: start.UTC(), Status: status, Facts: facts})
	snap.Components[source] = status
	return rows, sum, err
}

func enabled(names []string, name string) bool { return slices.Contains(names, name) }
func huaweiLAGDevice(d model.DeviceInfo) bool {
	return strings.TrimPrefix(d.SysObjectID, ".") == "1.3.6.1.4.1.2011.2.23.967" && firmwareToken(d.SysDescription, "S5735-L8T4S-QA2") && firmwareToken(d.SysDescription, "V200R023C00SPC500")
}
func h3cLAGDevice(d model.DeviceInfo) bool {
	return strings.TrimPrefix(d.SysObjectID, ".") == "1.3.6.1.4.1.25506.1.1460" && firmwareToken(d.SysDescription, "S5560X-30C-EI") && firmwareToken(d.SysDescription, "6628P47")
}
func firmwareToken(description, token string) bool {
	return slices.Contains(strings.FieldsFunc(description, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '.' }), token)
}
func lagIssue(snap *model.DeviceSnapshot, code, message string) {
	s := snap.Components["lag_membership"]
	s.Issues = append(s.Issues, model.Issue{Code: code, Component: "lag_membership", Message: message})
	s.DecodeComplete = false
	s.WalkComplete = false
	snap.Components["lag_membership"] = s
}

func (c *Collector) collectLAGSources(ctx context.Context, s *snmp.Session, snap *model.DeviceSnapshot) {
	if enabled(c.opts.Adapters, HuaweiLAGAdapter) && huaweiLAGDevice(snap.Device) {
		c.collectHuaweiLAG(ctx, s, snap)
	}
	if enabled(c.opts.Adapters, H3CLAGAdapter) && h3cLAGDevice(snap.Device) {
		c.collectH3CLAG(ctx, s, snap)
	}
	if enabled(c.opts.Adapters, LLDPDot3LAGAdapter) {
		c.collectLAGAdvertisements(ctx, s, snap)
	}
	// Optional protocol facts never create membership by themselves.
	if len(snap.LAGMembers) > 0 && ctx.Err() == nil {
		c.collectLACP(ctx, s, snap)
	}
}

func integerInstances(root string, rows []gosnmp.SnmpPDU, size int) (map[string]uint32, error) {
	out := map[string]uint32{}
	for _, p := range rows {
		idx, e := oidutil.Suffix(root, p.Name)
		v, ve := lldp.AsUint32(p)
		if e != nil || ve != nil || len(idx) != size {
			return nil, fmt.Errorf("invalid numeric instance under %s", root)
		}
		for _, x := range idx {
			if x > math.MaxInt32 {
				return nil, fmt.Errorf("index outside interface namespace")
			}
		}
		parts := make([]string, len(idx))
		for i, x := range idx {
			parts[i] = fmt.Sprint(x)
		}
		key := strings.Join(parts, ".")
		if _, ok := out[key]; ok {
			return nil, fmt.Errorf("duplicate instance")
		}
		out[key] = v
	}
	return out, nil
}

func parseHuaweiLAG(snap *model.DeviceSnapshot, groups, members []gosnmp.SnmpPDU) ([]model.LAGGroup, []model.LAGMember, error) {
	g, e := integerInstances(hwTrunkIfIndex, groups, 1)
	if e != nil {
		return nil, nil, e
	}
	m, e := integerInstances(hwTrunkValid, members, 2)
	if e != nil {
		return nil, nil, e
	}
	ifaces := map[int32]model.Interface{}
	for _, i := range snap.Interfaces {
		ifaces[i.IfIndex] = i
	}
	var gs []model.LAGGroup
	var ms []model.LAGMember
	for key, index := range g {
		if index == 0 || index > math.MaxInt32 {
			return nil, nil, fmt.Errorf("GROUP_INDEX_UNMAPPED")
		}
		i, ok := ifaces[int32(index)]
		if !ok || topology.IsPhysicalIfType(i.Type) || i.Type != 53 && i.Type != 161 {
			return nil, nil, fmt.Errorf("UNSUPPORTED_INTERFACE_ROLE")
		}
		x := int32(index)
		gs = append(gs, model.LAGGroup{SourceGroupID: "huawei:" + key, AggregateIfIndex: &x, Source: "huawei_private", Mode: "unknown"})
	}
	for key, valid := range m {
		if valid != 1 && valid != 2 {
			return nil, nil, fmt.Errorf("invalid Huawei row status")
		}
		if valid != 1 {
			continue
		}
		parts := strings.Split(key, ".")
		aggregate, ok := g[parts[0]]
		if !ok {
			return nil, nil, fmt.Errorf("GROUP_INDEX_UNMAPPED")
		}
		var member int32
		_, e = fmt.Sscan(parts[1], &member)
		if e != nil || !topology.IsPhysicalIfType(ifaces[member].Type) || member == int32(aggregate) {
			return nil, nil, fmt.Errorf("MEMBER_INDEX_UNMAPPED")
		}
		yes := true
		ms = append(ms, model.LAGMember{AggregateIfIndex: int32(aggregate), MemberIfIndex: member, Source: "huawei_private", Sources: []string{"huawei_private"}, Mode: "unknown", Status: "confirmed", Configured: &yes})
	}
	return gs, ms, nil
}

func (c *Collector) collectHuaweiLAG(ctx context.Context, s *snmp.Session, snap *model.DeviceSnapshot) {
	guards := []string{lldp.SysUpTime}
	before, be := c.getMap(s, ctx, guards)
	g, _, ge := c.lagWalk(s, ctx, snap, "huawei_groups", HuaweiLAGAdapter, hwTrunkIfIndex)
	m, _, me := c.lagWalk(s, ctx, snap, "huawei_members", HuaweiLAGAdapter, hwTrunkValid)
	// This exact firmware has no standard lastChange. Two complete equal reads
	// and monotonic uptime validate positive facts; absence stays conservative.
	g2, _, g2e := c.lagWalk(s, ctx, snap, "huawei_groups_check", HuaweiLAGAdapter, hwTrunkIfIndex)
	m2, _, m2e := c.lagWalk(s, ctx, snap, "huawei_members_check", HuaweiLAGAdapter, hwTrunkValid)
	after, ae := c.getMap(s, ctx, guards)
	u1, ok1 := scalarTicks(before, lldp.SysUpTime)
	u2, ok2 := scalarTicks(after, lldp.SysUpTime)
	if be != nil || ge != nil || me != nil || g2e != nil || m2e != nil || ae != nil || !ok1 || !ok2 || u1 < snap.Device.UptimeAfter || u2 < u1 {
		lagIssue(snap, "SNAPSHOT_UNSTABLE", "Huawei LAG source could not be read consistently")
		return
	}
	ga, e1 := integerInstances(hwTrunkIfIndex, g, 1)
	gb, e2 := integerInstances(hwTrunkIfIndex, g2, 1)
	ma, e3 := integerInstances(hwTrunkValid, m, 2)
	mb, e4 := integerInstances(hwTrunkValid, m2, 2)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || !maps.Equal(ga, gb) || !maps.Equal(ma, mb) {
		lagIssue(snap, "SNAPSHOT_UNSTABLE", "Huawei LAG tables changed or could not be decoded")
		return
	}
	groups, members, e := parseHuaweiLAG(snap, g, m)
	if e != nil {
		lagIssue(snap, "LAG_DECODE", e.Error())
		return
	}
	for i := range groups {
		known := false
		for _, m := range members {
			if groups[i].AggregateIfIndex != nil && m.AggregateIfIndex == *groups[i].AggregateIfIndex {
				known = true
			}
		}
		groups[i].Complete = known && c.opts.ViewVerified && snap.Components["if_mib"].WalkComplete && snap.Components["if_mib"].DecodeComplete
	}
	snap.LAGGroups = append(snap.LAGGroups, groups...)
	snap.LAGMembers = append(snap.LAGMembers, members...)
}

func bitmapPorts(p gosnmp.SnmpPDU) ([]int32, error) {
	b, e := lldp.AsBytes(p)
	if e != nil || len(b) > 255 {
		return nil, fmt.Errorf("invalid member bitmap")
	}
	var out []int32
	for i, x := range b {
		for bit := 0; bit < 8; bit++ {
			if x&(0x80>>bit) != 0 {
				out = append(out, int32(i*8+bit+1))
			}
		}
	}
	return out, nil
}
func (c *Collector) collectH3CLAG(ctx context.Context, s *snmp.Session, snap *model.DeviceSnapshot) {
	before, be := c.getMap(s, ctx, []string{lldp.SysUpTime, lagLastChange})
	modes, _, a := c.lagWalk(s, ctx, snap, "h3c_modes", H3CLAGAdapter, hh3cMode)
	ports, _, b := c.lagWalk(s, ctx, snap, "h3c_members", H3CLAGAdapter, hh3cMembers)
	selected, _, d := c.lagWalk(s, ctx, snap, "h3c_selected", H3CLAGAdapter, hh3cSelected)
	after, ae := c.getMap(s, ctx, []string{lldp.SysUpTime, lagLastChange})
	u1, o1 := scalarTicks(before, lldp.SysUpTime)
	u2, o2 := scalarTicks(after, lldp.SysUpTime)
	if be != nil || a != nil || b != nil || d != nil || ae != nil || !o1 || !o2 || u1 < snap.Device.UptimeAfter || u2 < u1 || !lagGuardStable(before, after, lagLastChange, snap.Device.UptimeBefore) {
		return
	}
	if err := applyH3CLAG(snap, modes, ports, selected); err != nil {
		lagIssue(snap, "LAG_DECODE", err.Error())
	}
}
func applyH3CLAG(snap *model.DeviceSnapshot, modes, ports, selected []gosnmp.SnmpPDU) error {
	m, err := integerInstances(hh3cMode, modes, 1)
	if err != nil {
		return err
	}
	sets := map[string][]int32{}
	sel := map[string][]int32{}
	for _, src := range []struct {
		root string
		rows []gosnmp.SnmpPDU
		dest map[string][]int32
	}{{hh3cMembers, ports, sets}, {hh3cSelected, selected, sel}} {
		for _, p := range src.rows {
			idx, e := oidutil.Suffix(src.root, p.Name)
			v, ve := bitmapPorts(p)
			if e != nil || ve != nil || len(idx) != 1 {
				return fmt.Errorf("invalid H3C group bitmap")
			}
			src.dest[fmt.Sprint(idx[0])] = v
		}
	}
	// Verified firmware bit positions map to physical ifIndex. Match the entire
	// member set to standard membership, never a group number or interface name.
	byAgg := map[int32][]int32{}
	for _, member := range snap.LAGMembers {
		byAgg[member.AggregateIfIndex] = append(byAgg[member.AggregateIfIndex], member.MemberIfIndex)
	}
	for _, v := range byAgg {
		slices.Sort(v)
	}
	for group, set := range sets {
		var matches []int32
		for agg, known := range byAgg {
			if len(set) > 0 && slices.Equal(set, known) {
				matches = append(matches, agg)
			}
		}
		if len(matches) != 1 {
			continue
		}
		mode := "unknown"
		switch m[group] {
		case 2:
			mode = "static"
		case 3:
			mode = "lacp"
		}
		agg := matches[0]
		coverage := snap.Components["lag_membership"]
		snap.LAGGroups = append(snap.LAGGroups, model.LAGGroup{SourceGroupID: "h3c:" + group, AggregateIfIndex: &agg, Source: "h3c_private", Mode: mode, Complete: coverage.Supported && coverage.WalkComplete && coverage.DecodeComplete})
		for i := range snap.LAGMembers {
			r := &snap.LAGMembers[i]
			if r.AggregateIfIndex != agg {
				continue
			}
			yes := true
			r.Configured = &yes
			r.Sources = append(r.Sources, "h3c_private")
			if _, ok := sel[group]; ok {
				v := slices.Contains(sel[group], r.MemberIfIndex)
				r.Selected = &v
			}
			if r.Mode != "unknown" && mode != "unknown" && r.Mode != mode {
				r.Status = "conflict"
			} else if mode != "unknown" {
				r.Mode = mode
			}
		}
	}
	return nil
}

func parseLAGAdvertisements(snap *model.DeviceSnapshot, root, direction string, rows []gosnmp.SnmpPDU) ([]model.LAGAdvertisement, error) {
	type row struct {
		status []byte
		id     *uint32
	}
	data := map[model.NeighborIndex]row{}
	for _, p := range rows {
		idx, e := oidutil.Suffix(root, p.Name)
		size := 3
		if direction == "remote" {
			size = 5
		}
		if e != nil || len(idx) != size || idx[0] != 1 || idx[1] < 1 || idx[1] > 2 {
			return nil, fmt.Errorf("invalid LLDP LAG instance")
		}
		key := model.NeighborIndex{LocalPortNum: idx[2]}
		if direction == "remote" {
			key = model.NeighborIndex{TimeMark: idx[2], LocalPortNum: idx[3], RemoteIndex: idx[4]}
		}
		r := data[key]
		if idx[1] == 1 {
			v, err := lldp.AsBytes(p)
			if err != nil || len(v) != 1 {
				return nil, fmt.Errorf("invalid LLDP LAG status")
			}
			r.status = v
		} else {
			v, err := lldp.AsUint32(p)
			if err != nil {
				return nil, err
			}
			r.id = &v
		}
		data[key] = r
	}
	var out []model.LAGAdvertisement
	for key, r := range data {
		if r.id == nil || len(r.status) != 1 {
			continue
		}
		var index *int32
		for _, p := range snap.LocalPorts {
			if p.Number == key.LocalPortNum {
				index = p.IfIndex
				break
			}
		}
		out = append(out, model.LAGAdvertisement{Direction: direction, Index: key, MemberIfIndex: index, AggregateID: *r.id, Capable: r.status[0]&0x80 != 0, Enabled: r.status[0]&0x40 != 0, RawStatus: r.status})
	}
	slices.SortFunc(out, func(a, b model.LAGAdvertisement) int {
		if a.Index.LocalPortNum < b.Index.LocalPortNum {
			return -1
		}
		if a.Index.LocalPortNum > b.Index.LocalPortNum {
			return 1
		}
		if a.Index.TimeMark < b.Index.TimeMark {
			return -1
		}
		if a.Index.TimeMark > b.Index.TimeMark {
			return 1
		}
		if a.Index.RemoteIndex < b.Index.RemoteIndex {
			return -1
		}
		if a.Index.RemoteIndex > b.Index.RemoteIndex {
			return 1
		}
		return 0
	})
	return out, nil
}
func (c *Collector) collectLAGAdvertisements(ctx context.Context, s *snmp.Session, snap *model.DeviceSnapshot) {
	guards := []string{lldp.SysUpTime, lldp.LldpStatsRemTablesLastChangeTime}
	before, be := c.getMap(s, ctx, guards)
	local, _, le := c.lagWalk(s, ctx, snap, "lldp_lag_local", LLDPDot3LAGAdapter, locLinkAgg)
	remote, _, re := c.lagWalk(s, ctx, snap, "lldp_lag_remote", LLDPDot3LAGAdapter, remLinkAgg)
	after, ae := c.getMap(s, ctx, guards)
	u1, o1 := scalarTicks(before, lldp.SysUpTime)
	u2, o2 := scalarTicks(after, lldp.SysUpTime)
	t1, tok1 := scalarTicks(before, lldp.LldpStatsRemTablesLastChangeTime)
	t2, tok2 := scalarTicks(after, lldp.LldpStatsRemTablesLastChangeTime)
	if be != nil || ae != nil || !o1 || !o2 || u2 < u1 || !tok1 || !tok2 || t1 != t2 || t1 != snap.Device.LastChangeAfter {
		return
	}
	for _, src := range []struct {
		root, dir string
		rows      []gosnmp.SnmpPDU
		err       error
	}{{locLinkAgg, "local", local, le}, {remLinkAgg, "remote", remote, re}} {
		if src.err != nil {
			continue
		}
		ads, e := parseLAGAdvertisements(snap, src.root, src.dir, src.rows)
		if e != nil {
			lagIssue(snap, "LAG_DECODE", e.Error())
			continue
		}
		snap.LAGAdvertisements = append(snap.LAGAdvertisements, ads...)
	}
}

func (c *Collector) collectLACP(ctx context.Context, s *snmp.Session, snap *model.DeviceSnapshot) {
	guards := []string{lldp.SysUpTime, lagLastChange}
	before, be := c.getMap(s, ctx, guards)
	// Membership remains useful if optional protocol details exceed the budget.
	for _, root := range []string{"1.2.840.10006.300.43.1.1.1.1.10"} {
		if ctx.Err() != nil {
			break
		}
		c.lagWalk(s, ctx, snap, "ieee_lag_groups", "", root)
	}
	byPort := map[int32]*model.LACPPort{}
	for _, col := range []int{12, 3, 5, 9, 11, 14, 17, 21, 23} {
		if ctx.Err() != nil {
			break
		}
		root := fmt.Sprintf("1.2.840.10006.300.43.1.2.1.1.%d", col)
		rows, _, err := c.lagWalk(s, ctx, snap, "lacp_protocol", "", root)
		if err != nil {
			continue
		}
		for _, p := range rows {
			idx, e := oidutil.Suffix(root, p.Name)
			if e != nil || len(idx) != 1 || idx[0] == 0 || idx[0] > math.MaxInt32 {
				continue
			}
			index := int32(idx[0])
			if byPort[index] == nil {
				byPort[index] = &model.LACPPort{MemberIfIndex: index}
			}
			r := byPort[index]
			switch col {
			case 5, 11, 12, 14, 17:
				v, e := lldp.AsUint32(p)
				if e != nil || col != 12 && v > 65535 || col == 12 && v > math.MaxInt32 {
					continue
				}
				switch col {
				case 5:
					r.ActorKey = &v
				case 11:
					r.PartnerKey = &v
				case 12:
					r.SelectedAggID = &v
				case 14:
					r.ActorPort = &v
				case 17:
					r.PartnerPort = &v
				}
			default:
				v, e := lldp.AsBytes(p)
				if e != nil {
					continue
				}
				switch col {
				case 3:
					r.ActorSystem = v
				case 9:
					r.PartnerSystem = v
				case 21:
					r.ActorState = v
				case 23:
					r.PartnerState = v
				}
			}
		}
	}
	after, ae := c.getMap(s, ctx, guards)
	u1, o1 := scalarTicks(before, lldp.SysUpTime)
	u2, o2 := scalarTicks(after, lldp.SysUpTime)
	_, hasGuard := scalarTicks(before, lagLastChange)
	stable := be == nil && ae == nil && o1 && o2 && u2 >= u1 && u1 >= snap.Device.UptimeAfter && hasGuard && lagGuardStable(before, after, lagLastChange, snap.Device.UptimeBefore)
	for _, p := range byPort {
		p.Stable = stable
		if stable && p.SelectedAggID != nil {
			for i := range snap.LAGMembers {
				r := &snap.LAGMembers[i]
				if r.MemberIfIndex == p.MemberIfIndex {
					selected := uint32(r.AggregateIfIndex) == *p.SelectedAggID
					if r.Selected != nil && *r.Selected != selected {
						r.Status = "conflict"
					}
					r.Selected = &selected
				}
			}
		}
		snap.LACPPorts = append(snap.LACPPorts, *p)
	}
	slices.SortFunc(snap.LACPPorts, func(a, b model.LACPPort) int { return int(a.MemberIfIndex - b.MemberIfIndex) })
}

func reconcileLAG(snap *model.DeviceSnapshot) {
	type key struct{ agg, member int32 }
	known := map[key]model.LAGMember{}
	owners := map[int32]map[int32]bool{}
	for _, r := range snap.LAGMembers {
		k := key{r.AggregateIfIndex, r.MemberIfIndex}
		if prev, ok := known[k]; ok {
			r.Sources = append(r.Sources, prev.Sources...)
			if prev.Status == "conflict" || prev.Mode != "unknown" && r.Mode != "unknown" && prev.Mode != r.Mode {
				r.Status = "conflict"
			}
			if r.Mode == "unknown" {
				r.Mode = prev.Mode
			}
			if r.Selected == nil {
				r.Selected = prev.Selected
			}
			if r.Attached == nil {
				r.Attached = prev.Attached
			}
			if r.Configured == nil {
				r.Configured = prev.Configured
			}
		}
		slices.Sort(r.Sources)
		r.Sources = slices.Compact(r.Sources)
		known[k] = r
		if owners[r.MemberIfIndex] == nil {
			owners[r.MemberIfIndex] = map[int32]bool{}
		}
		owners[r.MemberIfIndex][r.AggregateIfIndex] = true
	}

	snap.LAGMembers = nil
	for _, r := range known {
		if len(owners[r.MemberIfIndex]) > 1 {
			r.Status = "conflict"
		}
		if r.Status == "conflict" {
			lagIssue(snap, "MEMBERSHIP_CONFLICT", fmt.Sprintf("member ifIndex %d has conflicting evidence", r.MemberIfIndex))
		}
		snap.LAGMembers = append(snap.LAGMembers, r)
	}
	slices.SortFunc(snap.LAGMembers, func(a, b model.LAGMember) int {
		if a.MemberIfIndex != b.MemberIfIndex {
			return int(a.MemberIfIndex - b.MemberIfIndex)
		}
		return int(a.AggregateIfIndex - b.AggregateIfIndex)
	})
	seen := map[int32]bool{}
	for _, g := range snap.LAGGroups {
		if g.AggregateIfIndex != nil {
			seen[*g.AggregateIfIndex] = true
		}
	}
	for _, r := range snap.LAGMembers {
		if !seen[r.AggregateIfIndex] {
			x := r.AggregateIfIndex
			status := snap.Components["lag_membership"]
			snap.LAGGroups = append(snap.LAGGroups, model.LAGGroup{SourceGroupID: fmt.Sprintf("ifindex:%d", x), AggregateIfIndex: &x, Source: r.Source, Mode: r.Mode, Complete: status.Supported && status.WalkComplete && status.DecodeComplete})
			seen[x] = true
		}
	}
	for _, iface := range snap.Interfaces {
		if topology.IsLagIfType(iface.Type) && !seen[iface.IfIndex] {
			x := iface.IfIndex
			snap.LAGGroups = append(snap.LAGGroups, model.LAGGroup{SourceGroupID: fmt.Sprintf("ifindex:%d", x), AggregateIfIndex: &x, Source: "if_mib", Mode: "unknown"})
			seen[x] = true
		}
	}
	slices.SortFunc(snap.LAGGroups, func(a, b model.LAGGroup) int { return strings.Compare(a.SourceGroupID, b.SourceGroupID) })
	if len(snap.LAGMembers) > 0 {
		s := snap.Components["lag_membership"]
		s.Supported = true
		snap.Components["lag_membership"] = s
	}
}
