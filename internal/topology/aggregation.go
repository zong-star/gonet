package topology

import (
	"fmt"
	"slices"
	"strings"

	"gonet/internal/model"
)

const AggregationInferencePolicy = "peer-lag-v2"

// These inputs contain only facts from one committed scan. Callers apply their
// visibility policy before construction; display labels never identify vendors.
type AggregationDevice struct {
	ID                              int64
	SysObjectID, ClassificationRule string
	Verified                        bool
}
type AggregationMember struct {
	DeviceID int64
	model.LAGMember
	Name     string
	Complete bool
}
type AggregationLink struct {
	ID, DeviceA, DeviceB, PortA, PortB int64
	IfA, IfB                           int32
	ProtocolConflict                   bool
}
type AggregationConnection struct {
	GroupA, GroupB         *model.AggregationGroup
	LinkIDs                []int64
	Status, Mode, Coverage string
	Reasons                []string
}
type aggregationKey struct {
	device int64
	index  int32
}
type aggregationPort struct {
	device int64
	index  int32
	port   int64
}

func enterprise(oid, root string) bool {
	oid = strings.TrimPrefix(oid, ".")
	return oid == root || strings.HasPrefix(oid, root+".")
}
func directPeer(d AggregationDevice) bool {
	return d.Verified && (enterprise(d.SysObjectID, "1.3.6.1.4.1.25506") || enterprise(d.SysObjectID, "1.3.6.1.4.1.2011"))
}
func inferenceTarget(d AggregationDevice) bool {
	// The verified TS7914 classification is allowed alongside its observed
	// enterprise identity. Names, addresses and editable vendor labels are ignored.
	return d.Verified && enterprise(d.SysObjectID, "1.3.6.1.4.1.45577") &&
		strings.Contains(strings.ToLower(d.ClassificationRule), "ts7914")
}
func memberSource(m AggregationMember) bool {
	for _, source := range append(slices.Clone(m.Sources), m.Source) {
		if source == "ieee_lag" || source == "if_stack" || source == "huawei_private" || source == "h3c_private" {
			return true
		}
	}
	return false
}

// BuildAggregationConnections derives logical connections while retaining every
// physical ID. All candidates are checked before any group is emitted, so a
// conflicting last member cannot leave an earlier member falsely confirmed.
func BuildAggregationConnections(scanID int64, devices []AggregationDevice, members []AggregationMember, links []AggregationLink) []AggregationConnection {
	devs := map[int64]AggregationDevice{}
	for _, d := range devices {
		devs[d.ID] = d
	}
	relations := map[aggregationKey]AggregationMember{}
	tainted := map[aggregationKey]bool{}
	counts := map[aggregationKey]int{}
	groups := map[aggregationKey]*model.AggregationGroup{}
	complete := map[aggregationKey]bool{}
	for _, m := range members {
		if !devs[m.DeviceID].Verified || m.MemberIfIndex <= 0 || m.AggregateIfIndex <= 0 {
			continue
		}
		mk, gk := aggregationKey{m.DeviceID, m.MemberIfIndex}, aggregationKey{m.DeviceID, m.AggregateIfIndex}
		if prev, ok := relations[mk]; ok {
			tainted[aggregationKey{m.DeviceID, prev.AggregateIfIndex}], tainted[gk] = true, true
		}
		relations[mk] = m
		counts[gk]++
		if m.Status != "confirmed" || !memberSource(m) {
			tainted[gk] = true
		}
		if _, exists := groups[gk]; !exists {
			index := m.AggregateIfIndex
			var name *string
			if m.Name != "" {
				n := m.Name
				name = &n
			}
			mode := m.Mode
			if mode != "static" && mode != "lacp" {
				mode = "unknown"
			}
			sources := append(slices.Clone(m.Sources), m.Source)
			slices.Sort(sources)
			sources = slices.Compact(sources)
			groups[gk] = &model.AggregationGroup{GroupID: fmt.Sprintf("direct:%d:ifindex:%d", m.DeviceID, index), DeviceID: m.DeviceID, AggregateIfIndex: &index, InterfaceName: name, DisplayName: m.Name, EvidenceType: "direct", Mode: mode, Sources: sources}
			complete[gk] = m.Complete
		} else {
			g := groups[gk]
			if g.Mode != m.Mode {
				g.Mode = "unknown"
			}
			g.Sources = append(g.Sources, m.Sources...)
			g.Sources = append(g.Sources, m.Source)
			slices.Sort(g.Sources)
			g.Sources = slices.Compact(g.Sources)
			complete[gk] = complete[gk] && m.Complete
		}
	}
	type candidate struct {
		link     AggregationLink
		a, b     *model.AggregationGroup
		ka, kb   aggregationKey
		inferred bool
		status   string
	}
	candidates := []candidate{}
	peers := map[aggregationKey]map[int64]bool{}
	peerGroups := map[aggregationKey]map[string]bool{}
	owners := map[aggregationPort]map[string]bool{}
	addPeer := func(k aggregationKey, peer int64) {
		if peers[k] == nil {
			peers[k] = map[int64]bool{}
		}
		peers[k][peer] = true
	}
	addGroup := func(k aggregationKey, peer string) {
		if peerGroups[k] == nil {
			peerGroups[k] = map[string]bool{}
		}
		peerGroups[k][peer] = true
	}
	endpointLinks := map[aggregationPort]int{}
	for _, l := range links {
		for _, p := range []aggregationPort{{device: l.DeviceA, index: l.IfA}, {device: l.DeviceB, index: l.IfB}, {device: l.DeviceA, port: l.PortA}, {device: l.DeviceB, port: l.PortB}} {
			if p.index > 0 || p.port > 0 {
				endpointLinks[p]++
			}
		}
	}
	for _, l := range links {
		if !devs[l.DeviceA].Verified || !devs[l.DeviceB].Verified || l.DeviceA == l.DeviceB {
			continue
		}
		ma, oka := relations[aggregationKey{l.DeviceA, l.IfA}]
		mb, okb := relations[aggregationKey{l.DeviceB, l.IfB}]
		c := candidate{link: l, status: "unknown"}
		if oka {
			c.ka = aggregationKey{l.DeviceA, ma.AggregateIfIndex}
			c.a = groups[c.ka]
			addPeer(c.ka, l.DeviceB)
		}
		if okb {
			c.kb = aggregationKey{l.DeviceB, mb.AggregateIfIndex}
			c.b = groups[c.kb]
			addPeer(c.kb, l.DeviceA)
		}
		mappingConflict := false
		for _, p := range []aggregationPort{{device: l.DeviceA, index: l.IfA}, {device: l.DeviceB, index: l.IfB}, {device: l.DeviceA, port: l.PortA}, {device: l.DeviceB, port: l.PortB}} {
			if (p.index > 0 || p.port > 0) && endpointLinks[p] > 1 {
				mappingConflict = true
			}
		}
		if l.ProtocolConflict || mappingConflict {
			if oka {
				tainted[c.ka] = true
			}
			if okb {
				tainted[c.kb] = true
			}
		}
		if oka && okb {
			c.status = "confirmed"
			addGroup(c.ka, c.b.GroupID)
			addGroup(c.kb, c.a.GroupID)
			if c.a.Mode != "unknown" && c.b.Mode != "unknown" && c.a.Mode != c.b.Mode || l.ProtocolConflict {
				tainted[c.ka], tainted[c.kb] = true, true
			}
		} else if oka || okb {
			c.status = "partial"
			known, target, port, index, k := c.a, l.DeviceB, l.PortB, l.IfB, c.ka
			if okb {
				known, target, port, index, k = c.b, l.DeviceA, l.PortA, l.IfA, c.kb
			}
			if directPeer(devs[known.DeviceID]) && inferenceTarget(devs[target]) && (port > 0 || index > 0) {
				g := &model.AggregationGroup{GroupID: fmt.Sprintf("inferred:%d:peer:%d:ifindex:%d", target, known.DeviceID, *known.AggregateIfIndex), DeviceID: target, DisplayName: "推断聚合（对端 " + known.DisplayName + "）", EvidenceType: "peer_inferred", Mode: "unknown", Sources: []string{"peer_inferred"}, InferredFrom: &model.AggregationInference{DeviceID: known.DeviceID, GroupID: known.GroupID, ScanID: scanID}}
				if oka {
					c.b = g
				} else {
					c.a = g
				}
				c.inferred = true
				c.status = "inferred"
				addGroup(k, g.GroupID)
				// Track both identities when available. A missing ifIndex on one
				// observation must not hide a collision on the same stable port.
				for _, pk := range []aggregationPort{{device: target, index: index}, {device: target, port: port}} {
					if pk.index == 0 && pk.port == 0 {
						continue
					}
					if owners[pk] == nil {
						owners[pk] = map[string]bool{}
					}
					owners[pk][known.GroupID] = true
				}
			}
		}
		candidates = append(candidates, c)
	}
	for k, p := range peers {
		if len(p) > 1 {
			tainted[k] = true
		}
	}
	for k, p := range peerGroups {
		if len(p) > 1 {
			tainted[k] = true
		}
	}
	for _, groupOwners := range owners {
		if len(groupOwners) > 1 {
			for k, g := range groups {
				if groupOwners[g.GroupID] {
					tainted[k] = true
				}
			}
		}
	}
	result := []AggregationConnection{}
	byGroup := map[string]int{}
	for _, c := range candidates {
		status := c.status
		if c.ka.device != 0 && tainted[c.ka] || c.kb.device != 0 && tainted[c.kb] {
			status = "conflict"
		}
		out := AggregationConnection{GroupA: c.a, GroupB: c.b, LinkIDs: []int64{c.link.ID}, Status: status, Mode: "unknown", Coverage: "partial", Reasons: []string{}}
		if status == "conflict" {
			out.Reasons = append(out.Reasons, "MEMBERSHIP_CONFLICT")

		} else if status == "inferred" {
			out.Reasons = append(out.Reasons, "PEER_LAG_INFERRED", "LOCAL_LAG_MAPPING_UNAVAILABLE")
		} else if status == "confirmed" && c.a.Mode == c.b.Mode {
			out.Mode = c.a.Mode
		}
		if status == "confirmed" || status == "inferred" {
			keys := []string{c.a.GroupID, c.b.GroupID}
			slices.Sort(keys)
			key := strings.Join(keys, "|")
			if i, exists := byGroup[key]; exists {
				result[i].LinkIDs = append(result[i].LinkIDs, c.link.ID)
				continue
			}
			byGroup[key] = len(result)
		}
		result = append(result, out)
	}
	for i := range result {
		c := &result[i]
		slices.Sort(c.LinkIDs)
		clone := func(g *model.AggregationGroup) *model.AggregationGroup {
			if g == nil {
				return nil
			}
			v := *g
			return &v
		}
		c.GroupA, c.GroupB = clone(c.GroupA), clone(c.GroupB)
		for _, g := range []*model.AggregationGroup{c.GroupA, c.GroupB} {
			if g == nil {
				continue
			}
			g.LocalDeviceID = g.DeviceID
			g.MemberInterfaces = []int32{}
			g.EvidenceLinkIDs = slices.Clone(c.LinkIDs)
			if g.EvidenceType == "peer_inferred" {
				g.AggregationSource = "peer_inferred"
				r := g.InferredFrom.DeviceID
				g.RemoteDeviceID = &r
				v := g.InferredFrom.GroupID
				g.RemoteAggregationID = &v
			} else {
				g.AggregationSource = "native"
				for _, m := range members {
					if m.DeviceID == g.DeviceID && m.AggregateIfIndex == *g.AggregateIfIndex {
						g.MemberInterfaces = append(g.MemberInterfaces, m.MemberIfIndex)
					}
				}
			}
			for _, l := range links {
				if !slices.Contains(c.LinkIDs, l.ID) {
					continue
				}
				if l.DeviceA == g.DeviceID {
					g.MemberInterfaces = append(g.MemberInterfaces, l.IfA)
				} else if l.DeviceB == g.DeviceID {
					g.MemberInterfaces = append(g.MemberInterfaces, l.IfB)
				}
			}
			slices.Sort(g.MemberInterfaces)
			g.MemberInterfaces = slices.Compact(g.MemberInterfaces)
		}
		if c.Status == "inferred" {
			native := c.GroupA
			if native.EvidenceType == "peer_inferred" {
				native = c.GroupB
			}
			k := aggregationKey{native.DeviceID, *native.AggregateIfIndex}
			if len(c.LinkIDs) < 2 {
				c.Status = "partial"
				c.Reasons = append(c.Reasons, "PEER_INFERRED_MEMBER")
			} else if !complete[k] {
				c.Status = "partial"
				c.Reasons = append(c.Reasons, "PEER_AGGREGATION_INCOMPLETE")
			}
		}
		for _, g := range []*model.AggregationGroup{c.GroupA, c.GroupB} {
			if g != nil && g.EvidenceType == "peer_inferred" {
				g.InferenceStatus = c.Status
				if c.Status == "partial" && len(c.LinkIDs) == 1 {
					g.InferenceStatus = "peer_inferred_member"
				}
			}
		}
	}
	for i := range result {
		c := &result[i]
		slices.Sort(c.LinkIDs)
		if c.Status == "confirmed" {
			ka, kb := aggregationKey{c.GroupA.DeviceID, *c.GroupA.AggregateIfIndex}, aggregationKey{c.GroupB.DeviceID, *c.GroupB.AggregateIfIndex}
			if complete[ka] && complete[kb] && counts[ka] == len(c.LinkIDs) && counts[kb] == len(c.LinkIDs) {
				c.Coverage = "complete"
			}
		}
	}
	slices.SortFunc(result, func(a, b AggregationConnection) int {
		if a.LinkIDs[0] < b.LinkIDs[0] {
			return -1
		}
		if a.LinkIDs[0] > b.LinkIDs[0] {
			return 1
		}
		return 0
	})
	return result
}
