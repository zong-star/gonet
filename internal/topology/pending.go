package topology

import (
	"fmt"
	"gonet/internal/identity"
	"gonet/internal/model"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Pending records preserve observed edges without claiming an unclassified
// endpoint is a switch or inventing an unverified physical interface.
type PendingNode struct {
	Verification        model.VerificationDetails `json:"verification"`
	ManagementAddresses []netip.Addr              `json:"reported_management_addresses,omitempty"`
	Key                 string                    `json:"key"`
	Chassis             model.TypedID             `json:"chassis"`
	SystemName          string                    `json:"system_name"`
	SystemDescription   string                    `json:"system_description,omitempty"`
	Status              string                    `json:"status"`
}

func CandidateKey(n model.LLDPNeighbor, observer uint64) string {
	if key, strong := identity.NormalizedKey(n.Chassis, false); strong {
		return key
	}
	return fmt.Sprintf("unresolved:%d:%d:%d:%s", observer, n.Index.LocalPortNum, n.Index.RemoteIndex, identity.WeakKey(n.Chassis.Subtype, n.Chassis.Raw))
}

type PendingLink struct {
	LocalDevice   uint64         `json:"local_device_id"`
	LocalPortNum  uint32         `json:"local_port_num"`
	RemoteKey     string         `json:"remote_key"`
	RemoteDevice  uint64         `json:"remote_device_id,omitempty"`
	RemotePort    model.TypedID  `json:"remote_port"`
	OriginalPort  *model.TypedID `json:"original_port,omitempty"`
	Status        string         `json:"status"`
	Reason        string         `json:"reason"`
	ObservedAt    time.Time      `json:"observed_at"`
	Chassis       model.TypedID  `json:"-"`
	ObservationID int64          `json:"-"`
	ReasonCodes   []string       `json:"-"`
	Conflict      bool           `json:"-"`
}

func PendingProjection(rows []UnresolvedObservation, known map[string]uint64) ([]PendingNode, []PendingLink) {
	nodes := map[string]PendingNode{}
	links := make([]PendingLink, 0, len(rows))
	for _, u := range rows {
		n := u.Raw
		key := CandidateKey(n, uint64(u.Observer))
		status := "neighbor_unknown"
		reason := strings.ToLower(u.Reason)
		if strings.Contains(reason, "identity") && strings.Contains(reason, "conflict") {
			status = "identity_conflict"
		} else if strings.Contains(reason, "port") || strings.Contains(reason, "physical") || strings.Contains(reason, "topology_conflict") {
			status = "port_match_failed"
		}
		remote := known[key]
		if remote == 0 {
			node := nodes[key]
			node.Key, node.Chassis, node.Status = key, n.Chassis, status
			if n.SysName != "" {
				node.SystemName = n.SysName
			}
			if n.SysDescription != "" {
				node.SystemDescription = n.SysDescription
			}
			for _, ip := range n.MgmtAddresses {
				found := false
				for _, old := range node.ManagementAddresses {
					if old == ip {
						found = true
					}
				}
				if !found {
					node.ManagementAddresses = append(node.ManagementAddresses, ip)
				}
			}
			nodes[key] = node
		}
		links = append(links, PendingLink{LocalDevice: uint64(u.Observer), LocalPortNum: u.Row.LocalPortNum, RemoteKey: key, RemoteDevice: remote, RemotePort: n.Port, OriginalPort: n.OriginalPort, Status: status, Reason: u.Reason, ObservedAt: u.At,
			Chassis: n.Chassis, ObservationID: u.ObservationID, ReasonCodes: u.ReasonCodes, Conflict: u.Conflict || strings.Contains(reason, "conflict")})
	}
	out := make([]PendingNode, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	sort.SliceStable(links, func(i, j int) bool {
		a, b := links[i], links[j]
		if a.LocalDevice != b.LocalDevice {
			return a.LocalDevice < b.LocalDevice
		}
		if a.LocalPortNum != b.LocalPortNum {
			return a.LocalPortNum < b.LocalPortNum
		}
		return a.RemoteKey < b.RemoteKey
	})
	return out, links
}
