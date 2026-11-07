package collector

import (
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"gonet/internal/collector/lldp"
	"gonet/internal/collector/snmp"
	"gonet/internal/model"
)

// derive computes the three per-device conclusions (section 3.4).
func (c *Collector) derive(snap *model.DeviceSnapshot, sysSupported, sysDecoded, lldpChassisPresent, receiveVerified bool, issues *[]model.Issue) {
	d := &snap.Device
	system := snap.Components["system"]
	local := snap.Components["lldp_local"]
	rem := snap.Components["lldp_rem"]
	if sysSupported && !lldpChassisPresent {
		*issues = append(*issues, model.Issue{Code: "LLDP_LOCAL_UNAVAILABLE", Component: "lldp_local",
			Message: "local LLDP chassis is unavailable; check LLDP-MIB support and the SNMP read view"})
	}

	collectionComplete := system.Supported && system.WalkComplete && system.DecodeComplete &&
		local.Supported && local.WalkComplete && local.DecodeComplete &&
		rem.Supported && rem.WalkComplete && rem.DecodeComplete

	// snapshot stability: uptime must not restart/wrap, and LLDP lastChange must
	// be unchanged across the collection.
	stability := snap.Components["stability"]
	stable := stability.Supported && stability.WalkComplete && stability.DecodeComplete
	if !stable {
		*issues = append(*issues, model.Issue{Code: "SNAPSHOT_UNSTABLE", Component: "stability",
			Message: "uptime or LLDP lastChange unavailable; stability cannot be verified"})
	}
	if d.UptimeAfter < d.UptimeBefore {
		stable = false
		*issues = append(*issues, model.Issue{
			Code: "SNAPSHOT_UNSTABLE", Component: "system",
			Message: "sysUpTime decreased during collection (restart or wrap)",
		})
	}
	if d.LastChangeBefore != d.LastChangeAfter {
		stable = false
		*issues = append(*issues, model.Issue{
			Code: "SNAPSHOT_UNSTABLE", Component: "lldp_rem",
			Message: "lldpStatsRemTablesLastChangeTime changed during collection",
		})
	}

	absenceEligible := collectionComplete && stable && c.opts.ViewVerified && receiveVerified
	// Store the verification prerequisites so APIs can explain unknown coverage.
	snap.Components["snmp_view"] = model.ComponentStatus{Supported: c.opts.ViewVerified, WalkComplete: c.opts.ViewVerified, DecodeComplete: c.opts.ViewVerified}
	snap.Components["lldp_receive"] = model.ComponentStatus{Supported: receiveVerified, WalkComplete: receiveVerified, DecodeComplete: receiveVerified}
	ifm := snap.Components["if_mib"]
	if !ifm.Supported || !ifm.WalkComplete || !ifm.DecodeComplete || !lldpChassisPresent {
		absenceEligible = false
	}
	for _, lp := range snap.LocalPorts {
		if lp.IfIndex == nil || lp.MappingRule == "unresolved" {
			absenceEligible = false
		}
	}
	if c.opts.StartupGrace > 0 {
		if time.Duration(d.UptimeBefore)*(time.Second/100) < c.opts.StartupGrace {
			absenceEligible = false
			*issues = append(*issues, model.Issue{
				Code: "VIEW_UNVERIFIED", Component: "system",
				Message: "device uptime below startup_grace; negative evidence withheld",
			})
		}
	}

	snap.CollectionComplete = collectionComplete
	snap.SnapshotStable = stable
	snap.AbsenceEligible = absenceEligible
}

// Every local LLDP port must have a decoded, receive-enabled admin row.
func (c *Collector) receiveVerified(ports []model.LocalPort, pdus []gosnmp.SnmpPDU, sum snmp.WalkSummary, err error) bool {
	if err != nil || sum.FirstEndOfView {
		return false
	}
	statuses := map[uint32]uint32{}
	for _, p := range pdus {
		suffix, ok := strings.CutPrefix(strings.TrimPrefix(p.Name, "."), lldp.LldpPortConfigAdminStatus+".")
		n, e := strconv.ParseUint(suffix, 10, 32)
		v, ve := lldp.AsUint32(p)
		if !ok || e != nil || ve != nil || p.Type != gosnmp.Integer {
			return false
		}
		if _, duplicate := statuses[uint32(n)]; duplicate {
			return false
		}
		statuses[uint32(n)] = v
	}
	if len(ports) == 0 {
		return false
	}
	for _, lp := range ports {
		v, ok := statuses[lp.Number]
		if !ok || (v != lldp.AdminStatusRxOnly && v != lldp.AdminStatusTxAndRx) {
			return false
		}
	}
	return true
}

// associateLocalPorts attaches an ifIndex to each local LLDP port when its
// typed ID maps unambiguously to one interface (C09). locPortNum is never used
// as an ifIndex.
func (c *Collector) associateLocalPorts(ports []model.LocalPort, ifaces []model.Interface) {
	for i := range ports {
		lp := &ports[i]
		switch lp.ID.Subtype {
		case lldp.PortSubtypeInterfaceName:
			if idx, ok := uniqueIfaceByName(ifaces, string(lp.ID.Raw)); ok {
				setIfIndex(lp, ifaces[idx], "ifname-exact")
			} else {
				lp.MappingRule = "unresolved"
			}
		case lldp.PortSubtypeInterfaceAlias:
			if idx, ok := uniqueIfaceByAlias(ifaces, string(lp.ID.Raw)); ok {
				setIfIndex(lp, ifaces[idx], "ifalias-exact")
			} else {
				lp.MappingRule = "unresolved"
			}
		case lldp.PortSubtypeMACAddress:
			if idx, ok := uniqueIfaceByMAC(ifaces, lp.ID.Raw); ok {
				setIfIndex(lp, ifaces[idx], "mac-exact")
			} else {
				lp.MappingRule = "unresolved"
			}
		default:
			lp.MappingRule = "unresolved"
		}
	}
}

func setIfIndex(lp *model.LocalPort, iface model.Interface, rule string) {
	n := iface.IfIndex
	lp.IfIndex = &n
	lp.Physical = iface.Type == lldp.IfTypeEthernetCsmacd
	lp.MappingRule = rule
}

func uniqueIfaceByName(ifaces []model.Interface, name string) (int, bool) {
	idx := -1
	for i := range ifaces {
		if ifaces[i].Name == name {
			if idx != -1 {
				return 0, false
			}
			idx = i
		}
	}
	return idx, idx != -1
}

func uniqueIfaceByAlias(ifaces []model.Interface, alias string) (int, bool) {
	idx := -1
	for i := range ifaces {
		if ifaces[i].Alias == alias {
			if idx != -1 {
				return 0, false
			}
			idx = i
		}
	}
	return idx, idx != -1
}

func uniqueIfaceByMAC(ifaces []model.Interface, mac []byte) (int, bool) {
	return model.PhysicalInterfaceByMAC(ifaces, mac)
}
