package collector

import (
	"context"
	"fmt"
	"math"
	"slices"

	"github.com/gosnmp/gosnmp"

	"gonet/internal/collector/lldp"
	"gonet/internal/collector/oidutil"
	"gonet/internal/collector/snmp"
	"gonet/internal/model"
	"gonet/internal/topology"
)

// IF-MIB (RFC 2863) and IEEE8023-LAG-MIB (201610120000Z).
const (
	ifStackStatus     = "1.3.6.1.2.1.31.1.2.1.3"
	ifStackLastChange = "1.3.6.1.2.1.31.1.6.0"
	lagAttachedAggID  = "1.2.840.10006.300.43.1.2.1.1.13"
	lagActorOperKey   = "1.2.840.10006.300.43.1.1.1.1.7"
	lagDebugRxState   = "1.2.840.10006.300.43.1.2.3.1.1"
	lagLastChange     = "1.2.840.10006.300.43.1.3.0"
)

func (c *Collector) collectLAG(ctx context.Context, sess *snmp.Session, snap *model.DeviceSnapshot) {
	if len(snap.Interfaces) == 0 || ctx.Err() != nil {
		snap.Components["lag_membership"] = model.ComponentStatus{Skipped: true}
		return
	}
	// Baseline LLDP collection and retries finish before spending this budget.
	ctx, cancel := context.WithTimeout(ctx, c.opts.LAGTimeout)
	defer cancel()
	sess.LimitAdditionalPDUs(c.opts.LAGMaxPDUs)
	guards := []string{lldp.SysUpTime, ifStackLastChange, lagLastChange}
	before, err := c.getMap(sess, ctx, guards)
	if err != nil {
		snap.Components["lag_membership"] = model.ComponentStatus{Issues: []model.Issue{issueFromErr("lag_membership", err)}}
		return
	}
	stack, stackSum, stackErr := c.lagWalk(sess, ctx, snap, "if_stack", "", ifStackStatus)
	attached, lagSum, lagErr := c.lagWalk(sess, ctx, snap, "ieee_lag", "", lagAttachedAggID)
	after, endErr := c.getMap(sess, ctx, guards)
	upBefore, beforeOK := scalarTicks(before, lldp.SysUpTime)
	upAfter, afterOK := scalarTicks(after, lldp.SysUpTime)
	stable := endErr == nil && beforeOK && afterOK && upBefore >= snap.Device.UptimeAfter && upAfter >= upBefore
	stackStable := stable && lagGuardStable(before, after, ifStackLastChange, snap.Device.UptimeBefore)
	lagStable := stable && lagGuardStable(before, after, lagLastChange, snap.Device.UptimeBefore)
	if lagStable && lagErr == nil && len(attached) > 0 {
		// Obtain readable group instances before optional debug/protocol details.
		// A failed optional group read does not invalidate the observed members.
		c.collectIEEEGroups(ctx, sess, snap)
	}
	// Mode is optional. Read it after the membership guards so a debug-table
	// timeout cannot invalidate membership that has already been observed.
	var modes []gosnmp.SnmpPDU
	if lagStable && (len(stack) != 0 || len(attached) != 0) {
		modes, _, _ = c.lagWalk(sess, ctx, snap, "ieee_lag_debug", "", lagDebugRxState)
		modeAfter, modeErr := c.getMap(sess, ctx, guards)
		modeUptime, modeOK := scalarTicks(modeAfter, lldp.SysUpTime)
		if modeErr != nil || !modeOK || modeUptime < upAfter || !lagGuardStable(after, modeAfter, lagLastChange, snap.Device.UptimeBefore) {
			modes = nil
		}
	}
	stackStatus := componentStatus(stackSum, stackErr, stackStable, len(stack) > 0)
	lagStatus := componentStatus(lagSum, lagErr, lagStable, len(attached) > 0)
	if !stackStable || stackErr != nil {
		stack = nil
	}
	if !lagStable || lagErr != nil {
		attached = nil
	}
	members, coverage, issues := parseLAG(snap.Interfaces, stack, attached, modes)
	snap.LAGMembers = members
	snap.Components["if_stack"] = stackStatus
	snap.Components["ieee_lag"] = lagStatus
	_, hasChangeGuard := scalarTicks(before, lagLastChange)
	ifMIB := snap.Components["if_mib"]
	snap.Components["lag_membership"] = model.ComponentStatus{
		Supported:      stackStatus.Supported || lagStatus.Supported,
		WalkComplete:   coverage && c.opts.ViewVerified && hasChangeGuard && ifMIB.WalkComplete && ifMIB.DecodeComplete,
		DecodeComplete: stable && len(issues) == 0,
		Issues:         issues,
	}
	c.collectLAGSources(ctx, sess, snap)
	status := snap.Components["lag_membership"]
	for i := range snap.LAGGroups {
		if snap.LAGGroups[i].Source == "ieee_lag" {
			snap.LAGGroups[i].Complete = status.Supported && status.WalkComplete && status.DecodeComplete
		}
	}
	reconcileLAG(snap)
}

func parseIEEEGroups(interfaces []model.Interface, rows []gosnmp.SnmpPDU) ([]model.LAGGroup, error) {
	known := map[int32]bool{}
	for _, iface := range interfaces {
		known[iface.IfIndex] = topology.IsLagIfType(iface.Type)
	}
	out := []model.LAGGroup{}
	for _, p := range rows {
		idx, e := oidutil.Suffix(lagActorOperKey, p.Name)
		key, valueErr := lldp.AsUint32(p)
		if e != nil || valueErr != nil || len(idx) != 1 || idx[0] == 0 || idx[0] > math.MaxInt32 || key > 65535 || !known[int32(idx[0])] {
			return nil, fmt.Errorf("invalid dot3adAggTable instance")
		}
		x := int32(idx[0])
		out = append(out, model.LAGGroup{SourceGroupID: fmt.Sprintf("ifindex:%d", x), AggregateIfIndex: &x, Source: "ieee_lag", Mode: "unknown"})
	}
	slices.SortFunc(out, func(a, b model.LAGGroup) int { return int(*a.AggregateIfIndex - *b.AggregateIfIndex) })
	return out, nil
}
func (c *Collector) collectIEEEGroups(ctx context.Context, s *snmp.Session, snap *model.DeviceSnapshot) {
	guards := []string{lldp.SysUpTime, lagLastChange}
	before, be := c.getMap(s, ctx, guards)
	rows, _, err := c.lagWalk(s, ctx, snap, "ieee_lag_groups", "", lagActorOperKey)
	after, ae := c.getMap(s, ctx, guards)
	u1, o1 := scalarTicks(before, lldp.SysUpTime)
	u2, o2 := scalarTicks(after, lldp.SysUpTime)
	if be != nil || ae != nil || err != nil || !o1 || !o2 || u1 < snap.Device.UptimeAfter || u2 < u1 || !lagGuardStable(before, after, lagLastChange, snap.Device.UptimeBefore) {
		return
	}
	groups, e := parseIEEEGroups(snap.Interfaces, rows)
	if e != nil {
		status := snap.Components["ieee_lag_groups"]
		status.DecodeComplete = false
		status.Issues = append(status.Issues, model.Issue{Code: "LAG_GROUP_DECODE", Component: "ieee_lag_groups", Message: e.Error()})
		snap.Components["ieee_lag_groups"] = status
		return
	}
	snap.LAGGroups = append(snap.LAGGroups, groups...)
}

func lagGuardStable(before, after map[string]gosnmp.SnmpPDU, oid string, baseline uint32) bool {
	a, okA := scalarTicks(before, oid)
	b, okB := scalarTicks(after, oid)
	return (!okA && !okB) || (okA && okB && a == b && a <= baseline)
}

func parseLAG(interfaces []model.Interface, stack, attached, modes []gosnmp.SnmpPDU) ([]model.LAGMember, bool, []model.Issue) {
	types := make(map[int32]int32, len(interfaces))
	for _, iface := range interfaces {
		types[iface.IfIndex] = iface.Type
	}
	byMember := map[int32]map[int32]model.LAGMember{}
	observed := map[int32]bool{}
	rxState := map[int32]uint32{}
	var issues []model.Issue
	issue := func(code, message string) {
		issues = append(issues, model.Issue{Code: code, Component: "lag_membership", Message: message})
	}
	add := func(aggregate, member int32, source string) {
		if byMember[member] == nil {
			byMember[member] = map[int32]model.LAGMember{}
		}
		mode := "unknown"
		switch rxState[member] {
		case 1:
			mode = "lacp"

		}
		previous := byMember[member][aggregate]
		sources := append(previous.Sources, source)
		slices.Sort(sources)
		attached := previous.Attached
		if source == "ieee_lag" {
			yes := true
			attached = &yes
		}
		byMember[member][aggregate] = model.LAGMember{AggregateIfIndex: aggregate, MemberIfIndex: member, Source: source, Mode: mode, Status: "confirmed", Sources: slices.Compact(sources), Attached: attached}
	}
	for _, pdu := range modes {
		index, err := oidutil.Suffix(lagDebugRxState, pdu.Name)
		value, valueErr := lldp.AsUint32(pdu)
		if err == nil && valueErr == nil && len(index) == 1 && index[0] <= math.MaxInt32 {
			rxState[int32(index[0])] = value
		}
	}
	for _, pdu := range stack {
		index, err := oidutil.Suffix(ifStackStatus, pdu.Name)
		value, valueErr := lldp.AsUint32(pdu)
		if err != nil || valueErr != nil || len(index) != 2 || index[0] > math.MaxInt32 || index[1] > math.MaxInt32 || value < 1 || value > 3 {
			issue("LAG_DECODE", "invalid ifStackStatus instance")
			continue
		}
		aggregate, member := int32(index[0]), int32(index[1])
		if value == 1 && topology.IsLagIfType(types[aggregate]) && topology.IsPhysicalIfType(types[member]) {
			add(aggregate, member, "if_stack")
		}
	}
	for _, pdu := range attached {
		index, err := oidutil.Suffix(lagAttachedAggID, pdu.Name)
		value, valueErr := lldp.AsUint32(pdu)
		if err != nil || valueErr != nil || len(index) != 1 || index[0] == 0 || index[0] > math.MaxInt32 || value > math.MaxInt32 {
			issue("LAG_DECODE", "invalid dot3adAggPortAttachedAggID instance")
			continue
		}
		aggregate, member := int32(value), int32(index[0])
		if !topology.IsPhysicalIfType(types[member]) {
			continue
		}
		if aggregate != 0 && !topology.IsLagIfType(types[aggregate]) {
			issue("LAG_DECODE", "attached aggregator is missing or has an incompatible interface type")
			continue
		}
		observed[member] = true
		if aggregate != 0 {
			add(aggregate, member, "ieee_lag")
		} else {
			// Zero is operational detachment, not evidence against configured
			// membership independently observed through ifStack/vendor sources.
			for group, r := range byMember[member] {
				attached := false
				r.Attached = &attached
				byMember[member][group] = r
			}
		}
	}
	var members []model.LAGMember
	for member, aggregates := range byMember {
		if len(aggregates) > 1 {
			issue("LAG_CONFLICT", fmt.Sprintf("interface %d refers to multiple aggregators", member))
		}
		for _, relation := range aggregates {
			if len(aggregates) > 1 {
				relation.Status = "conflict"
			}
			members = append(members, relation)
		}
	}
	slices.SortFunc(members, func(a, b model.LAGMember) int {
		if a.MemberIfIndex != b.MemberIfIndex {
			return int(a.MemberIfIndex) - int(b.MemberIfIndex)
		}
		return int(a.AggregateIfIndex) - int(b.AggregateIfIndex)
	})
	complete := len(observed) > 0 && len(issues) == 0
	for index, kind := range types {
		if topology.IsPhysicalIfType(kind) && !observed[index] {
			complete = false
		}
	}
	return members, complete, issues
}
