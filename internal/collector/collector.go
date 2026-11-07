// Package collector orchestrates SNMP transport and LLDP/IF-MIB parsing to
// produce a single-device DeviceSnapshot (M1). It does not recurse, resolve
// identity, or touch any database.
package collector

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"

	"gonet/internal/collector/lldp"
	"gonet/internal/collector/snmp"
	"gonet/internal/model"
)

// Options configures the collector. Params carries transport/credentials
// (Target is set per call from the discovery target).
type Options struct {
	LAGTimeout                 time.Duration
	LAGMaxPDUs                 int
	CollectManagementAddresses bool
	Adapters                   []string
	Params                     snmp.Params
	MaxNeighbors               int
	ConsistencyRetries         int
	ViewVerified               bool
	DeviceTimeout              time.Duration
	StartupGrace               time.Duration
}

// Collector implements model.Collector for a single device.
type Collector struct {
	opts Options
}

// New builds a Collector with defaults applied.
func New(o Options) *Collector {
	if o.LAGTimeout == 0 {
		o.LAGTimeout = 3 * time.Second
	}
	if o.LAGMaxPDUs == 0 {
		o.LAGMaxPDUs = 32
	}
	if o.MaxNeighbors <= 0 {
		o.MaxNeighbors = 4096
	}
	return &Collector{opts: o}
}

// Collect produces a snapshot. If the first pass is snapshot-unstable and
// retries remain, it re-collects once (full re-collection, never stitching two
// passes). The final pass is authoritative.
func (c *Collector) Collect(ctx context.Context, target model.DiscoveryTarget) (*model.DeviceSnapshot, error) {
	if c.opts.DeviceTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.opts.DeviceTimeout)
		defer cancel()
	}
	// One deadline and PDU budget cover all consistency attempts.
	params := c.opts.Params
	params.Target = target.Address.Unmap().String()
	sess, err := snmp.NewSession(ctx, params)
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	attempts := c.opts.ConsistencyRetries + 1
	if attempts < 1 {
		attempts = 1
	}
	var last *model.DeviceSnapshot
	for i := 0; i < attempts; i++ {
		snap, err := c.collectOnce(ctx, target, sess)
		if snap == nil {
			return nil, err
		}
		last = snap
		if snap.SnapshotStable || err != nil || !snap.Components["stability"].Supported {
			if err == nil {
				c.collectLAG(ctx, sess, snap)
			}
			snap.RequestPDUs = sess.PDUsUsed()
			return snap, err
		}
	}
	last.RequestPDUs = sess.PDUsUsed()
	return last, nil
}

func (c *Collector) collectOnce(ctx context.Context, target model.DiscoveryTarget, sess *snmp.Session) (*model.DeviceSnapshot, error) {
	snap := &model.DeviceSnapshot{
		SchemaVersion: model.SchemaVersion,
		Device:        model.DeviceInfo{Target: target.Address},
		Components:    map[string]model.ComponentStatus{},
		StartedAt:     time.Now().UTC(),
	}

	dctx := ctx

	var errResult error
	var issues []model.Issue

	// Scalars before walks: sysObjectID/uptime are required; lastChange before
	// the walks is compared with the after value for snapshot stability.
	before := []string{
		lldp.SysObjectID, lldp.SysDescr, lldp.SysName,
		lldp.LldpLocChassisIDSubtype, lldp.LldpLocChassisID,
		lldp.LldpLocSysCapSupported, lldp.LldpLocSysCapEnabled,
		lldp.SysUpTime, lldp.LldpStatsRemTablesLastChangeTime,
	}
	beforeMap, berr := c.getMap(sess, dctx, before)
	if berr != nil {
		errResult = berr
		issues = append(issues, issueFromErr("system", berr))
	}
	sysSupported, sysDecoded, lldpChassisPresent := c.parseSystem(snap, beforeMap, &issues)

	// Table walks (order matters for reproducibility; each is bounded by the
	// session PDU budget).
	localPDUs, localSum, localErr := c.walk(sess, dctx, lldp.LldpLocPortTable)
	remPDUs, remSum, remErr := c.walk(sess, dctx, lldp.LldpRemTable)
	var manPDUs []gosnmp.SnmpPDU
	var manSum snmp.WalkSummary
	var manErr error
	readManagement := c.opts.CollectManagementAddresses
	ifDescrPDUs, ifDescrSum, ifDescrErr := c.walk(sess, dctx, lldp.IfDescr)
	ifTypePDUs, ifTypeSum, ifTypeErr := c.walk(sess, dctx, lldp.IfType)
	ifPhysPDUs, ifPhysSum, ifPhysErr := c.walk(sess, dctx, lldp.IfPhysAddress)
	ifNamePDUs, ifNameSum, ifNameErr := c.walk(sess, dctx, lldp.IfName)
	ifAliasPDUs, ifAliasSum, ifAliasErr := c.walk(sess, dctx, lldp.IfAlias)
	adminPDUs, adminSum, adminErr := c.walk(sess, dctx, lldp.LldpPortConfigAdminStatus)
	// Read the optional table after essential facts. Old TS/RS firmware can
	// return malformed/non-increasing instances; the bounded walker stops
	// those, while later scans can observe corrected, standards-compliant IPs.
	if readManagement {
		manPDUs, manSum, manErr = c.walk(sess, dctx, lldp.LldpRemManAddrTable)
	}

	// Scalars after walks.
	afterMap, aerr := c.getMap(sess, dctx, []string{lldp.SysUpTime, lldp.LldpStatsRemTablesLastChangeTime})
	if aerr != nil && errResult == nil {
		errResult = aerr
	}
	c.parseAfter(snap, afterMap, &issues)

	// Parse tables.
	localPorts, lIssues := lldp.ParseLocalPorts(localPDUs)
	issues = append(issues, lIssues...)
	neighbors, rIssues := lldp.ParseRemoteForDevice(remPDUs, snap.Device, c.opts.Adapters)
	issues = append(issues, rIssues...)
	mgmt, mIssues := lldp.ParseMgmtAddresses(manPDUs)
	issues = append(issues, mIssues...)
	ifaces, iIssues := lldp.ParseInterfaces(appendAll(ifDescrPDUs, ifTypePDUs, ifPhysPDUs, ifNamePDUs, ifAliasPDUs))
	issues = append(issues, iIssues...)

	for i := range neighbors {
		neighbors[i].MgmtAddresses = mgmt[neighbors[i].Index]
	}
	c.associateLocalPorts(localPorts, ifaces)

	snap.Interfaces = ifaces
	snap.LocalPorts = localPorts
	snap.Neighbors = neighbors

	// Component statuses.
	snap.Components["system"] = model.ComponentStatus{
		Supported:      sysSupported,
		WalkComplete:   berr == nil,
		DecodeComplete: sysDecoded,
	}
	snap.Components["lldp_local"] = componentStatus(localSum, localErr, len(lIssues) == 0, lldpChassisPresent || len(localPorts) > 0)
	snap.Components["lldp_rem"] = remoteComponentStatus(remSum, remErr, len(rIssues) == 0, len(neighbors) > 0, lldpChassisPresent, c.opts.ViewVerified)
	snap.Components["lldp_man_addr"] = componentStatus(manSum, manErr, len(mIssues) == 0, len(manPDUs) > 0)
	if !readManagement {
		snap.Components["lldp_man_addr"] = model.ComponentStatus{Skipped: true}
	}
	snap.Components["if_mib"] = componentStatus(combineSum(ifDescrSum, ifTypeSum, ifPhysSum, ifNameSum, ifAliasSum), errors.Join(ifDescrErr, ifTypeErr, ifPhysErr, ifNameErr, ifAliasErr), len(iIssues) == 0, len(ifaces) > 0)
	// Missing scalars must not look like a stable zero -> zero measurement.
	_, upBeforeOK := scalarTicks(beforeMap, lldp.SysUpTime)
	_, upAfterOK := scalarTicks(afterMap, lldp.SysUpTime)
	_, changeBeforeOK := scalarTicks(beforeMap, lldp.LldpStatsRemTablesLastChangeTime)
	_, changeAfterOK := scalarTicks(afterMap, lldp.LldpStatsRemTablesLastChangeTime)
	snap.Components["stability"] = model.ComponentStatus{
		Supported:      changeBeforeOK && changeAfterOK,
		WalkComplete:   berr == nil && aerr == nil,
		DecodeComplete: upBeforeOK && upAfterOK && changeBeforeOK && changeAfterOK,
	}

	receiveVerified := c.receiveVerified(localPorts, adminPDUs, adminSum, adminErr)

	c.derive(snap, sysSupported, sysDecoded, lldpChassisPresent, receiveVerified, &issues)

	if len(neighbors) > c.opts.MaxNeighbors {
		snap.CollectionComplete = false
		snap.AbsenceEligible = false
		issues = append(issues, model.Issue{
			Code: "WALK_LIMIT", Component: "lldp_rem",
			Message: fmt.Sprintf("neighbor count %d exceeds max_neighbors_per_device %d", len(neighbors), c.opts.MaxNeighbors),
		})
	}

	for _, name := range []string{"system", "lldp_local", "lldp_rem", "lldp_man_addr", "if_mib", "stability"} {
		issues = append(issues, snap.Components[name].Issues...)
	}
	snap.Issues = issues
	if errResult != nil && !sysSupported && !lldpChassisPresent && len(localPorts) == 0 && len(neighbors) == 0 && len(ifaces) == 0 {
		// No trustworthy fact was obtained: the model contract requires a nil
		// snapshot so the CLI reports a complete failure (exit 4), not partial.
		return nil, errResult
	}
	snap.CollectedAt = time.Now().UTC()
	if errResult != nil {
		snap.CollectionComplete = false
		snap.AbsenceEligible = false
	}
	return snap, errResult
}

func scalarTicks(m map[string]gosnmp.SnmpPDU, oid string) (uint32, bool) {
	p, ok := m[oid]
	if !ok || !isPresent(p) || p.Type != gosnmp.TimeTicks {
		return 0, false
	}
	v, err := uint32Value(p)
	return v, err == nil
}

func (c *Collector) getMap(sess *snmp.Session, ctx context.Context, oids []string) (map[string]gosnmp.SnmpPDU, error) {
	pdus, err := sess.Get(ctx, oids)
	// A broken scalar in a multi-OID request must not hide the other scalars.
	// Do not multiply retries for offline/auth/budget/cancellation failures.
	if err != nil && len(oids) > 1 && snmp.IsCode(err, snmp.CodeOther) {
		pdus = nil
		var failures []error
		for _, oid := range oids {
			values, e := sess.Get(ctx, []string{oid})
			if e != nil {
				failures = append(failures, e)
				pdus = append(pdus, gosnmp.SnmpPDU{Name: oid, Type: gosnmp.NoSuchObject})
				continue
			}
			if len(values) == 0 {
				pdus = append(pdus, gosnmp.SnmpPDU{Name: oid, Type: gosnmp.NoSuchObject})
			} else {
				pdus = append(pdus, values[0])
			}
		}
		err = errors.Join(failures...)
	}
	m := make(map[string]gosnmp.SnmpPDU, len(pdus))
	for i, p := range pdus {
		if i < len(oids) {
			m[oids[i]] = p
		}
	}
	return m, err
}

func (c *Collector) walk(sess *snmp.Session, ctx context.Context, root string) ([]gosnmp.SnmpPDU, snmp.WalkSummary, error) {
	var pdus []gosnmp.SnmpPDU
	sum, err := sess.Walk(ctx, root, func(p gosnmp.SnmpPDU) error {
		pdus = append(pdus, p)
		return nil
	})
	return pdus, sum, err
}

func (c *Collector) parseSystem(snap *model.DeviceSnapshot, m map[string]gosnmp.SnmpPDU, issues *[]model.Issue) (supported, decoded, chassisPresent bool) {
	d := &snap.Device
	if p, ok := m[lldp.SysObjectID]; ok && isPresent(p) {
		if v, err := oidString(p); err == nil {
			d.SysObjectID = v
			supported = true
		} else {
			*issues = append(*issues, issueFromErr("system", err))
		}
	}
	if p, ok := m[lldp.SysUpTime]; ok && isPresent(p) {
		if v, err := uint32Value(p); err == nil {
			d.UptimeBefore = v
			decoded = true
		} else {
			*issues = append(*issues, issueFromErr("system", err))
		}
	}
	if p, ok := m[lldp.LldpStatsRemTablesLastChangeTime]; ok && isPresent(p) {
		if v, err := uint32Value(p); err == nil {
			d.LastChangeBefore = v
		}
	}
	if p, ok := m[lldp.SysDescr]; ok && isPresent(p) {
		d.SysDescription, _ = stringValue(p)
	}
	if p, ok := m[lldp.SysName]; ok && isPresent(p) {
		d.SysName, _ = stringValue(p)
	}
	if p, ok := m[lldp.LldpLocChassisIDSubtype]; ok && isPresent(p) {
		if v, err := uint32Value(p); err == nil && p.Type == gosnmp.Integer && v >= 1 && v <= 7 {
			d.Chassis.Subtype = uint8(v)
		}
	}
	if p, ok := m[lldp.LldpLocChassisID]; ok && isPresent(p) {
		if v, err := bytesValue(p); err == nil && len(v) > 0 && len(v) <= 255 {
			d.Chassis.Raw = v
			chassisPresent = true
		}
	}
	if p, ok := m[lldp.LldpLocSysCapSupported]; ok && isPresent(p) {
		if v, err := bitsValue(p); err == nil {
			d.CapSupported = v
			d.CapSupportedNames = lldp.CapabilityNames(v)
		}
	}
	if p, ok := m[lldp.LldpLocSysCapEnabled]; ok && isPresent(p) {
		if v, err := bitsValue(p); err == nil {
			d.CapEnabled = v
			d.CapEnabledNames = lldp.CapabilityNames(v)
		}
	}
	chassisPresent = chassisPresent && d.Chassis.Subtype >= 1 && d.Chassis.Subtype <= 7
	return supported, decoded, chassisPresent
}

func (c *Collector) parseAfter(snap *model.DeviceSnapshot, m map[string]gosnmp.SnmpPDU, issues *[]model.Issue) {
	d := &snap.Device
	if p, ok := m[lldp.SysUpTime]; ok && isPresent(p) {
		if v, err := uint32Value(p); err == nil {
			d.UptimeAfter = v
		} else {
			*issues = append(*issues, issueFromErr("system", err))
		}
	}
	if p, ok := m[lldp.LldpStatsRemTablesLastChangeTime]; ok && isPresent(p) {
		if v, err := uint32Value(p); err == nil {
			d.LastChangeAfter = v
		}
	}
}
