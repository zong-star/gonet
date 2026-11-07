package collector

import (
	"context"
	"fmt"
	"github.com/gosnmp/gosnmp"
	"gonet/internal/collector/lldp"
	"gonet/internal/collector/oidutil"
	"gonet/internal/collector/snmp"
	"gonet/internal/model"
	"math"
	"time"
)

const ifAdminStatus = "1.3.6.1.2.1.2.2.1.7"
const ifOperStatus = "1.3.6.1.2.1.2.2.1.8"
const ifLastChange = "1.3.6.1.2.1.2.2.1.9"

type interfaceSession interface {
	Get(context.Context, []string) ([]gosnmp.SnmpPDU, error)
	Walk(context.Context, string, func(gosnmp.SnmpPDU) error) (snmp.WalkSummary, error)
}

// CollectInterfaceStatus has its own session and budget and never requests LLDP.
func CollectInterfaceStatus(ctx context.Context, params snmp.Params) ([]model.Interface, error) {
	sess, err := snmp.NewSession(ctx, params)
	if err != nil {
		return nil, err
	}
	defer sess.Close()
	return collectInterfaceStatus(ctx, sess)
}
func collectInterfaceStatus(ctx context.Context, s interfaceSession) ([]model.Interface, error) {
	uptime := func() (uint32, error) {
		pdus, e := s.Get(ctx, []string{lldp.SysUpTime})
		if e != nil {
			return 0, e
		}
		if len(pdus) != 1 || !isPresent(pdus[0]) {
			return 0, fmt.Errorf("sysUpTime unavailable")
		}
		return lldp.AsUint32(pdus[0])
	}
	before, err := uptime()
	if err != nil {
		return nil, err
	}
	start := time.Now()
	rows := map[int32]map[string]gosnmp.SnmpPDU{}
	roots := []string{lldp.IfIndex, lldp.IfDescr, lldp.IfType, lldp.IfName, lldp.IfAlias, ifAdminStatus, ifOperStatus, ifLastChange}
	for _, root := range roots {
		sum, e := s.Walk(ctx, root, func(p gosnmp.SnmpPDU) error {
			suffix, e := oidutil.Suffix(root, p.Name)
			if e != nil || len(suffix) != 1 || suffix[0] == 0 || suffix[0] > math.MaxInt32 {
				return fmt.Errorf("invalid interface index")
			}
			i := int32(suffix[0])
			if rows[i] == nil {
				rows[i] = map[string]gosnmp.SnmpPDU{}
			}
			rows[i][root] = p
			if len(rows) > 65536 {
				return fmt.Errorf("interface row limit exceeded")
			}
			return nil
		})
		if e != nil {
			return nil, fmt.Errorf("IF-MIB walk %s: %w", root, e)
		}
		if sum.Rows == 0 && root != lldp.IfAlias {
			return nil, fmt.Errorf("IF-MIB column %s unavailable", root)
		}
	}
	after, err := uptime()
	if err != nil {
		return nil, err
	}
	// A reset or TimeTicks rollover during collection invalidates this sample.
	if after < before || time.Duration(after-before)*10*time.Millisecond > time.Since(start)+5*time.Second {
		return nil, fmt.Errorf("sysUpTime unstable during collection")
	}
	at := time.Now().UTC()
	out := []model.Interface{}
	for index, cols := range rows {
		for _, root := range roots {
			if _, ok := cols[root]; !ok && root != lldp.IfAlias {
				return nil, fmt.Errorf("incomplete IF-MIB row %d", index)
			}
		}
		iv, e := lldp.AsUint32(cols[lldp.IfIndex])
		if e != nil || iv != uint32(index) {
			return nil, fmt.Errorf("ifIndex mismatch")
		}
		typ, e := lldp.AsUint32(cols[lldp.IfType])
		if e != nil {
			return nil, e
		}
		name, e := lldp.AsString(cols[lldp.IfName])
		if e != nil {
			return nil, e
		}
		descr, e := lldp.AsString(cols[lldp.IfDescr])
		if e != nil {
			return nil, e
		}
		alias := ""
		if p, ok := cols[lldp.IfAlias]; ok {
			alias, e = lldp.AsString(p)
			if e != nil {
				return nil, e
			}
		}
		admin, e := lldp.AsUint32(cols[ifAdminStatus])
		if e != nil || admin < 1 || admin > 3 {
			return nil, fmt.Errorf("invalid ifAdminStatus")
		}
		oper, e := lldp.AsUint32(cols[ifOperStatus])
		if e != nil || oper < 1 || oper > 7 {
			return nil, fmt.Errorf("invalid ifOperStatus")
		}
		ticks, e := lldp.AsUint32(cols[ifLastChange])
		if e != nil {
			return nil, e
		}
		st := model.InterfaceStatus{AdminStatus: []string{"unknown", "up", "down", "testing"}[admin], OperStatus: []string{"unknown", "up", "down", "testing", "unknown", "dormant", "not_present", "lower_layer_down"}[oper], LastChange: &ticks, SysUpTime: after, StatusCollectedAt: &at, StatusAttemptedAt: &at, StatusCollectionState: "success", LastChangeState: "unknown"}
		// 0 means before agent initialization; a value above uptime can be from
		// a previous 32-bit uptime cycle. Preserve ticks without inventing a date.
		if ticks == 0 {
			st.LastChangeState = "before_agent_initialization"
		} else if ticks <= after {
			v := at.Add(-time.Duration(after-ticks) * 10 * time.Millisecond)
			st.LastChangeAt = &v
			st.LastChangeState = "estimated_current_uptime_cycle"
		}
		out = append(out, model.Interface{IfIndex: index, Name: name, Description: descr, Alias: alias, AliasCollected: true, Type: int32(typ), InterfaceStatus: st})
	}
	return out, nil
}
