package collector

import (
	"errors"
	"fmt"

	"github.com/gosnmp/gosnmp"

	"gonet/internal/collector/lldp"
	"gonet/internal/collector/oidutil"
	"gonet/internal/collector/snmp"
	"gonet/internal/model"
)

func oidString(p gosnmp.SnmpPDU) (string, error) {
	if p.Type != gosnmp.ObjectIdentifier {
		return "", fmt.Errorf("expected ASN.1 OBJECT IDENTIFIER at %s", p.Name)
	}
	switch v := p.Value.(type) {
	case string:
		if _, err := oidutil.Split(v); err != nil {
			return "", err
		}
		return v, nil
	case []byte:
		if _, err := oidutil.Split(string(v)); err != nil {
			return "", err
		}
		return string(v), nil
	default:
		return "", fmt.Errorf("expected OID at %s, got %T", p.Name, p.Value)
	}
}

func uint32Value(p gosnmp.SnmpPDU) (uint32, error) { return lldp.AsUint32(p) }
func bytesValue(p gosnmp.SnmpPDU) ([]byte, error)  { return lldp.AsBytes(p) }
func bitsValue(p gosnmp.SnmpPDU) ([]byte, error)   { return lldp.AsBits(p) }
func stringValue(p gosnmp.SnmpPDU) (string, error) { return lldp.AsString(p) }

func isPresent(p gosnmp.SnmpPDU) bool {
	return p.Type != gosnmp.NoSuchObject && p.Type != gosnmp.NoSuchInstance && p.Value != nil
}

func issueFromErr(component string, err error) model.Issue {
	var se *snmp.Error
	if errors.As(err, &se) {
		msg := ""
		if se.Err != nil {
			msg = se.Err.Error()
		}
		return model.Issue{
			Code:      string(se.Code),
			Component: component,
			Message:   msg,
			Retryable: se.Code == snmp.CodeTimeout,
		}
	}
	return model.Issue{Code: "SNMP_ERROR", Component: component, Message: err.Error()}
}

func appendAll(slices ...[]gosnmp.SnmpPDU) []gosnmp.SnmpPDU {
	var out []gosnmp.SnmpPDU
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}

func combineSum(sums ...snmp.WalkSummary) snmp.WalkSummary {
	var out snmp.WalkSummary
	for _, s := range sums {
		out.Rows += s.Rows
		out.Requests += s.Requests
		out.FirstEndOfView = out.FirstEndOfView || s.FirstEndOfView
	}
	return out
}

func componentStatus(sum snmp.WalkSummary, err error, decodeOK, supported bool) model.ComponentStatus {
	cs := model.ComponentStatus{
		Supported:      supported,
		WalkComplete:   err == nil,
		DecodeComplete: decodeOK,
	}
	if err != nil {
		cs.Issues = append(cs.Issues, issueFromErr("walk", err))
	}
	return cs
}

func remoteComponentStatus(sum snmp.WalkSummary, err error, decodeOK, hasRows, lldpChassisPresent, viewVerified bool) model.ComponentStatus {
	cs := model.ComponentStatus{WalkComplete: err == nil, DecodeComplete: decodeOK}
	if err != nil {
		cs.Issues = append(cs.Issues, issueFromErr("lldp_rem", err))
	}
	switch {
	case hasRows:
		cs.Supported = true
	case sum.FirstEndOfView:
		cs.Supported = false
		cs.Issues = append(cs.Issues, model.Issue{
			Code: "MIB_UNSUPPORTED", Component: "lldp_rem",
			Message: "lldpRemTable not present in view (noSuchObject/endOfMibView)",
		})
	case lldpChassisPresent && viewVerified:
		// LLDP is present and the view is confirmed; a zero-row walk is a valid
		// empty neighbor table.
		cs.Supported = true
	default:
		cs.Supported = false
		cs.Issues = append(cs.Issues, model.Issue{
			Code: "VIEW_UNVERIFIED", Component: "lldp_rem",
			Message: "empty lldpRemTable walk; support not verified",
		})
	}
	return cs
}
