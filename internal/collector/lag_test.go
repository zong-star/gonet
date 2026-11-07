package collector

import (
	"testing"

	"github.com/gosnmp/gosnmp"

	"gonet/internal/model"
)

func TestParseLAGEvidence(t *testing.T) {
	ifaces := []model.Interface{{IfIndex: 10, Type: 161}, {IfIndex: 11, Type: 161}, {IfIndex: 1, Type: 6}, {IfIndex: 2, Type: 6}, {IfIndex: 3, Type: 6}, {IfIndex: 20, Type: 136}}
	pdu := func(oid string, value int) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Integer, Value: value}
	}
	stack := []gosnmp.SnmpPDU{pdu(ifStackStatus+".0.10", 1), pdu(ifStackStatus+".10.1", 1),
		pdu(ifStackStatus+".11.2", 2), pdu(ifStackStatus+".20.3", 1)}
	attached := []gosnmp.SnmpPDU{pdu(lagAttachedAggID+".1", 10), pdu(lagAttachedAggID+".2", 11), pdu(lagAttachedAggID+".3", 0)}
	modes := []gosnmp.SnmpPDU{pdu(lagDebugRxState+".1", 5), pdu(lagDebugRxState+".2", 1)}
	got, complete, issues := parseLAG(ifaces, stack, attached, modes)
	if !complete || len(issues) != 0 || len(got) != 2 || got[0].Mode != "unknown" || got[1].Mode != "lacp" {
		t.Fatalf("members=%+v complete=%v issues=%+v", got, complete, issues)
	}
	stack = append(stack, pdu(ifStackStatus+".11.1", 1))
	got, complete, issues = parseLAG(ifaces, stack, attached, nil)
	if complete || len(issues) != 1 || issues[0].Code != "LAG_CONFLICT" || len(got) != 3 ||
		got[0].Status != "conflict" || got[1].Status != "conflict" || got[2].Mode != "unknown" {
		t.Fatalf("members=%+v complete=%v issues=%+v", got, complete, issues)
	}
	got, complete, _ = parseLAG(ifaces, nil, nil, nil)
	if len(got) != 0 || complete {
		t.Fatal("unavailable tables cannot establish an empty member list")
	}
}

func TestIEEEGroupIndexAndDetachedConfiguration(t *testing.T) {
	ifaces := []model.Interface{{IfIndex: 639, Type: 161}, {IfIndex: 27, Type: 6}}
	pdu := func(oid string, value int) gosnmp.SnmpPDU {
		return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.Integer, Value: value}
	}
	groups, e := parseIEEEGroups(ifaces, []gosnmp.SnmpPDU{pdu(lagActorOperKey+".639", 7)})
	if e != nil || len(groups) != 1 || *groups[0].AggregateIfIndex != 639 {
		t.Fatalf("used key instead of OID index: %+v %v", groups, e)
	}
	if _, e = parseIEEEGroups(ifaces, []gosnmp.SnmpPDU{pdu(lagActorOperKey+".27", 639)}); e == nil {
		t.Fatal("physical interface accepted as aggregator")
	}
	members, _, issues := parseLAG(ifaces, []gosnmp.SnmpPDU{pdu(ifStackStatus+".639.27", 1)}, []gosnmp.SnmpPDU{pdu(lagAttachedAggID+".27", 0)}, nil)
	if len(issues) != 0 || len(members) != 1 || members[0].AggregateIfIndex != 639 || members[0].Attached == nil || *members[0].Attached {
		t.Fatalf("detachment erased configuration: %+v %+v", members, issues)
	}
}
