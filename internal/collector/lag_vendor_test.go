package collector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"gonet/internal/collector/lldp"
	"gonet/internal/collector/snmp"
	"gonet/internal/model"
)

func vendorFixture(t *testing.T, name string) (model.DeviceSnapshot, map[string][]gosnmp.SnmpPDU) {
	t.Helper()
	b, e := os.ReadFile(filepath.Join("../../testdata/adapters/lag-vendors", name+".json"))
	if e != nil {
		t.Fatal(e)
	}
	var fixture struct {
		Snapshot model.DeviceSnapshot `json:"snapshot"`
		Roots    map[string][]struct {
			OID, Type string
			Value     json.RawMessage
		} `json:"roots"`
	}
	if e = json.Unmarshal(b, &fixture); e != nil {
		t.Fatal(e)
	}
	out := map[string][]gosnmp.SnmpPDU{}
	for root, facts := range fixture.Roots {
		for _, f := range facts {
			p := gosnmp.SnmpPDU{Name: f.OID}
			switch f.Type {
			case "OctetString":
				var s string
				if e = json.Unmarshal(f.Value, &s); e != nil {
					t.Fatal(e)
				}
				v, e := base64.StdEncoding.DecodeString(s)
				if e != nil {
					t.Fatal(e)
				}
				p.Type, p.Value = gosnmp.OctetString, v
			case "Integer":
				var n int
				if e = json.Unmarshal(f.Value, &n); e != nil {
					t.Fatal(e)
				}
				p.Type, p.Value = gosnmp.Integer, n
			case "Gauge32", "Counter32", "TimeTicks":
				var n uint32
				if e = json.Unmarshal(f.Value, &n); e != nil {
					t.Fatal(e)
				}
				p.Type, p.Value = gosnmp.Gauge32, n
			default:
				t.Fatalf("unhandled fixture type %s", f.Type)
			}
			out[root] = append(out[root], p)
		}
	}
	var all []gosnmp.SnmpPDU
	for _, rows := range out {
		all = append(all, rows...)
	}
	for _, root := range []string{hwTrunkIfIndex, hwTrunkValid, hh3cMode, hh3cMembers, hh3cSelected} {
		out[root] = column(all, root)
	}
	return fixture.Snapshot, out
}
func column(rows []gosnmp.SnmpPDU, root string) []gosnmp.SnmpPDU {
	var result []gosnmp.SnmpPDU
	for _, p := range rows {
		if strings.HasPrefix(strings.TrimPrefix(p.Name, "."), root+".") {
			result = append(result, p)
		}
	}
	return result
}

func TestHuaweiLAGCapturedIndicesAndRole(t *testing.T) {
	s, roots := vendorFixture(t, "huawei-s5735-qa2")
	if !huaweiLAGDevice(s.Device) {
		t.Fatal("exact firmware did not match")
	}
	other := s.Device
	other.SysDescription = strings.ReplaceAll(other.SysDescription, "SPC500", "SPC500other")
	if huaweiLAGDevice(other) {
		t.Fatal("firmware suffix broadened adapter scope")
	}
	g, m, e := parseHuaweiLAG(&s, roots[hwTrunkIfIndex], roots[hwTrunkValid])
	if e != nil || len(g) != 1 || g[0].SourceGroupID != "huawei:0" || *g[0].AggregateIfIndex != 19 || len(m) != 2 {
		t.Fatalf("groups=%+v members=%+v err=%v", g, m, e)
	}
	for _, r := range m {
		if r.AggregateIfIndex != 19 || r.MemberIfIndex != 16 && r.MemberIfIndex != 17 || r.Mode != "unknown" {
			t.Fatalf("incorrect mapped relation %+v", r)
		}
	}
	for _, i := range s.Interfaces {
		if i.IfIndex == 19 && i.Type != 53 {
			t.Fatal("raw interface type was rewritten")
		}
	}
	s.Device.SysDescription = strings.ReplaceAll(s.Device.SysDescription, "SPC500", "SPC999")
	if huaweiLAGDevice(s.Device) {
		t.Fatal("unverified firmware enabled")
	}
	bad := append([]gosnmp.SnmpPDU{}, roots[hwTrunkValid]...)
	bad[0].Name = hwTrunkValid + ".7.16"
	if _, _, e = parseHuaweiLAG(&s, roots[hwTrunkIfIndex], bad); e == nil {
		t.Fatal("unmapped private group accepted")
	}
	_, empty, e := parseHuaweiLAG(&s, nil, nil)
	if e != nil || len(empty) != 0 {
		t.Fatal("names alone created members")
	}
}

func TestH3CCapturedStaticAndSingleLink(t *testing.T) {
	s, roots := vendorFixture(t, "h3c-s5560x")
	if !h3cLAGDevice(s.Device) {
		t.Fatal("exact H3C fingerprint did not match")
	}
	s.LAGMembers, _, _ = parseLAG(s.Interfaces, nil, column(roots["1.2.840.10006.300.43.1.2.1"], lagAttachedAggID), nil)
	if e := applyH3CLAG(&s, roots[hh3cMode], roots[hh3cMembers], roots[hh3cSelected]); e != nil {
		t.Fatal(e)
	}
	reconcileLAG(&s)
	if len(s.LAGMembers) != 4 {
		t.Fatalf("lost baseline members %+v", s.LAGMembers)
	}
	for _, r := range s.LAGMembers {
		if r.Mode != "static" || r.Selected == nil || !*r.Selected {
			t.Fatalf("mode/selection %+v", r)
		}
	}
	access, raw := vendorFixture(t, "h3c-s5130s-single")
	members, _, issues := parseLAG(access.Interfaces, nil, column(raw["1.2.840.10006.300.43.1.2.1"], lagAttachedAggID), nil)
	if len(members) != 0 || len(issues) != 0 {
		t.Fatal("single physical uplink became aggregation")
	}
}

func TestCapturedAdvertisementsNeverInventSundrayIfIndex(t *testing.T) {
	s, roots := vendorFixture(t, "h3c-s5560x")
	ads, e := parseLAGAdvertisements(&s, remLinkAgg, "remote", roots[remLinkAgg])
	if e != nil {
		t.Fatal(e)
	}
	n := 0
	for _, ad := range ads {
		if ad.Index.LocalPortNum == 27 || ad.Index.LocalPortNum == 28 {
			n++
			if !ad.Enabled || ad.AggregateID != 27 || ad.MemberIfIndex == nil || *ad.MemberIfIndex != int32(ad.Index.LocalPortNum) {
				t.Fatalf("wrong namespace %+v", ad)
			}
		}
	}
	if n != 2 {
		t.Fatal("core advertisements missing")
	}
	core, raw := vendorFixture(t, "sundray-ts7914")
	if len(raw["1.2.840.10006.300.43.1.2.1"]) != 0 {
		t.Fatal("unexpected core source")
	}
	reconcileLAG(&core)
	if len(core.LAGMembers) != 0 {
		t.Fatal("interface names fabricated core members")
	}
	if len(core.LAGGroups) != 34 {
		t.Fatal("IF-MIB aggregate role facts were lost")
	}
}

func TestHuaweiLAGRealCollectorAgainstLocalAgent(t *testing.T) {
	s, roots := vendorFixture(t, "huawei-s5735-qa2")
	oids := sampleFixture()
	oids[lldp.SysObjectID] = gosnmp.SnmpPDU{Name: lldp.SysObjectID, Type: gosnmp.ObjectIdentifier, Value: s.Device.SysObjectID}
	oids[lldp.SysDescr] = gosnmp.SnmpPDU{Name: lldp.SysDescr, Type: gosnmp.OctetString, Value: []byte(s.Device.SysDescription)}
	for key := range oids {
		if strings.HasPrefix(key, lldp.IfName+".") || strings.HasPrefix(key, lldp.IfDescr+".") || strings.HasPrefix(key, lldp.IfType+".") {
			delete(oids, key)
		}
	}
	for _, i := range s.Interfaces {
		for _, f := range []struct {
			oid   string
			kind  gosnmp.Asn1BER
			value any
		}{{lldp.IfName, gosnmp.OctetString, []byte(i.Name)}, {lldp.IfDescr, gosnmp.OctetString, []byte(i.Description)}, {lldp.IfType, gosnmp.Integer, int(i.Type)}} {
			key := f.oid + "." + fmtIndex(i.IfIndex)
			oids[key] = gosnmp.SnmpPDU{Name: key, Type: f.kind, Value: f.value}
		}
	}
	for _, root := range []string{hwTrunkIfIndex, hwTrunkValid} {
		for _, p := range roots[root] {
			p.Name = strings.TrimPrefix(p.Name, ".")
			oids[p.Name] = p
		}
	}
	a := startFixture(t, oids)
	host, portText, _ := net.SplitHostPort(a.addr())
	var port uint16
	for _, ch := range portText {
		port = port*10 + uint16(ch-'0')
	}
	c := New(Options{Params: snmp.Params{Target: host, Port: port, Version: "2c", Community: "public", Timeout: time.Second, MaxPDUs: 500}, Adapters: []string{HuaweiLAGAdapter}, DeviceTimeout: 5 * time.Second, ViewVerified: false})
	snap, e := c.Collect(context.Background(), model.DiscoveryTarget{Address: mustAddr(host)})
	if e != nil || snap == nil || len(snap.LAGMembers) != 2 || len(snap.LAGGroups) != 1 {
		t.Fatalf("collector did not persist positive private facts: %v %+v", e, snap)
	}
	if snap.LAGGroups[0].Complete {
		t.Fatal("unverified view reported complete")
	}
}
func fmtIndex(n int32) string { b, _ := json.Marshal(n); return string(b) }
