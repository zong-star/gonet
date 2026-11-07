package collector

import (
	"context"
	"fmt"
	"github.com/gosnmp/gosnmp"
	"gonet/internal/collector/lldp"
	"gonet/internal/collector/snmp"
	"net"
	"strconv"
	"testing"
	"time"
)

func statusFixture(admin, oper int, ticks uint32) map[string]gosnmp.SnmpPDU {
	r := map[string]gosnmp.SnmpPDU{}
	add := func(oid string, typ gosnmp.Asn1BER, value any) {
		r[oid] = gosnmp.SnmpPDU{Name: oid, Type: typ, Value: value}
	}
	add(lldp.SysUpTime, gosnmp.TimeTicks, uint32(100000))
	for _, i := range []int{1, 2, 100} {
		suffix := "." + strconv.Itoa(i)
		add(lldp.IfIndex+suffix, gosnmp.Integer, i)
		add(lldp.IfDescr+suffix, gosnmp.OctetString, []byte(fmt.Sprintf("port%d", i)))
		typ := 6
		if i == 100 {
			typ = 161
		}
		add(lldp.IfType+suffix, gosnmp.Integer, typ)
		add(lldp.IfName+suffix, gosnmp.OctetString, []byte(fmt.Sprintf("Ethernet%d", i)))
		add(lldp.IfAlias+suffix, gosnmp.OctetString, []byte("uplink"))
		add(ifAdminStatus+suffix, gosnmp.Integer, admin)
		add(ifOperStatus+suffix, gosnmp.Integer, oper)
		add(ifLastChange+suffix, gosnmp.TimeTicks, ticks)
	}
	return r
}
func TestInterfaceStatusRealSNMPVendors(t *testing.T) {
	for _, vendor := range []string{"H3C", "Huawei", "Sundray"} {
		for _, st := range []struct {
			name        string
			admin, oper int
			want        string
		}{{"up", 1, 1, "up"}, {"down", 1, 2, "down"}, {"admin_down", 2, 2, "down"}} {
			t.Run(vendor+"/"+st.name, func(t *testing.T) {
				f := startFixture(t, statusFixture(st.admin, st.oper, 90000))
				host, port, _ := net.SplitHostPort(f.addr())
				p, _ := strconv.Atoi(port)
				rows, e := CollectInterfaceStatus(context.Background(), snmp.Params{Target: host, Port: uint16(p), Version: "2c", Community: "public", Timeout: time.Second, MaxPDUs: 100, MaxRepetitions: 20})
				if e != nil {
					t.Fatal(e)
				}
				if len(rows) != 3 {
					t.Fatal(len(rows))
				}
				for _, i := range rows {
					if i.OperStatus != st.want || i.LastChange == nil || *i.LastChange != 90000 || i.LastChangeAt == nil || time.Since(*i.LastChangeAt) < 99*time.Second || time.Since(*i.LastChangeAt) > 102*time.Second {
						t.Fatalf("%+v", i)
					}
				}
				f.mu.Lock()
				defer f.mu.Unlock()
				for _, oid := range f.requested {
					if len(oid) >= len("1.0.8802") && oid[:len("1.0.8802")] == "1.0.8802" {
						t.Fatal("status poll requested LLDP")
					}
				}
			})
		}
	}
}

type statusReplay struct {
	uptimes []uint32
	rows    map[string]gosnmp.SnmpPDU
	fail    string
}

func (s *statusReplay) Get(context.Context, []string) ([]gosnmp.SnmpPDU, error) {
	v := s.uptimes[0]
	s.uptimes = s.uptimes[1:]
	return []gosnmp.SnmpPDU{{Type: gosnmp.TimeTicks, Value: v}}, nil
}
func (s *statusReplay) Walk(_ context.Context, root string, cb func(gosnmp.SnmpPDU) error) (snmp.WalkSummary, error) {
	if root == s.fail {
		return snmp.WalkSummary{}, fmt.Errorf("SNMP_TIMEOUT")
	}
	n := 0
	for _, p := range s.rows {
		if len(p.Name) > len(root) && p.Name[:len(root)+1] == root+"." {
			n++
			if e := cb(p); e != nil {
				return snmp.WalkSummary{}, e
			}
		}
	}
	return snmp.WalkSummary{Rows: n}, nil
}
func TestInterfaceStatusTimeTicksAndFailures(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		ticks, before, after uint32
		fail                 string
		wantError            bool
		wantDate             bool
	}{{"zero", 0, 100000, 100000, "", false, false}, {"normal", 90000, 100000, 100000, "", false, true}, {"previous_cycle", 200000, 100000, 100000, "", false, false}, {"reboot", 100, 100000, 1000, "", true, false}, {"wrap_during_poll", 100, 4294967290, 20, "", true, false}, {"timeout", 100, 100000, 100000, ifOperStatus, true, false}} {
		t.Run(tt.name, func(t *testing.T) {
			s := &statusReplay{uptimes: []uint32{tt.before, tt.after}, rows: statusFixture(1, 1, tt.ticks), fail: tt.fail}
			r, e := collectInterfaceStatus(context.Background(), s)
			if (e != nil) != tt.wantError {
				t.Fatal(e)
			}
			if e == nil {
				for _, i := range r {
					if (i.LastChangeAt != nil) != tt.wantDate {
						t.Fatalf("%+v", i)
					}
				}
			} else if r != nil {
				t.Fatal("partial sample escaped")
			}
		})
	}
	s := &statusReplay{uptimes: []uint32{100000, 100000}, rows: statusFixture(1, 1, 100)}
	delete(s.rows, ifOperStatus+".2")
	if _, e := collectInterfaceStatus(context.Background(), s); e == nil {
		t.Fatal("missing row accepted")
	}
}
