package collector

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"gonet/internal/collector/lldp"
	"gonet/internal/collector/snmp"
)

type scalarSession struct {
	requests       [][]string
	fail           func(int, []string) error
	missingChassis bool
	closed         bool
}

func (s *scalarSession) Close() error  { s.closed = true; return nil }
func (s *scalarSession) PDUsUsed() int { return len(s.requests) }
func (s *scalarSession) Get(_ context.Context, oids []string) ([]gosnmp.SnmpPDU, error) {
	s.requests = append(s.requests, append([]string(nil), oids...))
	if s.fail != nil {
		if err := s.fail(len(s.requests), oids); err != nil {
			return nil, err
		}
	}
	var out []gosnmp.SnmpPDU
	for _, o := range oids {
		p := gosnmp.SnmpPDU{Name: "." + o, Type: gosnmp.OctetString}
		switch o {
		case lldp.SysObjectID:
			p.Type = gosnmp.ObjectIdentifier
			p.Value = "1.3.6.1.4.1.99999.1"
		case lldp.SysName:
			p.Value = []byte("office")
		case lldp.SysDescr:
			p.Value = []byte("fixture model")
		case lldp.SysUpTime:
			p.Type = gosnmp.TimeTicks
			p.Value = uint32(123)
		case lldp.LldpLocChassisIDSubtype:
			p.Type = gosnmp.Integer
			p.Value = 4
		case lldp.LldpLocChassisID:
			p.Value = []byte{2, 0, 0, 0, 0, 42}
		default:
			panic("probe requested an unexpected OID")
		}
		if s.missingChassis && (o == lldp.LldpLocChassisID || o == lldp.LldpLocChassisIDSubtype) {
			p.Type = gosnmp.NoSuchObject
			p.Value = nil
		}
		out = append(out, p)
	}
	return out, nil
}
func TestBasicProbeOnlyGroupedScalarsWithoutPing(t *testing.T) {
	s := &scalarSession{}
	p := NewProber(ProbeOptions{Profile: "fixture", HostTimeout: time.Second, Open: func(context.Context, snmp.Params) (ProbeSession, error) { return s, nil }})
	a := p.Probe(context.Background(), netip.MustParseAddr("192.0.2.42"))
	if !a.Reachable || !a.Attempted || a.ResponseIP != a.IP || a.Facts.SysName != "office" || a.Facts.Chassis.Subtype != 4 || a.PDUs != 2 || len(s.requests[0]) != 4 || len(s.requests[1]) != 2 || !s.closed {
		t.Fatalf("bad scalar-only probe: %+v", a)
	}
}
func TestBasicProbeSystemFactsSurviveMissingChassis(t *testing.T) {
	s := &scalarSession{missingChassis: true}
	p := NewProber(ProbeOptions{Open: func(context.Context, snmp.Params) (ProbeSession, error) { return s, nil }})
	a := p.Probe(context.Background(), netip.MustParseAddr("192.0.2.42"))
	if !a.Reachable || a.Facts.SysName != "office" || a.Facts.Chassis.Subtype != 0 || len(a.Facts.Chassis.Raw) != 0 {
		t.Fatal("missing chassis lost system facts or fabricated identity")
	}
}
func TestBasicProbeBoundedFallbackAndNoAuthRetry(t *testing.T) {
	for _, code := range []snmp.Code{snmp.CodeOther, snmp.CodeAuth, snmp.CodeTimeout, snmp.CodeCanceled} {
		t.Run(string(code), func(t *testing.T) {
			s := &scalarSession{fail: func(_ int, oids []string) error {
				if len(oids) > 1 {
					return &snmp.Error{Code: code, Err: errors.New("fixture failure")}
				}
				return nil
			}}
			p := NewProber(ProbeOptions{Open: func(context.Context, snmp.Params) (ProbeSession, error) { return s, nil }})
			a := p.Probe(context.Background(), netip.MustParseAddr("192.0.2.42"))
			if code == snmp.CodeOther {
				if !a.Reachable || a.PDUs != 8 {
					t.Fatalf("fallback count=%d reachable=%v", a.PDUs, a.Reachable)
				}
			} else if a.PDUs != 1 || a.Reachable || a.ErrorCode != string(code) {
				t.Fatalf("transport error multiplied requests: %+v", a)
			}
		})
	}
}

func TestBasicProbeStopsFallbackOnTerminalError(t *testing.T) {
	s := &scalarSession{fail: func(n int, _ []string) error {
		code := snmp.CodeOther
		if n == 3 {
			code = snmp.CodeAuth
		}
		return &snmp.Error{Code: code}
	}}
	p := NewProber(ProbeOptions{Open: func(context.Context, snmp.Params) (ProbeSession, error) { return s, nil }})
	a := p.Probe(context.Background(), netip.MustParseAddr("192.0.2.42"))
	if a.PDUs != 3 || a.ErrorCode != "SNMP_AUTH" {
		t.Fatalf("fallback masked terminal error or continued: %+v", a)
	}
}
