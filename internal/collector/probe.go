package collector

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"gonet/internal/collector/lldp"
	"gonet/internal/collector/snmp"
	"gonet/internal/preprobe"
)

// ProbeSession supports only scalar GET; a basic probe cannot walk any table.
type ProbeSession interface {
	Get(context.Context, []string) ([]gosnmp.SnmpPDU, error)
	Close() error
	PDUsUsed() int
}
type ProbeOptions struct {
	Params      snmp.Params
	HostTimeout time.Duration
	Profile     string
	Open        func(context.Context, snmp.Params) (ProbeSession, error)
}
type Prober struct{ opts ProbeOptions }

func NewProber(o ProbeOptions) *Prober {
	if o.Open == nil {
		o.Open = func(ctx context.Context, p snmp.Params) (ProbeSession, error) { return snmp.NewSession(ctx, p) }
	}
	return &Prober{opts: o}
}

func probeFailure(err error) (string, string) {
	var e *snmp.Error
	if errors.As(err, &e) {
		return string(e.Code), string(e.Code)
	}
	if errors.Is(err, context.Canceled) {
		return "CANCELED", "probe canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "SNMP_TIMEOUT", "SNMP timeout"
	}
	return "SNMP_ERROR", "SNMP request failed"
}

func (p *Prober) Probe(ctx context.Context, a netip.Addr) (out preprobe.Attempt) {
	started := time.Now().UTC()
	out.IP = a.Unmap()
	out.Facts.Target = out.IP
	out.Profile = p.opts.Profile
	defer func() { out.At = time.Now().UTC(); out.Elapsed = time.Since(started) }()
	if p.opts.HostTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.opts.HostTimeout)
		defer cancel()
	}
	params := p.opts.Params
	params.Target = out.IP.String()
	s, err := p.opts.Open(ctx, params)
	if err != nil {
		out.ErrorCode, out.ErrorReason = probeFailure(err)
		return
	}
	defer s.Close()
	defer func() { out.PDUs = s.PDUsUsed() }()
	get := func(oids []string) (map[string]gosnmp.SnmpPDU, error) {
		if ctx.Err() == nil {
			out.Attempted = true
		}
		values, e := s.Get(ctx, oids)
		if e == nil {
			out.Reachable = true
		}
		// Isolate a broken scalar only for the existing recoverable error class.
		// Every fallback stays inside the same session PDU and host deadline.
		if e != nil && snmp.IsCode(e, snmp.CodeOther) && len(oids) > 1 {
			values = nil
			var failures []error
			var terminal error
			for _, oid := range oids {
				v, x := s.Get(ctx, []string{oid})
				if x != nil {
					failures = append(failures, x)
					if !snmp.IsCode(x, snmp.CodeOther) {
						terminal = x
						break
					}
					continue
				}
				out.Reachable = true
				values = append(values, v...)
			}
			e = errors.Join(failures...)
			if terminal != nil {
				e = terminal
			}
		}
		m := map[string]gosnmp.SnmpPDU{}
		for _, v := range values {
			if isPresent(v) {
				m[strings.TrimPrefix(v.Name, ".")] = v
			}
		}
		return m, e
	}
	first, err := get([]string{lldp.SysObjectID, lldp.SysName, lldp.SysDescr, lldp.SysUpTime})
	if v, ok := first[lldp.SysObjectID]; ok {
		out.Facts.SysObjectID, _ = oidString(v)
	}
	if v, ok := first[lldp.SysName]; ok {
		out.Facts.SysName, _ = stringValue(v)
	}
	if v, ok := first[lldp.SysDescr]; ok {
		out.Facts.SysDescription, _ = stringValue(v)
	}
	// Advertised strings are bounded before being persisted or logged.
	if len(out.Facts.SysName) > 512 {
		out.Facts.SysName = strings.ToValidUTF8(out.Facts.SysName[:512], "�")
	}
	if len(out.Facts.SysDescription) > 4096 {
		out.Facts.SysDescription = strings.ToValidUTF8(out.Facts.SysDescription[:4096], "�")
	}
	if v, ok := first[lldp.SysUpTime]; ok {
		out.Facts.UptimeBefore, _ = uint32Value(v)
	}
	if err != nil {
		out.ErrorCode, out.ErrorReason = probeFailure(err)
		if !snmp.IsCode(err, snmp.CodeOther) {
			if out.Reachable {
				out.ResponseIP = out.IP
			}
			return
		}
	}
	second, e := get([]string{lldp.LldpLocChassisIDSubtype, lldp.LldpLocChassisID})
	if e != nil {
		out.ErrorCode, out.ErrorReason = probeFailure(e)
	}
	if v, ok := second[lldp.LldpLocChassisIDSubtype]; ok {
		if n, x := uint32Value(v); x == nil && n >= 1 && n <= 7 {
			out.Facts.Chassis.Subtype = uint8(n)
		}
	}
	if v, ok := second[lldp.LldpLocChassisID]; ok {
		out.Facts.Chassis.Raw, _ = bytesValue(v)
		if len(out.Facts.Chassis.Raw) > 255 {
			out.Facts.Chassis.Raw = nil
			out.ErrorCode = "CHASSIS_INVALID"
			out.ErrorReason = "local chassis exceeds 255 bytes"
		}
	}
	if out.Reachable {
		out.ResponseIP = out.IP
	}
	return
}
