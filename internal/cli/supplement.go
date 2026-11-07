package cli

import (
	"context"
	"gonet/internal/collector/lldp"
	"gonet/internal/collector/snmp"
	"gonet/internal/config"
	"gonet/internal/control"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/webui"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// This explicitly requested pass only builds access hints. It never seeds a
// device or creates a link; discovery must independently see its LLDP chassis.
func supplementAddresses(ctx context.Context, cfg *config.Config, addrs []netip.Addr, progress func(webui.Progress)) map[string][]netip.Addr {
	type hint struct {
		address netip.Addr
		keys    []string
	}
	work := make(chan netip.Addr)
	results := make(chan hint)
	var wg sync.WaitGroup
	workers := cfg.Discovery.Workers
	if workers > 8 {
		workers = 8
	}
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range work {
				keys := probeChassis(ctx, cfg, a)
				results <- hint{a, keys}
			}
		}()
	}
	go func() {
		defer close(work)
		for _, a := range addrs {
			select {
			case work <- a:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	hints := map[string][]netip.Addr{}
	done := 0
	progress(webui.Progress{Stage: "address_lookup", Scheduled: len(addrs)})
	for h := range results {
		done++
		for _, k := range h.keys {
			hints[k] = append(hints[k], h.address)
		}
		progress(webui.Progress{Stage: "address_lookup", Target: h.address.String(), Completed: done, Scheduled: len(addrs)})
	}
	return hints
}
func probeChassis(ctx context.Context, cfg *config.Config, a netip.Addr) []string {
	if !cfg.InManagementScope(a) {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	name, e := cfg.ResolveProfileForAddr(a)
	if e != nil {
		return nil
	}
	profile, e := cfg.ResolveProfile(name)
	if e != nil {
		return nil
	}
	p := snmpParams(cfg, profile)
	p.Target = a.String()
	p.Timeout = time.Second
	p.Retries = 0
	p.MaxPDUs = 4
	session, e := snmp.NewSession(ctx, p)
	if e != nil {
		return nil
	}
	defer session.Close()
	pdus, e := session.Get(ctx, []string{lldp.LldpLocChassisIDSubtype, lldp.LldpLocChassisID})
	if e != nil {
		return nil
	}
	id := model.TypedID{}
	for _, pdu := range pdus {
		switch strings.TrimPrefix(pdu.Name, ".") {
		case strings.TrimPrefix(lldp.LldpLocChassisIDSubtype, "."):
			if v, err := lldp.AsUint32(pdu); err == nil && v <= 7 {
				id.Subtype = uint8(v)
			}
		case strings.TrimPrefix(lldp.LldpLocChassisID, "."):
			id.Raw, _ = lldp.AsBytes(pdu)
		}
	}
	key, ok := identity.NormalizedKey(id, cfg.Identity.AllowNetworkAddressChassis)
	if !ok {
		return nil
	}
	keys := map[string]bool{key: true}
	if mac, ok := identity.ChassisMAC(id); ok {
		keys[identity.WeakKey(4, mac)] = true
		keys[identity.WeakKey(7, mac)] = true
	}
	return control.SortedKeys(keys)
}
