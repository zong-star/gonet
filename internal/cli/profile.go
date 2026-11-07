package cli

import (
	"context"
	"gonet/internal/collector"
	"gonet/internal/config"
	"gonet/internal/model"
	"gonet/internal/preprobe"
	"net/netip"
)

// profileCollector selects credentials for each candidate address, including
// fallback addresses. Collectors contain immutable options; every call opens
// its own SNMP session.
type profileCollector struct {
	cfg    *config.Config
	byName map[string]model.Collector
	probes map[string]preprobe.Prober
}

func newProfileCollector(cfg *config.Config) (*profileCollector, error) {
	c := &profileCollector{cfg: cfg, byName: map[string]model.Collector{}, probes: map[string]preprobe.Prober{}}
	for name := range cfg.SNMP.Profiles {
		prof, err := cfg.ResolveProfile(name)
		if err != nil {
			return nil, err
		}
		c.byName[name] = collector.New(collector.Options{
			LAGTimeout: cfg.SNMP.LAGTimeout.Duration, LAGMaxPDUs: cfg.SNMP.LAGMaxPDUs,
			CollectManagementAddresses: cfg.SNMP.CollectManagementAddresses, Adapters: cfg.SNMP.Adapters,
			Params: snmpParams(cfg, prof), MaxNeighbors: cfg.SNMP.MaxNeighborsPerDevice,
			ConsistencyRetries: cfg.SNMP.ConsistencyRetries, ViewVerified: cfg.SNMP.ViewVerified,
			DeviceTimeout: cfg.SNMP.DeviceTimeout.Duration, StartupGrace: cfg.SNMP.StartupGrace.Duration,
		})
		params := snmpParams(cfg, prof)
		params.Timeout = cfg.Discovery.Preprobe.Timeout.Duration
		params.Retries = cfg.Discovery.Preprobe.Retries
		params.MaxPDUs = 10
		c.probes[name] = collector.NewProber(collector.ProbeOptions{Params: params, HostTimeout: cfg.Discovery.Preprobe.HostTimeout.Duration, Profile: name})
	}
	return c, nil
}

func (c *profileCollector) Probe(ctx context.Context, a netip.Addr) preprobe.Attempt {
	if !c.cfg.InManagementScope(a) {
		return preprobe.Attempt{IP: a, ErrorCode: "ADDRESS_OUT_OF_SCOPE"}
	}
	name, err := c.cfg.ResolveProfileForAddr(a)
	if err != nil {
		return preprobe.Attempt{IP: a, ErrorCode: "PROFILE_UNAVAILABLE"}
	}
	return c.probes[name].Probe(ctx, a)
}

func (c *profileCollector) Collect(ctx context.Context, t model.DiscoveryTarget) (*model.DeviceSnapshot, error) {
	name, err := c.cfg.ResolveProfileForAddr(t.Address.Unmap())
	if err != nil {
		return nil, err
	}
	t.Profile = name
	return c.byName[name].Collect(ctx, t)
}

func excludedPrefixes(cfg *config.Config) []netip.Prefix {
	var out []netip.Prefix
	for _, raw := range cfg.Discovery.ExcludedCIDRs {
		if p, err := netip.ParsePrefix(raw); err == nil {
			out = append(out, p.Masked())
		}
	}
	return out
}
