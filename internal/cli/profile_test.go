package cli

import (
	"context"
	"gonet/internal/config"
	"gonet/internal/model"
	"net/netip"
	"testing"
)

type profileProbe struct {
	name string
	seen []model.DiscoveryTarget
}

func (p *profileProbe) Collect(_ context.Context, t model.DiscoveryTarget) (*model.DeviceSnapshot, error) {
	p.seen = append(p.seen, t)
	return &model.DeviceSnapshot{}, nil
}

func TestScanProfilesSelectedPerCandidateAddress(t *testing.T) {
	a, b := &profileProbe{name: "default"}, &profileProbe{name: "specific"}
	c := profileCollector{cfg: &config.Config{SNMP: config.SNMPConfig{DefaultProfile: "default", ProfileRules: []config.ProfileRule{{CIDR: "192.0.2.0/24", Profile: "default"}, {CIDR: "192.0.2.128/25", Profile: "specific"}}}}, byName: map[string]model.Collector{"default": a, "specific": b}}
	for _, ip := range []string{"192.0.2.1", "192.0.2.129", "198.51.100.1"} {
		if _, err := c.Collect(context.Background(), model.DiscoveryTarget{Address: netip.MustParseAddr(ip)}); err != nil {
			t.Fatal(err)
		}
	}
	if len(a.seen) != 2 || len(b.seen) != 1 || b.seen[0].Profile != "specific" {
		t.Fatal("scan/fallback address did not use longest-prefix profile")
	}
}
