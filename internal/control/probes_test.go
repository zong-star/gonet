package control

import (
	"net/netip"
	"testing"
	"time"

	"gonet/internal/config"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/preprobe"
	"gonet/internal/store/postgres"
)

func TestProbeProjectionRechecksPolicyFreshnessAndAssociation(t *testing.T) {
	now := time.Now()
	old := now.Add(-time.Hour)
	id := int64(85)
	facts := &model.DeviceInfo{Chassis: model.TypedID{Subtype: 4, Raw: []byte{2, 0, 0, 0, 0, 2}}, SysName: "<untrusted>"}
	exp := &postgres.TopologyExport{ProbePool: []preprobe.Record{
		{IP: netip.MustParseAddr("192.0.2.2"), Identity: "lldp:4:020000000002", Facts: facts, Status: "identified", LastSuccess: &old, LastIdentitySuccess: &old, MatchedDeviceID: &id},
		{IP: netip.MustParseAddr("192.0.2.3"), Identity: "lldp:4:020000000003", Facts: facts, Status: "unresponsive", LastSuccess: &now, LastIdentitySuccess: &now},
	}, ProbeSummary: preprobe.Summary{Cursor: preprobe.Cursor{ScopeDigest: "old", Covered: 254}, Completed: 200}, Links: []postgres.ExportLink{{DeviceAID: 85, DeviceBID: 1}}}
	cfg := &config.Config{Discovery: config.DiscoveryConfig{Preprobe: config.PreprobeConfig{Enabled: true, RefreshInterval: config.Duration{Duration: time.Minute}}}}
	s := Scope{Settings: Settings{AllowedCIDRs: []string{"192.0.2.0/24"}, ExcludedCIDRs: []string{"192.0.2.3/32"}}}
	PrepareProbeView(exp, cfg, s.Settings)
	p := projectProbes(exp, s)
	if exp.ProbeSummary.RangeHosts != 253 || exp.ProbeSummary.Completed != 0 || exp.ProbeSummary.Cursor.Covered != 0 {
		t.Fatal("policy change retained misleading previous coverage")
	}
	if len(p) != 2 || p[0].CacheStatus != "stale" || p[0].TopologyStatus != "linked" || p[1].ScopeStatus != "excluded_or_out_of_scope" {
		t.Fatalf("projection lost facts/eligibility: %+v", p)
	}
	if p[0].Facts.SysName != "<untrusted>" || p[0].MatchedDeviceID == nil || *p[0].MatchedDeviceID != 85 {
		t.Fatal("display projection rewrote identity or successful facts")
	}
}

func TestProbeModelUsesVerifiedAssociationWithoutIPGuessing(t *testing.T) {
	id := int64(85)
	v := &View{Devices: []Device{{ExportDevice: postgres.ExportDevice{ID: id}, Source: "inventory", Model: "S5560X-30F-EI"}}, ProbePool: []Probe{
		{Record: preprobe.Record{Rule: "classified-without-label", MatchedDeviceID: &id}},
		{Record: preprobe.Record{Rule: "classified-without-label"}},
		{Record: preprobe.Record{Rule: "classified-without-label", MatchedDeviceID: &id, Conflict: true}},
		{Record: preprobe.Record{Rule: "exact-model", MatchedDeviceID: &id}},
	}}
	LabelModels(v, []identity.Rule{{ID: "classified-without-label", Action: "switch", SysObjectIDPrefix: "1.3.6.1.4.1.99999"}, {ID: "exact-model", Action: "switch", SysObjectIDPrefix: "1.3.6.1.4.1.88888", Model: "Direct-model"}})
	if v.ProbePool[0].Model != "S5560X-30F-EI" || v.ProbePool[1].Model != "" || v.ProbePool[2].Model != "" || v.ProbePool[3].Model != "Direct-model" {
		t.Fatalf("incorrect model projection: %+v", v.ProbePool)
	}
}
