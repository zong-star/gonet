package discovery

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"github.com/gosnmp/gosnmp"
	"gonet/internal/collector/lldp"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/topology"
	"net/netip"
	"os"
	"testing"
)

func realNoIPCoordinator(t *testing.T, adapt, inventory bool) (*Coordinator, *fakeCollector, netip.Addr) {
	t.Helper()
	b, e := os.ReadFile("../../testdata/adapters/sundray-ts7914/h3c-pair.json")
	if e != nil {
		t.Fatal(e)
	}
	var p struct {
		Core model.DeviceSnapshot `json:"core"`
		Peer model.DeviceSnapshot `json:"peer"`
	}
	if e = json.Unmarshal(b, &p); e != nil {
		t.Fatal(e)
	}
	if adapt {
		n := p.Core.Neighbors[0]
		var pdus []gosnmp.SnmpPDU
		for _, v := range []struct {
			col   string
			typ   gosnmp.Asn1BER
			value any
		}{{lldp.LldpRemChassisIDSubtype, gosnmp.Integer, int(n.Chassis.Subtype)}, {lldp.LldpRemChassisID, gosnmp.OctetString, n.Chassis.Raw}, {lldp.LldpRemPortIDSubtype, gosnmp.Integer, int(n.Port.Subtype)}, {lldp.LldpRemPortID, gosnmp.OctetString, n.Port.Raw}} {
			pdus = append(pdus, gosnmp.SnmpPDU{Name: v.col + ".0.65800.1", Type: v.typ, Value: v.value})
		}
		rows, issues := lldp.ParseRemoteForDevice(pdus, p.Core.Device, []string{lldp.TS7914Adapter})
		if len(issues) > 0 {
			t.Fatal(issues)
		}
		rows[0].SysName = n.SysName
		rows[0].SysDescription = n.SysDescription
		p.Core.Neighbors = rows
	}
	for i := range p.Core.Neighbors {
		p.Core.Neighbors[i].MgmtAddresses = nil
	}
	for i := range p.Peer.Neighbors {
		p.Peer.Neighbors[i].MgmtAddresses = nil
	}
	rules, e := identity.LoadRules("../../config/device_rules.yaml")
	if e != nil {
		t.Fatal(e)
	}
	const core = "manual:verified-core"
	reg, e := identity.New(identity.Options{Rules: rules, Overrides: []identity.Override{{Subtype: 7, RawHex: hex.EncodeToString(p.Core.Device.Chassis.Raw), CanonicalKey: core}, {Subtype: 4, RawHex: hex.EncodeToString(p.Peer.Neighbors[0].Chassis.Raw), CanonicalKey: core}}, ClassificationOverrides: []identity.ClassificationOverride{{IdentityKey: core, Result: "switch", Reason: "operator-confirmed TS stack"}}})
	if e != nil {
		t.Fatal(e)
	}
	res := topology.NewResolver(nil)
	if e = res.SetOverrides([]topology.Override{{IdentityKey: core, CanonicalKey: topology.MakePortKey(5, p.Core.LocalPorts[0].ID.Raw), Aliases: []topology.PortKey{topology.MakePortKey(5, p.Peer.Neighbors[0].Port.Raw)}, Physical: true, Reason: "paired physical interface names"}}); e != nil {
		t.Fatal(e)
	}
	fc := newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{p.Core.Device.Target: &p.Core, p.Peer.Device.Target: &p.Peer})
	addresses := map[string][]netip.Addr{}
	if inventory {
		key, _ := identity.NormalizedKey(p.Peer.Device.Chassis, false)
		addresses[key] = []netip.Addr{p.Peer.Device.Target}
	}
	c, e := New(Options{Seeds: []netip.Addr{p.Core.Device.Target}, ManagementCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, MaxDepth: 4, Workers: 2, Collector: fc, Registry: reg, Resolver: res, AddressOverrides: addresses})
	if e != nil {
		t.Fatal(e)
	}
	return c, fc, p.Peer.Device.Target
}

func TestRealPairWithoutAnyNeighborManagementIP(t *testing.T) {
	for _, adapt := range []bool{false, true} {
		c, fc, peer := realNoIPCoordinator(t, adapt, true)
		r := c.Run(context.Background())
		want := "single_sided"
		if adapt {
			want = "bidirectional"
		}
		if len(r.Devices) != 2 || len(r.Links) != 1 || r.Links[0].Confidence() != want || fc.callCount(peer) != 1 {
			t.Fatalf("no-IP real replay: adapted=%v devices=%d links=%+v issues=%+v", adapt, len(r.Devices), r.Links, r.Issues)
		}
		for _, o := range r.Outcomes {
			for _, n := range o.Snapshot.Neighbors {
				if len(n.MgmtAddresses) != 0 {
					t.Fatal("test retained management address dependency")
				}
			}
		}
		if adapt {
			found := false
			for _, o := range r.Observations {
				if o.Raw.OriginalPort != nil && o.Raw.OriginalPort.Subtype == 0 {
					found = true
				}
			}
			if !found {
				t.Fatal("original TS encoding was lost")
			}
		}
	}
}

func TestNoAccessAddressRetainsNodeAndObservedEdge(t *testing.T) {
	c, fc, peer := realNoIPCoordinator(t, true, false)
	r := c.Run(context.Background())
	if fc.callCount(peer) != 0 || len(r.Devices) != 1 || len(r.Links) != 0 || len(r.PendingNodes) != 1 || len(r.PendingLinks) != 1 || r.Counts.DevicesUnscanned != 1 || !hasIssue(r.Issues, "NO_ACCESS_ADDRESS") {
		t.Fatalf("unreachable identity/edge lost: %+v nodes=%+v pending=%+v", r.Counts, r.PendingNodes, r.PendingLinks)
	}
}
