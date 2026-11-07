package topology

import (
	"testing"
	"time"

	"gonet/internal/model"
)

func fixedNow() time.Time { return time.Unix(1000, 0).UTC() }

func newTestResolver() *Resolver {
	return NewResolver(NewPortRegistry(fixedNow))
}

func hasCode(issues []model.Issue, code string) bool {
	for _, i := range issues {
		if i.Code == code {
			return true
		}
	}
	return false
}

// C09: locPortNum=27 maps to ifIndex=1031 via interfaceName; the LLDP port
// number is kept separately and is never used as an ifIndex.
func TestC09LocalPortIfIndex(t *testing.T) {
	r := newTestResolver()
	lp := model.LocalPort{
		Number: 27,
		ID:     model.TypedID{Subtype: 5, Raw: []byte("Ten-GigabitEthernet1/0/31")},
	}
	ifaces := []model.Interface{{IfIndex: 1031, Name: "Ten-GigabitEthernet1/0/31", Type: 6}}
	res := r.ResolveLocalPort(1, lp, ifaces)

	if res.State != PortVerified {
		t.Fatalf("state = %v, want verified", res.State)
	}
	if res.Port.IfIndex == nil || *res.Port.IfIndex != 1031 {
		t.Errorf("ifIndex = %v, want 1031", res.Port.IfIndex)
	}
	if res.Port.LLDPPortNum == nil || *res.Port.LLDPPortNum != 27 {
		t.Errorf("lldpPortNum = %v, want 27", res.Port.LLDPPortNum)
	}
	if !res.Port.Physical {
		t.Error("physical = false, want true for ethernetCsmacd")
	}
	if res.Port.MappingRule != "ifname-exact" {
		t.Errorf("mapping rule = %q, want ifname-exact", res.Port.MappingRule)
	}
}

// L04: an ifIndex change with the same LLDP typed key reuses the port ref.
func TestL04IfIndexChangeNoNewPort(t *testing.T) {
	r := newTestResolver()
	lp := model.LocalPort{Number: 1, ID: model.TypedID{Subtype: 5, Raw: []byte("Gi0/1")}}

	p1 := r.ResolveLocalPort(1, lp, []model.Interface{{IfIndex: 101, Name: "Gi0/1", Type: 6}}).Port
	p2 := r.ResolveLocalPort(1, lp, []model.Interface{{IfIndex: 201, Name: "Gi0/1", Type: 6}}).Port

	if p1.Ref != p2.Ref {
		t.Errorf("ifIndex change created a new port: %d -> %d", p1.Ref, p2.Ref)
	}
	if p2.IfIndex == nil || *p2.IfIndex != 201 {
		t.Errorf("ifIndex = %v, want 201 after change", p2.IfIndex)
	}
	if len(r.Ports().All()) != 1 {
		t.Errorf("ports = %d, want 1", len(r.Ports().All()))
	}
}

// L05: a LAG endpoint is non-physical and must not become a physical link.
func TestL05LagPort(t *testing.T) {
	r := newTestResolver()
	lp := model.LocalPort{Number: 1, ID: model.TypedID{Subtype: 5, Raw: []byte("Port-Channel1")}}
	ifaces := []model.Interface{{IfIndex: 500, Name: "Port-Channel1", Type: IfTypeLAG}}
	res := r.ResolveLocalPort(1, lp, ifaces)

	if res.Port.Physical {
		t.Error("LAG port must not be physical")
	}
	if res.State != PortProvisional {
		t.Errorf("state = %v, want provisional", res.State)
	}
	if !hasCode(res.Issues, "NON_PHYSICAL_PORT") {
		t.Errorf("missing NON_PHYSICAL_PORT issue: %+v", res.Issues)
	}
}

// L05: a duplicate interface alias is ambiguous and must not pick a first row.
func TestL05DuplicateAlias(t *testing.T) {
	r := newTestResolver()
	lp := model.LocalPort{Number: 1, ID: model.TypedID{Subtype: 1, Raw: []byte("uplink")}}
	ifaces := []model.Interface{
		{IfIndex: 10, Alias: "uplink", Type: 6},
		{IfIndex: 11, Alias: "uplink", Type: 6},
	}
	res := r.ResolveLocalPort(1, lp, ifaces)

	if res.Port.IfIndex != nil {
		t.Errorf("ambiguous alias resolved to ifIndex %d", *res.Port.IfIndex)
	}
	if res.State != PortUnresolved {
		t.Errorf("state = %v, want unresolved", res.State)
	}
}

// L05: an unknown remote port subtype is unresolved, never a fake physical link.
func TestL05UnknownRemotePort(t *testing.T) {
	r := newTestResolver()
	n := model.LLDPNeighbor{
		Index: model.NeighborIndex{TimeMark: 1, LocalPortNum: 1, RemoteIndex: 1},
		Port:  model.TypedID{Subtype: 7, Raw: []byte("local-id")},
	}
	res := r.ResolveRemotePort(2, n, nil, nil)

	if res.State != PortUnresolved {
		t.Errorf("state = %v, want unresolved", res.State)
	}
	if res.Port.Physical {
		t.Error("unknown remote port must not be physical")
	}
	if !hasCode(res.Issues, "PORT_UNRESOLVED") {
		t.Errorf("missing PORT_UNRESOLVED issue: %+v", res.Issues)
	}
}

// Remote port exact match against a scanned peer's local port table.
func TestRemotePortExactMatch(t *testing.T) {
	r := newTestResolver()
	n := model.LLDPNeighbor{Port: model.TypedID{Subtype: 5, Raw: []byte("Gi0/2")}}
	remoteLocalPorts := []model.LocalPort{{Number: 3, ID: model.TypedID{Subtype: 5, Raw: []byte("Gi0/2")}}}
	remoteIfaces := []model.Interface{{IfIndex: 302, Name: "Gi0/2", Type: 6}}

	res := r.ResolveRemotePort(2, n, remoteLocalPorts, remoteIfaces)
	if res.State != PortVerified {
		t.Fatalf("state = %v, want verified", res.State)
	}
	if res.Port.IfIndex == nil || *res.Port.IfIndex != 302 {
		t.Errorf("ifIndex = %v, want 302", res.Port.IfIndex)
	}
}

// A remote interfaceName port is provisional while the peer is unscanned.
func TestRemoteProvisionalIfName(t *testing.T) {
	r := newTestResolver()
	n := model.LLDPNeighbor{Port: model.TypedID{Subtype: 5, Raw: []byte("Gi0/9")}}
	res := r.ResolveRemotePort(2, n, nil, nil)
	if res.State != PortProvisional {
		t.Errorf("state = %v, want provisional", res.State)
	}
	if res.Port.Physical {
		t.Error("provisional remote port must not be physical")
	}
}

// The same typed key on two devices must not merge (device-local keys).
func TestPortsDeviceLocal(t *testing.T) {
	r := newTestResolver()
	lp := model.LocalPort{Number: 1, ID: model.TypedID{Subtype: 5, Raw: []byte("Gi0/1")}}
	ifaces := []model.Interface{{IfIndex: 1, Name: "Gi0/1", Type: 6}}
	p1 := r.ResolveLocalPort(1, lp, ifaces).Port
	p2 := r.ResolveLocalPort(2, lp, ifaces).Port
	if p1.Ref == p2.Ref {
		t.Error("same typed key on different devices was merged")
	}
}

// A real LLDP key change on the same ifIndex is isolated and reported.
func TestPortIDChanged(t *testing.T) {
	r := newTestResolver()
	old := model.LocalPort{Number: 1, ID: model.TypedID{Subtype: 5, Raw: []byte("Gi0/1")}}
	ifaces := []model.Interface{{IfIndex: 101, Name: "Gi0/1", Type: 6}}
	r.ResolveLocalPort(1, old, ifaces)

	newLP := model.LocalPort{Number: 2, ID: model.TypedID{Subtype: 5, Raw: []byte("Gi0/1-renamed")}}
	ifaces2 := []model.Interface{
		{IfIndex: 101, Name: "Gi0/1-renamed", Type: 6},
	}
	res := r.ResolveLocalPort(1, newLP, ifaces2)
	if !hasCode(res.Issues, "PORT_ID_CHANGED") {
		t.Errorf("missing PORT_ID_CHANGED issue: %+v", res.Issues)
	}
	if len(r.Ports().All()) != 2 {
		t.Errorf("ports = %d, want 2 (old and new isolated)", len(r.Ports().All()))
	}
}
