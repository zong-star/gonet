package discovery

import (
	"context"
	"net/netip"
	"testing"

	"gonet/internal/identity"
	"gonet/internal/model"
)

func TestRediscoveryLinkLocalToRoutableAndExistingDevice(t *testing.T) {
	core := netip.MustParseAddr("192.0.2.1")
	peer := netip.MustParseAddr("10.201.109.200")
	child := netip.MustParseAddr("10.201.109.201")
	macA, macB, macC := []byte{2, 0, 0, 0, 0, 1}, []byte{0xac, 0xce, 0x92, 0x88, 0x36, 0xc2}, []byte{2, 0, 0, 0, 0, 3}
	neighbor := nb(1, 1, 1, macB, "P1", netip.MustParseAddr("169.254.54.194"))
	neighbor.SysName = "Aggregation-Switch"
	coreSnap := devSnap(core, macA, "TS7914", []model.LocalPort{lp(1, "P1")}, []model.Interface{ifc(1, "P1")}, []model.LLDPNeighbor{neighbor})
	peerSnap := devSnap(peer, macB, "Aggregation-Switch", []model.LocalPort{lp(1, "P1"), lp(2, "P2")}, []model.Interface{ifc(1, "P1"), ifc(2, "P2")}, []model.LLDPNeighbor{nb(1, 1, 1, macA, "P1", core), nb(1, 2, 1, macC, "P1", child)})
	childSnap := devSnap(child, macC, "child", []model.LocalPort{lp(1, "P1")}, []model.Interface{ifc(1, "P1")}, nil)
	opts := Options{Seeds: []netip.Addr{core}, ManagementCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("10.201.109.0/24")}, MaxDepth: 4}
	first := newCoord(t, newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{core: coreSnap}), opts).Run(context.Background())
	if len(first.PendingNodes) != 1 || first.PendingNodes[0].Verification.FailureCode != "INVALID_MANAGEMENT_IP" || len(first.Devices) != 1 {
		t.Fatalf("first advertisement lost or managed without SNMP: %+v", first)
	}
	key := first.PendingNodes[0].Key
	copyCore := *coreSnap
	copyCore.Neighbors = append([]model.LLDPNeighbor(nil), coreSnap.Neighbors...)
	copyCore.Neighbors[0].MgmtAddresses = []netip.Addr{peer}
	fc := newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{core: &copyCore, peer: peerSnap, child: childSnap})
	secondCoord := newCoord(t, fc, opts)
	if err := secondCoord.RestoreContext(first.Devices, first.Ports); err != nil {
		t.Fatal(err)
	}
	second := secondCoord.Run(context.Background())
	if len(second.Devices) != 3 || len(second.Links) != 2 || len(second.PendingNodes) != 0 || fc.callCount(peer) != 1 || fc.callCount(child) != 1 {
		t.Fatalf("new address did not verify and recurse: devices=%d links=%d pending=%+v issues=%+v", len(second.Devices), len(second.Links), second.PendingNodes, second.Issues)
	}
	if second.Verifications[0].Key(uint64(second.Verifications[0].SourceDevice)) != key || second.Verifications[0].Details.Status != "verified" {
		t.Fatal("candidate identity changed with management IP")
	}
	third := newCoord(t, newFakeCollector(fc.snapshots), opts)
	if err := third.RestoreContext(second.Devices, second.Ports); err != nil {
		t.Fatal(err)
	}
	r := third.Run(context.Background())
	if len(r.Devices) != 3 || len(r.Links) != 2 {
		t.Fatal("existing devices or links duplicated")
	}
}

func TestFailedPeerGetsNewAddressLaterInSameRun(t *testing.T) {
	// Core sees B at a dead address, plus C. C -> D later reveals B's
	// corrected address. B must retry at its original depth and recurse to E.
	mac := func(n byte) []byte { return []byte{2, 0, 0, 0, 0, n} }
	ip := func(n string) netip.Addr { return netip.MustParseAddr("192.0.2." + n) }
	snap := func(addr string, n byte, neighbors ...model.LLDPNeighbor) *model.DeviceSnapshot {
		return devSnap(ip(addr), mac(n), addr, []model.LocalPort{lp(1, "P1"), lp(2, "P2"), lp(3, "P3")}, []model.Interface{ifc(1, "P1"), ifc(2, "P2"), ifc(3, "P3")}, neighbors)
	}
	fc := newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{
		ip("1"): snap("1", 1, nb(1, 1, 1, mac(2), "P1", ip("12")), nb(1, 2, 1, mac(3), "P1", ip("3"))),
		ip("3"): snap("3", 3, nb(1, 2, 1, mac(4), "P1", ip("4"))),
		ip("4"): snap("4", 4, nb(1, 2, 1, mac(2), "P2", ip("2"))),
		ip("2"): snap("2", 2, nb(1, 3, 1, mac(5), "P1", ip("5")), nb(1, 1, 1, mac(1), "P1", ip("1"))),
		ip("5"): snap("5", 5),
	})
	c := newCoord(t, fc, Options{Seeds: []netip.Addr{ip("1")}, ManagementCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, MaxDepth: 3, MaxAddressesPerDevice: 2})
	r := c.Run(context.Background())
	if fc.callCount(ip("12")) != 1 || fc.callCount(ip("2")) != 1 || fc.callCount(ip("5")) != 1 || len(r.Devices) != 5 || len(r.Links) != 5 {
		t.Fatalf("failed task prevented later-address retry/recursion: calls=%v counts=%+v issues=%+v", fc.callOrder(), r.Counts, r.Issues)
	}
	for _, v := range r.Verifications {
		if c.opts.Registry.Matches(v.MatchedDevice, model.TypedID{Subtype: 4, Raw: mac(2)}) && v.Details.Status != "verified" {
			t.Fatal("successful retry still pending")
		}
	}
}

func TestSNMPFailureRetainedAndRetriedNextRun(t *testing.T) {
	snaps := linearTopology(t)
	peer := netip.MustParseAddr("192.0.2.2")
	saved := snaps[peer]
	delete(snaps, peer)
	opts := Options{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ManagementCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, MaxDepth: 4}
	fc := newFakeCollector(snaps)
	r := newCoord(t, fc, opts).Run(context.Background())
	if fc.callCount(peer) != 1 || len(r.PendingNodes) != 1 || r.PendingNodes[0].Verification.Status != "verification_failed" || r.PendingNodes[0].Verification.LastAttemptAt == nil {
		t.Fatalf("failure not retained: %+v", r.PendingNodes)
	}
	snaps[peer] = saved
	c := newCoord(t, newFakeCollector(snaps), opts)
	if err := c.RestoreContext(r.Devices, r.Ports); err != nil {
		t.Fatal(err)
	}
	if got := c.Run(context.Background()); len(got.Devices) != 3 || len(got.PendingNodes) != 0 {
		t.Fatal("previous failure blocked later run")
	}
}

func TestVerificationDoesNotMergeSameNameOrWrongChassis(t *testing.T) {
	snaps := ringTopology(t)
	for _, s := range snaps {
		s.Device.SysName = "duplicate-name"
	}
	c := newCoord(t, newFakeCollector(snaps), Options{Seeds: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, ManagementCIDRs: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}, MaxDepth: 4})
	r := c.Run(context.Background())
	if len(r.Devices) != 3 {
		t.Fatal("same names merged separate chassis")
	}
	if !hasIssue(r.Issues, "SYSNAME_CONFLICT") {
		t.Fatal("duplicate-name diagnostic missing")
	}
	snaps[netip.MustParseAddr("192.0.2.2")].Device.Chassis.Raw = []byte{2, 0, 0, 0, 0, 99}
	c = newCoord(t, newFakeCollector(snaps), c.opts)
	r = c.Run(context.Background())
	if !hasIssue(r.Issues, "IDENTITY_CONFLICT") {
		t.Fatal("wrong advertised management address did not report conflict")
	}
	for _, v := range r.Verifications {
		if v.Details.Status == "identity_conflict" && v.MatchedDevice != 0 {
			t.Fatal("conflicting candidate was automatically linked")
		}
	}
}

func TestMACFormatsPreserveVerifiedDeviceIdentity(t *testing.T) {
	reg := newTestRegistry(t)
	chassis := model.TypedID{Subtype: 4, Raw: []byte{0xac, 0xce, 0x92, 0x88, 0x37, 0x06}}
	d := reg.ResolveDirect(devSnap(netip.MustParseAddr("192.0.2.1"), chassis.Raw, "sw", nil, nil, nil)).Device
	for _, text := range []string{"acce-9288-3706", "ac:ce:92:88:37:06", "ACCE.9288.3706"} {
		got := reg.ResolveAdvertised(model.LLDPNeighbor{Chassis: model.TypedID{Subtype: 4, Raw: []byte(text)}})
		if got.State != identity.Resolved || got.Device.Ref != d.Ref {
			t.Fatalf("MAC %s not normalized", text)
		}
	}
}

func TestIPv4LinkLocalRequiresExplicitOptionAndScope(t *testing.T) {
	a := netip.MustParseAddr("169.254.54.194")
	for _, allow := range []bool{false, true} {
		fc := newFakeCollector(map[netip.Addr]*model.DeviceSnapshot{a: devSnap(a, []byte{2, 0, 0, 0, 0, 1}, "local", nil, nil, nil)})
		c := newCoord(t, fc, Options{Seeds: []netip.Addr{a}, ManagementCIDRs: []netip.Prefix{netip.MustParsePrefix("169.254.0.0/16")}, AllowIPv4LinkLocal: allow})
		c.Run(context.Background())
		if (fc.callCount(a) > 0) != allow {
			t.Fatal("link-local policy ignored")
		}
	}
}
