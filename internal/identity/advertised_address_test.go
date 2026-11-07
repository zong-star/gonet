package identity

import (
	"gonet/internal/model"
	"net/netip"
	"testing"
)

func TestMissingChassisCanUseVerifiedAddressButConflictsStaySeparate(t *testing.T) {
	r := newTestRegistry(t)
	a := r.ResolveDirect(snap("10.0.0.1", "sw", macChassis(2, 0, 0, 0, 0, 1), []byte{0x20})).Device
	r.ResolveDirect(snap("10.0.0.2", "sw", macChassis(2, 0, 0, 0, 0, 2), []byte{0x20}))
	n := model.LLDPNeighbor{MgmtAddresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	if got := r.ResolveAdvertised(n); got.Device != a {
		t.Fatal("missing optional chassis discarded verified address evidence")
	}
	n.MgmtAddresses = append(n.MgmtAddresses, netip.MustParseAddr("10.0.0.2"))
	if got := r.ResolveAdvertised(n); got.State != ResolvedConflict {
		t.Fatal("conflicting verified address owners merged")
	}
	n.Chassis = macChassis(2, 0, 0, 0, 0, 99)
	n.MgmtAddresses = n.MgmtAddresses[:1]
	if got := r.ResolveAdvertised(n); got.Device == a {
		t.Fatal("different strong chassis merged by IP")
	}
}
