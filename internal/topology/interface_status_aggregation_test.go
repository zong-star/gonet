package topology

import "testing"

func TestPeerAggregationRequiresCompletePeerAndDistinctMembers(t *testing.T) {
	f := peerFixture(t)
	for i := range f.Members {
		f.Members[i].Complete = false
	}
	r := buildPeer(f)
	if len(r) != 1 || r[0].Status != "partial" || len(r[0].LinkIDs) != 2 {
		t.Fatalf("incomplete peer formed valid LAG: %+v", r)
	}
	f = peerFixture(t)
	f.Links[1].IfB = f.Links[0].IfB
	r = buildPeer(f)
	for _, c := range r {
		if c.Status != "conflict" {
			t.Fatalf("duplicate peer member accepted: %+v", r)
		}
	}
}
