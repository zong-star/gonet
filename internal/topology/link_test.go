package topology

import (
	"testing"
	"time"

	"gonet/internal/model"
)

func obs(observer, localPort, remote, remotePort uint64, at time.Time) model.LinkObservation {
	return model.LinkObservation{
		Observer:   model.DevRef(observer),
		LocalPort:  model.PortRef(localPort),
		Remote:     model.DevRef(remote),
		RemotePort: model.PortRef(remotePort),
		At:         at,
	}
}

// L01: A→B and B→A plus a duplicate advertisement produce exactly one
// bidirectional link; duplicates never add a direction.
func TestL01BidirectionalAndDuplicate(t *testing.T) {
	b := NewLinkBuilder()
	t0 := time.Unix(100, 0)
	b.Add(obs(1, 10, 2, 20, t0))
	b.Add(obs(1, 10, 2, 20, t0.Add(time.Second)))   // duplicate direction
	b.Add(obs(2, 20, 1, 10, t0.Add(2*time.Second))) // reverse direction

	res := b.Build()
	if len(res.Links) != 1 {
		t.Fatalf("links = %d, want 1", len(res.Links))
	}
	ev := res.Links[0]
	want := model.LinkKey{A: 1, PA: 10, B: 2, PB: 20}
	if ev.Key != want {
		t.Errorf("key = %+v, want %+v", ev.Key, want)
	}
	if !ev.SeenFromA || !ev.SeenFromB {
		t.Errorf("directions = A:%v B:%v, want both", ev.SeenFromA, ev.SeenFromB)
	}
	if ev.Confidence() != "bidirectional" {
		t.Errorf("confidence = %q, want bidirectional", ev.Confidence())
	}
}

// L02: two physical port pairs between the same device pair stay two links.
func TestL02ParallelLinks(t *testing.T) {
	b := NewLinkBuilder()
	t0 := time.Unix(100, 0)
	b.Add(obs(1, 10, 2, 20, t0))
	b.Add(obs(1, 11, 2, 21, t0))
	b.Add(obs(2, 20, 1, 10, t0))
	b.Add(obs(2, 21, 1, 11, t0))

	res := b.Build()
	if len(res.Links) != 2 {
		t.Fatalf("links = %d, want 2 (parallel physical links)", len(res.Links))
	}
	for _, ev := range res.Links {
		if ev.Confidence() != "bidirectional" {
			t.Errorf("link %+v confidence = %q", ev.Key, ev.Confidence())
		}
	}
}

// L03: a previous bidirectional round must not make a one-directional round
// bidirectional. Each round is aggregated independently.
func TestL03SingleSidedNoCrossRound(t *testing.T) {
	t0 := time.Unix(100, 0)
	b1 := NewLinkBuilder()
	b1.Add(obs(1, 10, 2, 20, t0))
	b1.Add(obs(2, 20, 1, 10, t0))
	r1 := b1.Build()
	if len(r1.Links) != 1 || r1.Links[0].Confidence() != "bidirectional" {
		t.Fatalf("round 1 = %+v, want one bidirectional link", r1.Links)
	}

	b2 := NewLinkBuilder() // fresh round
	b2.Add(obs(1, 10, 2, 20, t0.Add(time.Minute)))
	r2 := b2.Build()
	if len(r2.Links) != 1 {
		t.Fatalf("round 2 links = %d, want 1", len(r2.Links))
	}
	if r2.Links[0].Confidence() != "single_sided" {
		t.Errorf("round 2 confidence = %q, want single_sided (no cross-round stitching)", r2.Links[0].Confidence())
	}
}

// L06: one physical port claiming two mutually exclusive remotes is isolated;
// no last-write-wins link is written.
func TestL06PortConflict(t *testing.T) {
	b := NewLinkBuilder()
	t0 := time.Unix(100, 0)
	b.Add(obs(1, 10, 2, 20, t0))
	b.Add(obs(1, 10, 3, 30, t0))

	res := b.Build()
	if len(res.Links) != 0 {
		t.Errorf("links = %d, want 0 (conflict must not become an active link)", len(res.Links))
	}
	if len(res.Conflicts) != 1 {
		t.Fatalf("conflicts = %d, want 1", len(res.Conflicts))
	}
	c := res.Conflicts[0]
	if c.Device != 1 || c.Port != 10 {
		t.Errorf("conflict endpoint = device %d port %d, want device 1 port 10", c.Device, c.Port)
	}
	if len(c.Remotes) != 2 {
		t.Errorf("conflict remotes = %d, want 2", len(c.Remotes))
	}
	if !hasCode(res.Issues, "TOPOLOGY_CONFLICT") {
		t.Errorf("missing TOPOLOGY_CONFLICT issue: %+v", res.Issues)
	}
}

// A remote port claimed by two different observers is also a conflict.
func TestSharedRemotePortConflict(t *testing.T) {
	b := NewLinkBuilder()
	t0 := time.Unix(100, 0)
	b.Add(obs(1, 10, 2, 20, t0))
	b.Add(obs(3, 30, 2, 20, t0))

	res := b.Build()
	if len(res.Links) != 0 {
		t.Errorf("links = %d, want 0", len(res.Links))
	}
	if len(res.Conflicts) != 1 || res.Conflicts[0].Device != 2 || res.Conflicts[0].Port != 20 {
		t.Errorf("conflicts = %+v, want one on device 2 port 20", res.Conflicts)
	}
}

// Same-chassis self connection is diagnostic only and never a link.
func TestSelfConnectionDiagnostic(t *testing.T) {
	b := NewLinkBuilder()
	b.Add(obs(1, 10, 1, 11, time.Unix(100, 0)))

	res := b.Build()
	if len(res.Links) != 0 {
		t.Errorf("links = %d, want 0 for self connection", len(res.Links))
	}
	if len(res.SelfConnections) != 1 {
		t.Errorf("self connections = %d, want 1", len(res.SelfConnections))
	}
}

// Canonical always orders device A < device B and swaps ports accordingly.
func TestCanonical(t *testing.T) {
	k, err := Canonical(5, 50, 2, 20)
	if err != nil {
		t.Fatal(err)
	}
	want := model.LinkKey{A: 2, PA: 20, B: 5, PB: 50}
	if k != want {
		t.Errorf("Canonical = %+v, want %+v", k, want)
	}
	if _, err := Canonical(3, 1, 3, 2); err != ErrSelfLink {
		t.Errorf("self link error = %v, want ErrSelfLink", err)
	}
}
