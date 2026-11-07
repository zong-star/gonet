package preprobe

import (
	"testing"
	"time"

	"gonet/internal/identity"
	"gonet/internal/model"
)

func TestIndexTypedMACAliasesAndNoNameMatching(t *testing.T) {
	reg := registry(t)
	a := success(ip("192.0.2.2"))
	b := success(ip("192.0.2.3"))
	b.Facts.Chassis = model.TypedID{Subtype: 7, Raw: []byte("02:00:00:00:00:02")}
	other := success(ip("192.0.2.4"))
	pool := []Record{Merge(Record{}, a, reg), Merge(Record{}, b, reg), Merge(Record{}, other, reg)}
	x := NewIndex(pool, NewRange(prefixes("192.0.2.0/29"), nil, false), time.Minute, reg)
	d, ok := reg.EnsureAdvertised(model.LLDPNeighbor{Chassis: a.Facts.Chassis})
	if !ok {
		t.Fatal("fixture identity not admitted")
	}
	if c := x.Candidates(d); len(c) != 2 {
		t.Fatalf("typed aliases/multiple addresses failed: %+v", c)
	}
	r := pool[0]
	r.Conflict = true
	x.Update(r)
	if c := x.Candidates(d); len(c) != 1 || c[0].IP != b.IP {
		t.Fatal("IP conflict not removed immediately from index")
	}
	reg2, e := identity.New(identity.Options{Overrides: []identity.Override{{Subtype: 7, RawHex: "737461636b2d41", CanonicalKey: "manual:stack"}}})
	if e != nil {
		t.Fatal(e)
	}
	manual := success(ip("192.0.2.5"))
	manual.Facts.Chassis = model.TypedID{Subtype: 7, Raw: []byte("stack-A")}
	weak := success(ip("192.0.2.6"))
	weak.Facts.Chassis = model.TypedID{Subtype: 7, Raw: []byte("same-name")}
	y := NewIndex([]Record{Merge(Record{}, manual, reg2), Merge(Record{}, weak, reg2)}, NewRange(prefixes("192.0.2.0/29"), nil, false), time.Minute, reg2)
	owner, ok := reg2.EnsureAdvertised(model.LLDPNeighbor{Chassis: manual.Facts.Chassis})
	if !ok || len(y.Candidates(owner)) != 1 {
		t.Fatal("explicit weak-chassis mapping lost")
	}
}
