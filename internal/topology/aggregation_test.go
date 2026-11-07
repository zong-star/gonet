package topology

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"testing"

	"gonet/internal/model"
)

type aggregationFixture struct {
	ScanID  int64 `json:"scan_id"`
	Devices []AggregationDevice
	Members []AggregationMember
	Links   []AggregationLink
}

func peerFixture(t *testing.T) aggregationFixture {
	t.Helper()
	b, e := os.ReadFile("../../testdata/adapters/lag-vendors/peer-inference/two-member.json")
	if e != nil {
		t.Fatal(e)
	}
	var f aggregationFixture
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	return f
}
func buildPeer(f aggregationFixture) []AggregationConnection {
	return BuildAggregationConnections(f.ScanID, f.Devices, f.Members, f.Links)
}
func TestPeerAggregationTwoMembersAndSingle(t *testing.T) {
	for _, count := range []int{1, 2} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			f := peerFixture(t)
			f.Links = f.Links[:count]
			r := buildPeer(f)
			want := "inferred"
			if count == 1 {
				want = "partial"
			}
			if len(r) != 1 || r[0].Status != want || len(r[0].LinkIDs) != count || r[0].Coverage != "partial" {
				t.Fatalf("%+v", r)
			}
			g := r[0].GroupA
			if g.AggregateIfIndex != nil || g.InterfaceName != nil || g.InferredFrom.DeviceID != 74 || g.Mode != "unknown" || r[0].Mode != "unknown" {
				t.Fatalf("invented local facts: %+v", g)
			}
			if f.Members[0].AggregateIfIndex != 639 || len(f.Members) != 2 {
				t.Fatal("input mutated")
			}
		})
	}
}
func TestPeerAggregationVendorAndEvidenceBoundaries(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*aggregationFixture)
		want   string
	}{
		{"huawei private", func(f *aggregationFixture) {
			f.Devices[1].SysObjectID = "1.3.6.1.4.1.2011.2.23.967"
			for i := range f.Members {
				f.Members[i].Source = "huawei_private"
			}
		}, "inferred"},
		{"no direct map", func(f *aggregationFixture) { f.Members = nil }, "unknown"},
		{"no oid name cannot identify", func(f *aggregationFixture) { f.Devices[0].SysObjectID = "" }, "partial"},
		{"enterprise boundary", func(f *aggregationFixture) { f.Devices[0].SysObjectID = "1.3.6.1.4.1.455770" }, "partial"},
		{"unsupported sundray product", func(f *aggregationFixture) {
			f.Devices[0].SysObjectID = "1.3.6.1.4.1.45577.99"
			f.Devices[0].ClassificationRule = "other"
		}, "partial"},
		{"unknown direct vendor", func(f *aggregationFixture) { f.Devices[1].SysObjectID = "1.3.6.1.4.1.99999" }, "partial"},
		{"inferred source cannot infer", func(f *aggregationFixture) {
			for i := range f.Members {
				f.Members[i].Source = "peer_inferred"
			}
		}, "conflict"},
		{"conflicting member", func(f *aggregationFixture) { f.Members[1].Status = "conflict" }, "conflict"},
		{"attached zero config persists", func(f *aggregationFixture) {
			yes, no := true, false
			for i := range f.Members {
				f.Members[i].Configured = &yes
				f.Members[i].Attached = &no
				f.Members[i].Source = "huawei_private"
			}
		}, "inferred"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := peerFixture(t)
			c.mutate(&f)
			r := buildPeer(f)
			n := 0
			for _, g := range r {
				n += len(g.LinkIDs)
				if g.Status != c.want {
					t.Fatalf("%+v", r)
				}
			}
			if n != 2 {
				t.Fatal("physical links lost")
			}
		})
	}
}
func TestPeerAggregationGroupsAndIndependentLinks(t *testing.T) {
	f := peerFixture(t)
	f.Links = append(f.Links, AggregationLink{ID: 300, DeviceA: 1, DeviceB: 74, IfA: 114, IfB: 29})
	r := buildPeer(f)
	if len(r) != 2 || r[0].Status != "inferred" || len(r[0].LinkIDs) != 2 || r[1].Status != "unknown" {
		t.Fatalf("%+v", r)
	}
	f.Members = append(f.Members, AggregationMember{DeviceID: 74, LAGMember: model.LAGMember{AggregateIfIndex: 640, MemberIfIndex: 29, Source: "ieee_lag", Status: "confirmed", Mode: "static"}, Name: "Bridge-Aggregation2"})
	r = buildPeer(f)
	if len(r) != 2 || r[1].Status != "partial" || r[0].GroupA.GroupID == r[1].GroupA.GroupID {
		t.Fatalf("groups mixed: %+v", r)
	}
	// Same numeric group ID on another source device must remain a new group.
	f.Devices = append(f.Devices, AggregationDevice{ID: 75, SysObjectID: f.Devices[1].SysObjectID, Verified: true})
	m := f.Members[0]
	m.DeviceID = 75
	f.Members = append(f.Members, m)
	f.Links = append(f.Links, AggregationLink{ID: 301, DeviceA: 1, DeviceB: 75, IfA: 115, IfB: 27})
	r = buildPeer(f)
	if len(r) != 3 || r[0].GroupA.GroupID == r[2].GroupA.GroupID {
		t.Fatalf("source devices mixed: %+v", r)
	}
}
func TestPeerAggregationWholeGroupConflicts(t *testing.T) {
	for _, kind := range []string{"multiple peers", "remote port shared", "stable port mixed index", "direct disagreement", "duplicate member", "protocol"} {
		t.Run(kind, func(t *testing.T) {
			f := peerFixture(t)
			switch kind {
			case "multiple peers":
				f.Devices = append(f.Devices, AggregationDevice{ID: 2, SysObjectID: "1.3.6.1.4.1.45577", Verified: true})
				f.Links[1].DeviceA = 2
			case "remote port shared":
				f.Links[1].IfA = f.Links[0].IfA
				f.Members[1].AggregateIfIndex = 640
			case "stable port mixed index":
				f.Links[1].IfA = 0
				f.Links[1].PortA = f.Links[0].PortA
				f.Members[1].AggregateIfIndex = 640
			case "direct disagreement":
				f.Members = append(f.Members, AggregationMember{DeviceID: 1, LAGMember: model.LAGMember{AggregateIfIndex: 900, MemberIfIndex: 78, Status: "confirmed", Source: "if_stack"}})
			case "duplicate member":
				m := f.Members[0]
				m.AggregateIfIndex = 640
				f.Members = append(f.Members, m)
			case "protocol":
				f.Members = append(f.Members, AggregationMember{DeviceID: 1, LAGMember: model.LAGMember{AggregateIfIndex: 900, MemberIfIndex: 78, Status: "confirmed", Source: "if_stack"}}, AggregationMember{DeviceID: 1, LAGMember: model.LAGMember{AggregateIfIndex: 900, MemberIfIndex: 113, Status: "confirmed", Source: "if_stack"}})
				f.Links[1].ProtocolConflict = true
			}
			r := buildPeer(f)
			n := 0
			for _, c := range r {
				n += len(c.LinkIDs)
				if c.Status != "conflict" {
					t.Fatalf("late conflict did not taint group: %+v", r)
				}
			}
			if n != 2 {
				t.Fatal("lost links")
			}
		})
	}
}
func TestPeerAggregationDirectUpgradeAndDeterminism(t *testing.T) {
	f := peerFixture(t)
	original := buildPeer(f)
	slices.Reverse(f.Links)
	slices.Reverse(f.Members)
	slices.Reverse(f.Devices)
	if r := buildPeer(f); !reflect.DeepEqual(original, r) {
		t.Fatalf("input order changed result: %+v / %+v", original, r)
	}
	for _, i := range []int32{78, 113} {
		f.Members = append(f.Members, AggregationMember{DeviceID: 1, LAGMember: model.LAGMember{AggregateIfIndex: 900, MemberIfIndex: i, Source: "if_stack", Status: "confirmed", Mode: "static"}, Name: "lag-real", Complete: true})
	}
	r := buildPeer(f)
	if len(r) != 1 || r[0].Status != "confirmed" || r[0].Coverage != "complete" || r[0].GroupA.InterfaceName == nil || *r[0].GroupA.InterfaceName != "lag-real" {
		t.Fatalf("upgrade: %+v", r)
	}
}
