package identity

import "testing"

func TestRuleOIDSegmentBoundary(t *testing.T) {
	c, err := NewClassifier([]Rule{{ID: "model", SysObjectIDPrefix: "1.3.6.1.4.1.99999.1", Action: "switch"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, oid := range []string{"1.3.6.1.4.1.99999.10", "1.3.6.1.4.1.99999.11.1"} {
		if c.Classify(oid, "", nil, nil).Switch() {
			t.Fatalf("rule leaked across OID boundary: %s", oid)
		}
	}
	if !c.Classify(".1.3.6.1.4.1.99999.1.2", "", nil, nil).Switch() {
		t.Fatal("child OID should match")
	}
}

func TestNetworkChassisRequiresValidFamilyAndAddress(t *testing.T) {
	for _, raw := range [][]byte{{1}, {1, 192, 0, 2}, {9, 192, 0, 2, 1}, {1, 224, 0, 0, 1}, {1, 0, 0, 0, 0}} {
		if _, ok := StrongKey(5, raw, true); ok {
			t.Fatalf("invalid network chassis accepted: %x", raw)
		}
	}
	if _, ok := StrongKey(5, []byte{1, 192, 0, 2, 1}, true); !ok {
		t.Fatal("valid permitted network chassis rejected")
	}
}
