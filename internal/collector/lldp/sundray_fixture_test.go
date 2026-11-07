package lldp

import (
	"encoding/base64"
	"encoding/json"
	"github.com/gosnmp/gosnmp"
	"os"
	"strings"
	"testing"
)

func TestTS7914RealMalformedRowsRemainUnresolved(t *testing.T) {
	b, err := os.ReadFile("../../../testdata/adapters/sundray-ts7914/nonstandard-agent.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Facts []struct {
			OID   string          `json:"oid"`
			ASN1  string          `json:"asn1"`
			Value json.RawMessage `json:"value"`
		} `json:"facts"`
		Management []struct {
			OID   string `json:"oid"`
			Value int    `json:"value"`
		} `json:"management_getnext"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	var remote []gosnmp.SnmpPDU
	for _, f := range fixture.Facts {
		if !strings.HasPrefix(strings.TrimPrefix(f.OID, "."), LldpRemTable+".") {
			continue
		}
		p := gosnmp.SnmpPDU{Name: f.OID}
		switch f.ASN1 {
		case "Integer":
			var v int
			if err := json.Unmarshal(f.Value, &v); err != nil {
				t.Fatal(err)
			}
			p.Type = gosnmp.Integer
			p.Value = v
		case "OctetString":
			var v string
			if err := json.Unmarshal(f.Value, &v); err != nil {
				t.Fatal(err)
			}
			raw, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				t.Fatal(err)
			}
			p.Type = gosnmp.OctetString
			p.Value = raw
		default:
			t.Fatalf("unexpected ASN.1 type %q", f.ASN1)
		}
		remote = append(remote, p)
	}
	rows, issues := ParseRemoteNeighbors(remote)
	if len(issues) == 0 {
		t.Fatal("real subtype 0 was incorrectly accepted")
	}
	found := false
	for _, row := range rows {
		if row.Index.LocalPortNum == 65800 {
			found = true
			if row.Port.Subtype != 0 || len(row.Issues) == 0 {
				t.Fatal("bad port subtype was silently normalized")
			}
		}
	}
	if !found {
		t.Fatal("real malformed row was discarded instead of retained as evidence")
	}
	var mgmt []gosnmp.SnmpPDU
	for _, m := range fixture.Management {
		mgmt = append(mgmt, gosnmp.SnmpPDU{Name: m.OID, Type: gosnmp.Integer, Value: m.Value})
	}
	addresses, errors := ParseMgmtAddresses(mgmt)
	if len(addresses) != 0 || len(errors) == 0 {
		t.Fatal("zero-length real management row became an address")
	}
}
