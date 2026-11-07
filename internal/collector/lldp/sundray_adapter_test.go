package lldp

import (
	"encoding/hex"
	"encoding/json"
	"github.com/gosnmp/gosnmp"
	"gonet/internal/model"
	"os"
	"testing"
)

func TestTSAdapterRealSampleScopedAndRawPreserved(t *testing.T) {
	b, e := os.ReadFile("../../../testdata/adapters/sundray-ts7914/h3c-pair.json")
	if e != nil {
		t.Fatal(e)
	}
	var p struct {
		Core model.DeviceSnapshot `json:"core"`
	}
	if e = json.Unmarshal(b, &p); e != nil {
		t.Fatal(e)
	}
	n := p.Core.Neighbors[0]
	pdus := []gosnmp.SnmpPDU{}
	for _, v := range []struct {
		col   string
		typ   gosnmp.Asn1BER
		value any
	}{{LldpRemChassisIDSubtype, gosnmp.Integer, int(n.Chassis.Subtype)}, {LldpRemChassisID, gosnmp.OctetString, n.Chassis.Raw}, {LldpRemPortIDSubtype, gosnmp.Integer, int(n.Port.Subtype)}, {LldpRemPortID, gosnmp.OctetString, n.Port.Raw}} {
		pdus = append(pdus, gosnmp.SnmpPDU{Name: v.col + ".0.65800.1", Type: v.typ, Value: v.value})
	}
	plain, issues := ParseRemoteNeighbors(pdus)
	if len(issues) == 0 || plain[0].Port.Subtype != 0 {
		t.Fatal("standard decoder was weakened")
	}
	normalized, issues := ParseRemoteForDevice(pdus, p.Core.Device, []string{TS7914Adapter})
	if len(issues) != 0 || len(normalized) != 1 || normalized[0].Port.Subtype != 3 || len(normalized[0].Port.Raw) != 6 || normalized[0].OriginalPort == nil || normalized[0].OriginalPort.Subtype != 0 || string(normalized[0].OriginalPort.Raw) != string(n.Port.Raw) {
		t.Fatalf("adapter failed to retain source: %+v issues=%v", normalized, issues)
	}
	if hex.EncodeToString(n.Port.Raw) != hex.EncodeToString(pdus[3].Value.([]byte)) {
		t.Fatal("input facts mutated")
	}
	other := p.Core.Device
	other.SysDescription = "different firmware"
	for _, tc := range []struct {
		d       model.DeviceInfo
		enabled []string
	}{{p.Core.Device, nil}, {other, []string{TS7914Adapter}}} {
		got, issues := ParseRemoteForDevice(pdus, tc.d, tc.enabled)
		if len(issues) == 0 || got[0].Port.Subtype != 0 {
			t.Fatal("adapter escaped its explicit scope")
		}
	}
}
