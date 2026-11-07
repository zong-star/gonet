package lldp

import (
	"github.com/gosnmp/gosnmp"
	"gonet/internal/model"
	"testing"
)

func TestRSAdapterScopedFirmwareAndMalformedMAC(t *testing.T) {
	for _, descr := range []string{
		"Linux (none) 3.6.5-Broadcom Linux #10 Sat Oct 11 09:37:35 UTC 2025 armv7l",
		"Linux (none) 3.6.5-Broadcom Linux #10 Sat Oct 11 10:24:38 UTC 2025 armv7l",
		"Linux (none) 4.4.39-Broadcom Linux #1 SMP Sat Oct 11 10:45:52 UTC 2025 armv7l",
	} {
		device := model.DeviceInfo{SysObjectID: ".1.3.6.1.4.1.45577", SysDescription: descr}
		pdus := []gosnmp.SnmpPDU{
			{Name: LldpRemChassisIDSubtype + ".0.52.1", Type: gosnmp.Integer, Value: 7},
			{Name: LldpRemChassisID + ".0.52.1", Type: gosnmp.OctetString, Value: []byte("02:00:00:00:00:05")},
			{Name: LldpRemPortIDSubtype + ".0.52.1", Type: gosnmp.Integer, Value: 0},
			{Name: LldpRemPortID + ".0.52.1", Type: gosnmp.OctetString, Value: []byte("02:00:00:00:00:2d")},
		}
		rows, issues := ParseRemoteForDevice(pdus, device, []string{RS39Adapter})
		if len(issues) > 0 || len(rows) != 1 || rows[0].Port.Subtype != 3 || rows[0].OriginalPort == nil || rows[0].EncodingAdapter != RS39Adapter {
			t.Fatalf("RS adapter: %v %v", rows, issues)
		}
		for _, other := range []model.DeviceInfo{{SysObjectID: ".1.3.6.1.4.1.45578", SysDescription: descr}, {SysObjectID: device.SysObjectID, SysDescription: descr + " changed"}} {
			_, issues = ParseRemoteForDevice(pdus, other, []string{RS39Adapter})
			if len(issues) == 0 {
				t.Fatal("RS adapter escaped scope")
			}
		}
		pdus[3].Value = []byte("invalid-mac-value")
		_, issues = ParseRemoteForDevice(pdus, device, []string{RS39Adapter})
		if len(issues) == 0 {
			t.Fatal("malformed port accepted")
		}
	}
}
