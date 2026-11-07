package identity

import (
	"encoding/json"
	"gonet/internal/model"
	"os"
	"strings"
	"testing"
)

func TestH3CModelRuleAgainstSanitizedRealSample(t *testing.T) {
	b, err := os.ReadFile("../../testdata/adapters/h3c-s5130s-28p-ei/snapshot-subset.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Snapshot model.DeviceSnapshot `json:"snapshot"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRules("../../config/device_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	classifier, err := NewClassifier(rules)
	if err != nil {
		t.Fatal(err)
	}
	d := fixture.Snapshot.Device
	if !classifier.Classify(d.SysObjectID, d.SysDescription, d.CapSupported, d.CapEnabled).Switch() {
		t.Fatal("verified model/firmware sample did not match")
	}
	if classifier.Classify(d.SysObjectID, strings.ReplaceAll(d.SysDescription, "S5130S-28P-EI", "Unverified-Model"), d.CapSupported, d.CapEnabled).Switch() {
		t.Fatal("rule generalized beyond verified model")
	}
	if classifier.Classify(d.SysObjectID, strings.ReplaceAll(d.SysDescription, "Release 6368", "Release 9999"), d.CapSupported, d.CapEnabled).Switch() {
		t.Fatal("rule generalized beyond verified firmware sample")
	}
}

func TestHuaweiModelRuleAgainstSanitizedRealSample(t *testing.T) {
	b, err := os.ReadFile("../../testdata/adapters/huawei-s5735-l8t4s-qa2/h3c-pair.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Huawei model.DeviceSnapshot `json:"huawei"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRules("../../config/device_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClassifier(rules)
	if err != nil {
		t.Fatal(err)
	}
	d := fixture.Huawei.Device
	for _, tc := range []struct {
		name, oid, descr string
		want             bool
	}{
		{"verified", d.SysObjectID, d.SysDescription, true},
		{"other-model", d.SysObjectID, strings.ReplaceAll(d.SysDescription, "S5735-L8T4S-QA2", "S5735-Unverified"), false},
		{"other-firmware", d.SysObjectID, strings.ReplaceAll(d.SysDescription, "V200R023C00SPC500", "V200R999C00SPC999"), false},
		{"other-oid", ".1.3.6.1.4.1.2011.2.23.9670", d.SysDescription, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.Classify(tc.oid, tc.descr, d.CapSupported, d.CapEnabled).Switch(); got != tc.want {
				t.Fatalf("model classification=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestS5120V2R6318P01ModelRuleAgainstRealSystemFacts(t *testing.T) {
	data, err := os.ReadFile("../../testdata/adapters/h3c-s5120v2-28p-si-r6318p01/device.json")
	if err != nil {
		t.Fatal(err)
	}
	var device model.DeviceInfo
	if err := json.Unmarshal(data, &device); err != nil {
		t.Fatal(err)
	}
	rules, err := LoadRules("../../config/device_rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	classifier, err := NewClassifier(rules)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, oid, description, rule string
	}{
		{"verified-crlf", device.SysObjectID, device.SysDescription, "h3c-live-1678-6318p01"},
		{"verified-lf", device.SysObjectID, strings.ReplaceAll(device.SysDescription, "\r\n", "\n"), "h3c-live-1678-6318p01"},
		{"existing-release", device.SysObjectID, strings.ReplaceAll(device.SysDescription, "6318P01", "6126P20"), "h3c-live-1678-6126p20"},
		{"other-product-oid", ".1.3.6.1.4.1.25506.1.16780", device.SysDescription, ""},
		{"other-model", device.SysObjectID, strings.ReplaceAll(device.SysDescription, "S5120V2-28P-SI", "S5120V2-28P-PWR-SI"), ""},
		{"other-release", device.SysObjectID, strings.ReplaceAll(device.SysDescription, "6318P01", "6318P02"), ""},
		{"release-suffix", device.SysObjectID, strings.ReplaceAll(device.SysDescription, "6318P01", "6318P010"), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// No capability bits: this must work on the preprobe facts that
			// previously classified the device as unknown.
			got := classifier.Classify(tc.oid, tc.description, nil, nil)
			if tc.rule == "" {
				if got.Managed() {
					t.Fatalf("unverified product/release classified as managed: %+v", got)
				}
			} else if !got.Switch() || got.RuleID != tc.rule {
				t.Fatalf("classification=%+v want switch via %s", got, tc.rule)
			}
		})
	}
}
