package lldp

import (
	"fmt"
	"math"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// AsBytes returns the raw OCTET STRING bytes of a varbind, copying them so the
// result never aliases the receive buffer.
func AsBytes(pdu gosnmp.SnmpPDU) ([]byte, error) {
	if pdu.Type != gosnmp.OctetString {
		return nil, fmt.Errorf("expected ASN.1 OCTET STRING at %s", pdu.Name)
	}
	switch v := pdu.Value.(type) {
	case []byte:
		return append([]byte(nil), v...), nil
	case string:
		return []byte(v), nil
	default:
		return nil, fmt.Errorf("expected OCTET STRING at %s, got %T", pdu.Name, pdu.Value)
	}
}

// AsString returns a display string with invalid UTF-8 bytes replaced. It is
// only for display; identity always uses raw bytes.
func AsString(pdu gosnmp.SnmpPDU) (string, error) {
	b, err := AsBytes(pdu)
	if err != nil {
		return "", err
	}
	text := strings.ToValidUTF8(string(b), "\uFFFD")
	if len(text) > 1024 {
		text = strings.ToValidUTF8(text[:1024], "")
	}
	return text, nil
}

// AsUint32 returns an unsigned 32-bit integer value, rejecting negative or
// out-of-range values (used for indexes, subtypes and timeticks).
func AsUint32(pdu gosnmp.SnmpPDU) (uint32, error) {
	if pdu.Type != gosnmp.Integer && pdu.Type != gosnmp.TimeTicks && pdu.Type != gosnmp.Counter32 && pdu.Type != gosnmp.Gauge32 && pdu.Type != gosnmp.Uinteger32 {
		return 0, fmt.Errorf("expected ASN.1 integer at %s", pdu.Name)
	}
	switch v := pdu.Value.(type) {
	case int:
		if v < 0 || uint64(v) > math.MaxUint32 {
			return 0, fmt.Errorf("negative integer %d at %s", v, pdu.Name)
		}
		return uint32(v), nil
	case int32:
		if v < 0 {
			return 0, fmt.Errorf("negative integer %d at %s", v, pdu.Name)
		}
		return uint32(v), nil
	case int64:
		if v < 0 || v > math.MaxUint32 {
			return 0, fmt.Errorf("integer %d out of uint32 range at %s", v, pdu.Name)
		}
		return uint32(v), nil
	case uint:
		if uint64(v) > math.MaxUint32 {
			return 0, fmt.Errorf("integer out of uint32 range at %s", pdu.Name)
		}
		return uint32(v), nil
	case uint32:
		return v, nil
	case uint64:
		if v > math.MaxUint32 {
			return 0, fmt.Errorf("integer %d out of uint32 range at %s", v, pdu.Name)
		}
		return uint32(v), nil
	default:
		return 0, fmt.Errorf("expected integer at %s, got %T", pdu.Name, pdu.Value)
	}
}

// AsBits returns the raw BITS bytes of a varbind. gosnmp decodes ASN.1 BIT
// STRING as BitStringValue whose Bytes are packed MSB-first (bit n lives at
// raw[n/8] & (0x80>>(n%8))), matching the LLDP-MIB capability bit order.
func AsBits(pdu gosnmp.SnmpPDU) ([]byte, error) {
	if pdu.Type != gosnmp.OctetString && pdu.Type != gosnmp.BitString {
		return nil, fmt.Errorf("expected ASN.1 BITS at %s", pdu.Name)
	}
	switch v := pdu.Value.(type) {
	case gosnmp.BitStringValue:
		return append([]byte(nil), v.Bytes...), nil
	case []byte:
		return append([]byte(nil), v...), nil
	default:
		return nil, fmt.Errorf("expected BITS at %s, got %T", pdu.Name, pdu.Value)
	}
}

// capabilityNames maps LLDP system capability bit positions to names.
var capabilityNames = []string{
	"other",
	"repeater",
	"bridge",
	"wlanAccessPoint",
	"router",
	"telephone",
	"docsisCableDevice",
	"stationOnly",
}

// CapabilityNames returns the names of set bits in a raw BITS byte slice.
// bridge=2 (0x20), wlanAccessPoint=3 (0x10), router=4 (0x08), telephone=5
// (0x04), stationOnly=7 (0x01). bridge+router is legal and does not exclude a
// layer-3 switch.
func CapabilityNames(raw []byte) []string {
	var out []string
	for i := 0; i < len(raw)*8; i++ {
		if raw[i/8]&(0x80>>(i%8)) != 0 {
			if i < len(capabilityNames) {
				out = append(out, capabilityNames[i])
			}
		}
	}
	return out
}
