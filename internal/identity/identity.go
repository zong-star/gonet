// Package identity resolves device identity from a typed snapshot and from
// advertised LLDP neighbor rows. Strong identities are globally unique keys;
// weak identities (local, interface name, alias) are preserved but never used
// to merge devices. This package is in-memory (M2); the database replaces the
// registry in M4.
package identity

import (
	"encoding/hex"
	"fmt"
	"net/netip"
)

// Chassis ID subtype values relevant to identity.
const (
	ChassisSubtypeMACAddress     = 4
	ChassisSubtypeNetworkAddress = 5
)

// IsValidUnicastMAC reports whether raw is a 6-byte, non-zero, unicast MAC.
// Only such a MAC is accepted as a strong chassis identity.
func IsValidUnicastMAC(raw []byte) bool {
	if len(raw) != 6 {
		return false
	}
	allZero := true
	for _, b := range raw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}
	// The least significant bit of the first octet is the multicast bit.
	if raw[0]&0x01 != 0 {
		return false
	}
	return true
}

// StrongKey returns a globally unique identity key for the given chassis ID and
// whether one exists. MAC (subtype 4) must be a valid unicast non-zero MAC.
// networkAddress (subtype 5) is only accepted when explicitly allowed; its raw
// bytes already include the leading IANA family byte.
func StrongKey(subtype uint8, raw []byte, allowNetworkAddress bool) (string, bool) {
	switch subtype {
	case ChassisSubtypeMACAddress:
		if IsValidUnicastMAC(raw) {
			return "lldp:4:" + hex.EncodeToString(raw), true
		}
	case ChassisSubtypeNetworkAddress:
		if allowNetworkAddress && len(raw) > 1 && ((raw[0] == 1 && len(raw) == 5) || (raw[0] == 2 && len(raw) == 17)) {
			a, ok := netip.AddrFromSlice(raw[1:])
			if ok && a.IsGlobalUnicast() {
				return "lldp:5:" + hex.EncodeToString(raw), true
			}
		}
	}
	return "", false
}

// WeakKey returns a typed key for display and alias only. It must never be used
// as a global identity because local/interface-name/alias values are not
// guaranteed unique across devices.
func WeakKey(subtype uint8, raw []byte) string {
	return fmt.Sprintf("lldp:%d:%s", subtype, hex.EncodeToString(raw))
}
