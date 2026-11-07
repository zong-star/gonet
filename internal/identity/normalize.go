package identity

import (
	"encoding/hex"
	"gonet/internal/model"
	"net"
	"strings"
)

// ParseMACContent accepts complete MAC encodings, never a substring or a
// punctuation-stripped arbitrary local identifier. The caller retains raw data.
func ParseMACContent(raw []byte) ([]byte, bool) {
	if IsValidUnicastMAC(raw) {
		return append([]byte(nil), raw...), true
	}
	s := strings.TrimSpace(string(raw))
	var mac []byte
	var err error
	switch len(s) {
	case 12:
		mac, err = hex.DecodeString(s)
	case 14:
		// H3C displays complete MACs as aaaa-bbbb-cccc. Only this exact
		// grouping is accepted; arbitrary punctuation is never stripped.
		if s[4] == '-' && s[9] == '-' {
			mac, err = hex.DecodeString(s[:4] + s[5:9] + s[10:])
		} else {
			mac, err = net.ParseMAC(s)
		}
	case 17:
		mac, err = net.ParseMAC(s)
	default:
		return nil, false
	}
	if err != nil || !IsValidUnicastMAC(mac) {
		return nil, false
	}
	return []byte(mac), true
}

func NormalizedKey(chassis model.TypedID, allowNet bool) (string, bool) {
	if chassis.Subtype == 4 || chassis.Subtype == 7 {
		if mac, ok := ChassisMAC(chassis); ok {
			return WeakKey(chassis.Subtype, mac), true
		}
	}
	return StrongKey(chassis.Subtype, chassis.Raw, allowNet)
}

func ChassisMAC(chassis model.TypedID) ([]byte, bool) {
	// A six-letter local name is not a binary MAC. local(7) must actually
	// look like a complete textual MAC, as in the verified TS encoding.
	if chassis.Subtype != 4 && chassis.Subtype != 7 {
		return nil, false
	}
	if chassis.Subtype == 7 && len(chassis.Raw) == 6 {
		return nil, false
	}
	return ParseMACContent(chassis.Raw)
}

// knownChassis prefers exact typed identity, then a unique MAC owner across
// type 4/7. Two existing identities with the same normalized MAC are ambiguous.
func (r *Registry) knownChassis(chassis model.TypedID) (*Device, bool) {
	key, strong := r.identityKey(chassis)
	if strong {
		if d := r.byKey[key]; d != nil {
			return d, false
		}
	}
	if chassis.Subtype != 4 && chassis.Subtype != 7 {
		return nil, false
	}
	mac, ok := ChassisMAC(chassis)
	if !ok {
		return nil, false
	}
	var owner *Device
	for _, d := range r.devices {
		match := false
		if d.Chassis.Subtype == 4 || d.Chassis.Subtype == 7 {
			if b, ok := ChassisMAC(d.Chassis); ok && hex.EncodeToString(b) == hex.EncodeToString(mac) {
				match = true
			}
		}
		if !match {
			continue
		}
		if owner != nil && owner != d {
			return nil, true
		}
		owner = d
	}
	return owner, false
}

// CandidateKeys selects access inventory routes only; probing still verifies identity.
func (r *Registry) CandidateKeys(d *Device) []string {
	keys := append([]string{d.StrongKey}, d.IdentityKeys...)
	if owner, ambiguous := r.knownChassis(d.Chassis); !ambiguous && owner == d && (d.Chassis.Subtype == 4 || d.Chassis.Subtype == 7) {
		if mac, ok := ChassisMAC(d.Chassis); ok {
			keys = append(keys, WeakKey(4, mac), WeakKey(7, mac))
		}
	}
	return keys
}

func (r *Registry) bindChassis(d *Device, chassis model.TypedID) {
	key, ok := NormalizedKey(chassis, r.allowNetAddr)
	if !ok {
		return
	}
	if owner := r.byKey[key]; owner != nil && owner != d {
		return
	}
	r.byKey[key] = d
	for _, k := range d.IdentityKeys {
		if k == key {
			return
		}
	}
	d.IdentityKeys = append(d.IdentityKeys, key)
}
