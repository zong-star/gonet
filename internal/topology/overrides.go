package topology

import (
	"encoding/hex"
	"fmt"
	"gonet/internal/model"
	"strings"
)

type Override struct {
	IdentityKey  string
	CanonicalKey PortKey
	Aliases      []PortKey
	Physical     bool
	Reason       string
}

func (r *Resolver) SetOverrides(overrides []Override) error {
	r.overrides = map[string]map[PortKey]Override{}
	for _, o := range overrides {
		if o.IdentityKey == "" || o.Reason == "" || !ValidPortKey(string(o.CanonicalKey)) {
			return fmt.Errorf("port override requires identity, typed canonical key and reason")
		}
		m := r.overrides[o.IdentityKey]
		if m == nil {
			m = map[PortKey]Override{}
			r.overrides[o.IdentityKey] = m
		}
		for _, key := range append([]PortKey{o.CanonicalKey}, o.Aliases...) {
			if !ValidPortKey(string(key)) {
				return fmt.Errorf("invalid port alias %q", key)
			}
			if _, exists := m[key]; exists {
				return fmt.Errorf("port alias %q is not unique", key)
			}
			m[key] = o
		}
	}
	return nil
}

func (r *Resolver) SetDeviceIdentity(device model.DevRef, key string) {
	if r.deviceIdentities == nil {
		r.deviceIdentities = map[model.DevRef]string{}
	}
	r.deviceIdentities[device] = key
}

func idFromKey(key PortKey) model.TypedID {
	p := strings.Split(string(key), ":")
	raw, _ := hex.DecodeString(p[2])
	return model.TypedID{Subtype: p[1][0] - '0', Raw: raw}
}
