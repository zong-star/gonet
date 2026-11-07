package identity

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ClassificationOverride is explicit operator knowledge about one resolved
// identity. It never promotes other devices sharing a vendor OID/sysDescr.
type ClassificationOverride struct {
	IdentityKey string
	Result      string
	Reason      string
}

func compileClassificationOverrides(overrides []ClassificationOverride) (map[string]Classification, error) {
	out := map[string]Classification{}
	for _, o := range overrides {
		valid := strings.HasPrefix(o.IdentityKey, "manual:") && len(o.IdentityKey) > len("manual:")
		if strings.HasPrefix(o.IdentityKey, "lldp:4:") {
			b, err := hex.DecodeString(strings.TrimPrefix(o.IdentityKey, "lldp:4:"))
			valid = err == nil && IsValidUnicastMAC(b) && o.IdentityKey == "lldp:4:"+hex.EncodeToString(b)
		}
		if !valid || o.Reason == "" || (!IsManagedKind(o.Result) && o.Result != "excluded") {
			return nil, fmt.Errorf("classification override requires a manual/strong MAC identity, managed/excluded result and reason")
		}
		if _, exists := out[o.IdentityKey]; exists {
			return nil, fmt.Errorf("duplicate classification override %q", o.IdentityKey)
		}
		out[o.IdentityKey] = Classification{Result: o.Result, RuleID: "override:" + o.IdentityKey, Reason: o.Reason}
	}
	return out, nil
}
