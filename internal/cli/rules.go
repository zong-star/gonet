package cli

import (
	"encoding/hex"
	"fmt"
	"gonet/internal/config"
	"gonet/internal/identity"
	"gonet/internal/topology"
)

func resolutionRules(cfg *config.Config) (*identity.Registry, *topology.Resolver, error) {
	var rules []identity.Rule
	var err error
	if cfg.Classification.RulesFile != "" {
		rules, err = identity.LoadRules(cfg.Classification.RulesFile)
		if err != nil {
			return nil, nil, err
		}
	}
	var overrides []identity.Override
	for _, o := range cfg.Identity.Overrides {
		if o.Reason == "" || o.MatchChassis.Subtype < 1 || o.MatchChassis.Subtype > 7 {
			return nil, nil, fmt.Errorf("identity override requires valid subtype and reason")
		}
		if b, e := hex.DecodeString(o.MatchChassis.RawHex); e != nil || len(b) == 0 || len(b) > 255 {
			return nil, nil, fmt.Errorf("invalid override raw_hex")
		}
		overrides = append(overrides, identity.Override{Subtype: uint8(o.MatchChassis.Subtype), RawHex: o.MatchChassis.RawHex, CanonicalKey: o.CanonicalKey})
	}
	var classes []identity.ClassificationOverride
	for _, o := range cfg.Classification.Overrides {
		classes = append(classes, identity.ClassificationOverride{IdentityKey: o.IdentityKey, Result: o.Result, Reason: o.Reason})
	}
	reg, err := identity.New(identity.Options{AllowNetworkAddressChassis: cfg.Identity.AllowNetworkAddressChassis, Rules: rules, Overrides: overrides, ClassificationOverrides: classes})
	if err != nil {
		return nil, nil, err
	}
	res := topology.NewResolver(nil)
	var portOverrides []topology.Override
	for _, o := range cfg.Ports.Overrides {
		aliases := make([]topology.PortKey, 0, len(o.AliasKeys))
		for _, a := range o.AliasKeys {
			aliases = append(aliases, topology.PortKey(a))
		}
		portOverrides = append(portOverrides, topology.Override{IdentityKey: o.IdentityKey, CanonicalKey: topology.PortKey(o.CanonicalPortKey), Aliases: aliases, Physical: o.Physical, Reason: o.Reason})
	}
	if err := res.SetOverrides(portOverrides); err != nil {
		return nil, nil, err
	}
	if cfg.Ports.RulesFile != "" {
		pr, err := topology.LoadPortRules(cfg.Ports.RulesFile)
		if err != nil {
			return nil, nil, err
		}
		known := map[string]bool{}
		for _, r := range rules {
			known[r.ID] = true
		}
		for _, r := range pr {
			if !known[r.DeviceRuleID] {
				return nil, nil, fmt.Errorf("port rule %q references unknown device_rule_id", r.ID)
			}
		}
		if err := res.SetRules(pr); err != nil {
			return nil, nil, err
		}
	}
	return reg, res, nil
}
