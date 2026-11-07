package topology

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"gonet/internal/model"
	"gopkg.in/yaml.v3"
)

// PortRule is scoped to one verified device classification rule. Aliases
// convert exact interface names only; raw LLDP identities remain unchanged.
type PortRule struct {
	ID                    string            `yaml:"id"`
	DeviceRuleID          string            `yaml:"device_rule_id"`
	Aliases               map[string]string `yaml:"aliases"`
	NonPhysicalNameRegex  string            `yaml:"non_physical_name_regex"`
	Fixture               string            `yaml:"fixture"`
	LegacyGigabitEthernet bool              `yaml:"legacy_gigabit_ethernet"`
	re                    *regexp.Regexp
}

func LoadPortRules(path string) ([]PortRule, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var file struct {
		Version int        `yaml:"version"`
		Rules   []PortRule `yaml:"rules"`
	}
	d := yaml.NewDecoder(f)
	d.KnownFields(true)
	if err := d.Decode(&file); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("port rules must contain one YAML document")
	}
	if file.Version != 1 {
		return nil, fmt.Errorf("unsupported port rules version %d", file.Version)
	}
	return file.Rules, nil
}

// SetRules rejects ambiguous aliases and duplicate scopes rather than
// choosing whichever rule happens to be encountered first.
func (r *Resolver) SetRules(rules []PortRule) error {
	r.rules = map[string]PortRule{}
	ids := map[string]bool{}
	for _, rule := range rules {
		if rule.ID == "" || rule.DeviceRuleID == "" || rule.Fixture == "" || ids[rule.ID] {
			return fmt.Errorf("port rule requires unique id, device_rule_id and fixture")
		}
		ids[rule.ID] = true
		if _, ok := r.rules[rule.DeviceRuleID]; ok {
			return fmt.Errorf("duplicate port rule scope %q", rule.DeviceRuleID)
		}
		dest := map[string]bool{}
		for from, to := range rule.Aliases {
			if from == "" || to == "" || from == to || dest[to] {
				return fmt.Errorf("port aliases must be nonempty and one-to-one")
			}
			if _, chain := rule.Aliases[to]; chain {
				return fmt.Errorf("port alias chains are ambiguous")
			}
			dest[to] = true
		}
		if rule.NonPhysicalNameRegex != "" {
			var err error
			rule.re, err = regexp.Compile(rule.NonPhysicalNameRegex)
			if err != nil {
				return err
			}
		}
		r.rules[rule.DeviceRuleID] = rule
	}
	return nil
}

func (r *Resolver) SetDeviceRule(device model.DevRef, ruleID string) {
	if r.deviceRules == nil {
		r.deviceRules = map[model.DevRef]string{}
	}
	r.deviceRules[device] = ruleID
}

func (r *Resolver) localMapping(device model.DevRef, lp model.LocalPort, ifaces []model.Interface) (*int32, int32, string) {
	idx, typ, source := resolveLocalMapping(lp, ifaces)
	if name, ok := r.verifiedInterfaceAlias(device, lp.ID); ok {
		if i, unique := uniqueByName(ifaces, name); unique {
			idx, typ, source = ptrIface(ifaces, i, TS7914AliasRule)
		}
	}
	rule, ok := r.rules[r.deviceRules[device]]
	if !ok {
		return idx, typ, source
	}
	if idx == nil && lp.ID.Subtype == 5 {
		if name, ok := rule.Aliases[string(lp.ID.Raw)]; ok {
			if i, unique := uniqueByName(ifaces, name); unique {
				idx, typ, source = ptrIface(ifaces, i, "rule:"+rule.ID+":alias")
			}
		}
	}
	if idx != nil && rule.re != nil {
		for _, iface := range ifaces {
			if iface.IfIndex == *idx && rule.re.MatchString(iface.Name) {
				return idx, 0, "rule:" + rule.ID + ":non-physical"
			}
		}
	}
	return idx, typ, source
}

// A typed key is never constructed from display text or loosely normalized
// punctuation. This validator is also used for manual override inputs.
func ValidPortKey(key string) bool {
	p := strings.Split(key, ":")
	if len(p) != 3 || p[0] != "lldp" || len(p[1]) != 1 || p[1][0] < '1' || p[1][0] > '7' || len(p[2]) == 0 || len(p[2]) > 510 || len(p[2])%2 != 0 {
		return false
	}
	for _, c := range p[2] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
