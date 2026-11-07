package identity

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gonet/internal/collector/oidutil"
)

// Classification records a managed kind, exclusion or unknown result and its rule.
type Classification struct {
	Result        string `json:"result"` // switch | router | wireless_controller | excluded | unknown
	RuleID        string `json:"rule_id"`
	Reason        string `json:"reason"`
	CandidateKind string `json:"candidate_kind,omitempty"`
}

func IsManagedKind(kind string) bool {
	return kind == "switch" || kind == "router" || kind == "wireless_controller"
}
func (c Classification) Managed() bool { return IsManagedKind(c.Result) }
func (c Classification) IsProbeCandidate() bool {
	return c.IsBridgeCandidate() || IsManagedKind(c.CandidateKind)
}

// Excluded reports whether the classification excludes the device.
func (c Classification) Excluded() bool { return c.Result == "excluded" }

// Switch reports whether the classification confirms a switch.
func (c Classification) Switch() bool { return c.Result == "switch" }

// IsBridgeCandidate reports a bridge capability candidate that still needs
// sysObjectID confirmation after a probe.
func (c Classification) IsBridgeCandidate() bool {
	return c.Result == "unknown" && strings.Contains(c.Reason, "bridge candidate")
}

// Rule is a configured device classification rule. A rule with both a
// sysObjectID prefix and a description regex requires both to match.
type Rule struct {
	ID                string
	Vendor            string // display metadata only; never used as identity
	Model             string
	SysObjectIDPrefix string
	DescriptionRegex  string
	Action            string // switch | router | wireless_controller | excluded
	Priority          int
}

type compiledRule struct {
	Rule
	re *regexp.Regexp
}

// Classifier applies configured rules then capability screening.
type Classifier struct {
	rules []compiledRule
}

// NewClassifier compiles rules and validates them. Rules with neither a prefix
// nor a regex are rejected (they would match everything).
func NewClassifier(rules []Rule) (*Classifier, error) {
	compiled := make([]compiledRule, 0, len(rules))
	ids := map[string]bool{}
	for _, r := range rules {
		if r.ID == "" {
			return nil, fmt.Errorf("classification rule without id")
		}
		if ids[r.ID] {
			return nil, fmt.Errorf("duplicate classification rule %q", r.ID)
		}
		ids[r.ID] = true
		if r.SysObjectIDPrefix != "" {
			if _, err := oidutil.Split(r.SysObjectIDPrefix); err != nil {
				return nil, fmt.Errorf("classification rule %q: %w", r.ID, err)
			}
		}
		if r.SysObjectIDPrefix == "" && r.DescriptionRegex == "" {
			return nil, fmt.Errorf("classification rule %q has no match condition", r.ID)
		}
		if !IsManagedKind(r.Action) && r.Action != "excluded" {
			return nil, fmt.Errorf("classification rule %q has invalid action %q", r.ID, r.Action)
		}
		cr := compiledRule{Rule: r}
		if r.DescriptionRegex != "" {
			re, err := regexp.Compile(r.DescriptionRegex)
			if err != nil {
				return nil, fmt.Errorf("classification rule %q bad regex: %w", r.ID, err)
			}
			cr.re = re
		}
		compiled = append(compiled, cr)
	}
	for i, a := range compiled {
		for _, b := range compiled[i+1:] {
			if a.Priority == b.Priority && a.Action != b.Action && (a.SysObjectIDPrefix == "" || b.SysObjectIDPrefix == "" || oidMatches(a.SysObjectIDPrefix, b.SysObjectIDPrefix) || oidMatches(b.SysObjectIDPrefix, a.SysObjectIDPrefix)) {
				return nil, fmt.Errorf("classification rules %q and %q have conflicting actions at equal priority; assign explicit priorities", a.ID, b.ID)
			}
		}
	}
	sort.SliceStable(compiled, func(i, j int) bool { return compiled[i].Priority < compiled[j].Priority })
	return &Classifier{rules: compiled}, nil
}

// An exact supported model advertisement may authorize a bounded probe even
// when its capabilities say router/AP. The product OID and local chassis must
// still be verified directly before it is admitted to the formal topology.
func (c *Classifier) ClassifyAdvertisement(descr string, supported, enabled []byte) Classification {
	base := c.Classify("", descr, supported, enabled)
	if base.RuleID != "capability" {
		return base
	}
	for _, r := range c.rules {
		if r.re != nil && r.re.MatchString(descr) {
			if r.Action == "excluded" {
				return Classification{Result: "excluded", RuleID: r.ID, Reason: "advertised exclusion:" + r.ID}
			}
			if IsManagedKind(r.Action) {
				return Classification{Result: "unknown", RuleID: r.ID, Reason: "supported model candidate; direct product OID required", CandidateKind: r.Action}
			}
		}
	}
	return base
}

// Classify returns a managed kind, excluded or unknown with the deciding rule.
func (c *Classifier) Classify(sysObjectID, sysDescr string, capSupported, capEnabled []byte) Classification {
	oid := strings.TrimPrefix(sysObjectID, ".")
	for _, r := range c.rules {
		if r.SysObjectIDPrefix != "" {
			prefix := strings.TrimPrefix(r.SysObjectIDPrefix, ".")
			if !oidMatches(prefix, oid) {
				continue
			}
		}
		if r.re != nil && !r.re.MatchString(sysDescr) {
			continue
		}
		return Classification{Result: r.Action, RuleID: r.ID, Reason: "rule:" + r.ID}
	}
	return capabilityScreen(capSupported, capEnabled)
}

func oidMatches(prefix, oid string) bool {
	p, err := oidutil.Split(prefix)
	if err != nil {
		return false
	}
	o, err := oidutil.Split(oid)
	if err != nil || len(o) < len(p) {
		return false
	}
	for i, n := range p {
		if o[i] != n {
			return false
		}
	}
	return true
}

// capabilityScreen classifies by LLDP system capabilities. Bridge (with or
// without router) is only a candidate; router-only and AP/telephone/station
// are excluded. A layer-3 switch is not excluded merely for advertising router.
func capabilityScreen(capSupported, capEnabled []byte) Classification {
	bits := capEnabled
	if len(bits) == 0 {
		bits = capSupported
	}
	hasAP := capBit(bits, 3)
	hasPhone := capBit(bits, 5)
	hasStation := capBit(bits, 7)
	hasBridge := capBit(bits, 2)
	hasRouter := capBit(bits, 4)

	switch {
	case hasAP || hasPhone || hasStation:
		return Classification{Result: "excluded", RuleID: "capability", Reason: "capability:ap/telephone/station"}
	case hasBridge:
		return Classification{Result: "unknown", RuleID: "capability", Reason: "capability:bridge candidate (needs sysObjectID confirmation)"}
	case hasRouter:
		return Classification{Result: "excluded", RuleID: "capability", Reason: "capability:router-only"}
	default:
		return Classification{Result: "unknown", RuleID: "capability", Reason: "no classifying capability"}
	}
}

func capBit(bits []byte, n int) bool {
	if n < 0 || n/8 >= len(bits) {
		return false
	}
	return bits[n/8]&(0x80>>uint(n%8)) != 0
}
