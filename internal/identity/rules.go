package identity

import (
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ruleDef is the YAML shape of one classification rule.
type ruleDef struct {
	ID                string `yaml:"id"`
	Vendor            string `yaml:"vendor"`
	Model             string `yaml:"model"`
	SysObjectIDPrefix string `yaml:"sys_object_id_prefix"`
	DescriptionRegex  string `yaml:"description_regex"`
	Action            string `yaml:"action"`
	Priority          int    `yaml:"priority"`
}

type rulesFile struct {
	Version int       `yaml:"version"`
	Rules   []ruleDef `yaml:"rules"`
}

// LoadRules reads a strict device_rules.yaml file into classifier rules.
func LoadRules(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read device rules: %w", err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	var rf rulesFile
	if err := dec.Decode(&rf); err != nil {
		return nil, fmt.Errorf("parse device rules: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("device rules must contain one YAML document")
	}
	if rf.Version != 1 {
		return nil, fmt.Errorf("unsupported device rules version %d (want 1)", rf.Version)
	}
	out := make([]Rule, 0, len(rf.Rules))
	for _, r := range rf.Rules {
		out = append(out, Rule{
			ID:                r.ID,
			Vendor:            r.Vendor,
			Model:             r.Model,
			SysObjectIDPrefix: r.SysObjectIDPrefix,
			DescriptionRegex:  r.DescriptionRegex,
			Action:            r.Action,
			Priority:          r.Priority,
		})
	}
	if _, err := NewClassifier(out); err != nil {
		return nil, err
	}
	return out, nil
}
