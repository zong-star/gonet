package control

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"gonet/internal/config"
	"gonet/internal/secretfile"
)

// Community is write-only, including when Settings is persisted to scope JSON.
type SNMPSettings struct {
	Version             string `json:"version"`
	CommunityConfigured bool   `json:"community_configured"`
	Community           string `json:"-"`
}

func (s *SNMPSettings) UnmarshalJSON(data []byte) error {
	var wire struct {
		Version             string `json:"version"`
		CommunityConfigured bool   `json:"community_configured"`
		Community           string `json:"community"`
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil || d.Decode(&struct{}{}) != io.EOF {
		return errors.New("SNMP 配置格式无效")
	}
	*s = SNMPSettings{Version: wire.Version, Community: wire.Community, CommunityConfigured: wire.CommunityConfigured}
	return nil
}

func (s SNMPSettings) Validate() error {
	if s.Version != "2c" {
		return errors.New("网页 SNMP 配置仅支持 v2c")
	}
	if len(s.Community) > 255 || strings.ContainsAny(s.Community, "\x00\r\n") {
		return errors.New("SNMP 团体名不能超过 255 字节或包含换行、NUL")
	}
	return nil
}

func SyncSNMPSettings(s *Settings, cfg *config.Config) {
	p := cfg.SNMP.Profiles[cfg.SNMP.DefaultProfile]
	resolved, err := cfg.ResolveProfile(cfg.SNMP.DefaultProfile)
	s.SNMP = &SNMPSettings{Version: p.Version, CommunityConfigured: err == nil && resolved.Version == "2c" && resolved.Community != ""}
}

func applySNMPSettings(cfg *config.Config, configPath string, s *SNMPSettings) (func() error, error) {
	noop := func() error { return nil }
	if s == nil {
		return noop, nil
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	name := cfg.SNMP.DefaultProfile
	p, exists := cfg.SNMP.Profiles[name]
	if !exists {
		return nil, errors.New("默认 SNMP 配置不存在")
	}
	rollback := noop
	if s.Community != "" {
		hash := sha256.Sum256([]byte(name))
		relative := filepath.Join("config", fmt.Sprintf("snmp-community-%x.secret", hash[:8]))
		var err error
		rollback, err = secretfile.Store(filepath.Join(filepath.Dir(configPath), relative), s.Community)
		if err != nil {
			return nil, errors.New("SNMP 团体名保存失败")
		}
		p.CommunityFile = relative
	} else {
		resolved, err := cfg.ResolveProfile(name)
		if err != nil || resolved.Version != "2c" || resolved.Community == "" {
			return nil, errors.New("请填写 SNMP v2c 团体名")
		}
	}
	p.Version = "2c"
	cfg.SNMP.Profiles[name] = p
	cfg.Discovery.Preprobe.Enabled = true
	s.CommunityConfigured = true
	return rollback, nil
}
