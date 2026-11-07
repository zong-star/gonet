// Package control shares local-console policy with CLI exports. IP addresses
// authorize access only; chassis identities still govern device membership.
package control

import (
	"encoding/json"
	"fmt"
	"gonet/internal/config"
	"gopkg.in/yaml.v3"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Settings struct {
	SNMP                 *SNMPSettings       `json:"snmp,omitempty"`
	TopologyScanInterval *CollectionInterval `json:"topology_scan_interval,omitempty"`
	CollectionInterval   *CollectionInterval `json:"collection_interval,omitempty"`
	Seeds                []string            `json:"seeds"`
	AllowedCIDRs         []string            `json:"allowed_cidrs"`
	ExcludedCIDRs        []string            `json:"excluded_cidrs"`
	BootstrapCIDRs       []string            `json:"bootstrap_cidrs"`
	ReadManagement       bool                `json:"read_management_addresses"`
}
type InventoryRow struct {
	Row           int      `json:"row"`
	Area          string   `json:"area"`
	Name          string   `json:"name"`
	Address       string   `json:"address"`
	Vendor        string   `json:"vendor"`
	Model         string   `json:"model"`
	Hostname      string   `json:"hostname"`
	Included      bool     `json:"included"`
	Reason        string   `json:"reason"`
	IdentityKeys  []string `json:"identity_keys,omitempty"`
	SourceAddress string   `json:"source_address,omitempty"`
	AddressNote   string   `json:"address_note,omitempty"`
}
type Scope struct {
	Version       int            `json:"version"`
	Mode          string         `json:"mode,omitempty"`
	Source        string         `json:"source,omitempty"`
	Sheet         string         `json:"sheet,omitempty"`
	UpdatedAt     time.Time      `json:"updated_at"`
	IncludedCount int            `json:"included_count"`
	ExcludedCount int            `json:"excluded_count"`
	Settings      Settings       `json:"settings"`
	Rows          []InventoryRow `json:"rows"`
}

func LoadScope(path string) (*Scope, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Scope{Version: 1, Rows: []InventoryRow{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var s Scope
	if err = json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	if s.Version != 1 {
		return nil, fmt.Errorf("unsupported scope version")
	}
	return &s, nil
}
func prefix(raw string) (netip.Prefix, error) {
	if a, e := netip.ParseAddr(strings.TrimSpace(raw)); e == nil {
		return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
	}
	p, e := netip.ParsePrefix(strings.TrimSpace(raw))
	if e != nil {
		return p, fmt.Errorf("无效 IP/IP 段：%s", raw)
	}
	return p.Masked(), nil
}
func CanonicalCIDRs(raw []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, v := range raw {
		p, e := prefix(v)
		if e != nil {
			return nil, e
		}
		if !seen[p.String()] {
			out = append(out, p.String())
			seen[p.String()] = true
		}
	}
	return out, nil
}
func (s Settings) Allows(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
		return false
	}
	for _, v := range s.ExcludedCIDRs {
		p, e := prefix(v)
		if e == nil && p.Contains(a) {
			return false
		}
	}
	for _, v := range s.AllowedCIDRs {
		p, e := prefix(v)
		if e == nil && p.Contains(a) {
			return true
		}
	}
	return false
}
func (s *Settings) Validate(maxTargets int) error {
	if s.SNMP != nil {
		if err := s.SNMP.Validate(); err != nil {
			return err
		}
	}
	if s.TopologyScanInterval != nil {
		if _, err := s.TopologyScanInterval.TopologyDuration(); err != nil {
			return err
		}
	}
	if s.CollectionInterval != nil {
		if _, err := s.CollectionInterval.Duration(); err != nil {
			return err
		}
	}
	if len(s.Seeds) == 0 || len(s.Seeds) > 200 {
		return fmt.Errorf("需要 1–200 个发现起点 IP")
	}
	var err error
	if s.AllowedCIDRs, err = CanonicalCIDRs(s.AllowedCIDRs); err != nil {
		return err
	}
	if len(s.AllowedCIDRs) == 0 {
		return fmt.Errorf("至少需要一个允许范围")
	}
	if s.ExcludedCIDRs, err = CanonicalCIDRs(s.ExcludedCIDRs); err != nil {
		return err
	}
	if s.BootstrapCIDRs, err = CanonicalCIDRs(s.BootstrapCIDRs); err != nil {
		return err
	}
	seen := map[string]bool{}
	seeds := []string{}
	for _, v := range s.Seeds {
		a, e := netip.ParseAddr(strings.TrimSpace(v))
		if e != nil || !s.Allows(a) {
			return fmt.Errorf("起点 %s 无效、未被允许或命中排除范围", v)
		}
		a = a.Unmap()
		if !seen[a.String()] {
			seen[a.String()] = true
			seeds = append(seeds, a.String())
		}
	}
	s.Seeds = seeds
	_, err = s.BootstrapAddresses(maxTargets)
	return err
}

// Address supplementation is opt-in and bounded across the whole request.
// CIDRs authorize probes; their hosts never become extra topology seeds.
func (s Settings) BootstrapAddresses(max int) ([]netip.Addr, error) {
	out := []netip.Addr{}
	seen := map[netip.Addr]bool{}
	if max <= 0 {
		if len(s.BootstrapCIDRs) > 0 {
			return nil, fmt.Errorf("地址补全没有剩余目标预算")
		}
		return out, nil
	}
	for _, v := range s.BootstrapCIDRs {
		p, e := prefix(v)
		if e != nil {
			return nil, e
		}
		p = p.Masked()
		// Bound enumeration before looping, including excluded hosts.
		hostBits := p.Addr().BitLen() - p.Bits()
		if hostBits > 20 || hostBits >= 0 && (uint64(1)<<hostBits) > uint64(max+2) {
			return nil, fmt.Errorf("地址补全范围 %s 过大，单次最多 %d 个地址", v, max)
		}
		for a := p.Addr(); p.Contains(a); a = a.Next() {
			if a.Is4() && p.Bits() < 31 {
				next := a.Next()
				if a == p.Addr() || !p.Contains(next) {
					continue
				}
			}
			if !s.Allows(a) {
				continue
			}
			if !seen[a] {
				if len(out) >= max {
					return nil, fmt.Errorf("地址补全超出 %d 个地址预算", max)
				}
				seen[a] = true
				out = append(out, a)
			}
		}
		// A supplement range must be wholly inside one configured allow range.
		allowed := false
		for _, raw := range s.AllowedCIDRs {
			q, _ := prefix(raw)
			if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, fmt.Errorf("地址补全范围 %s 必须包含在允许范围中", v)
		}
	}
	return out, nil
}
func (s *Scope) Migrate(cfg *config.Config) {
	if s.Mode == "lldp" {
		return
	}
	s.Mode = "lldp"
	s.Version = 1
	s.Settings = Settings{Seeds: append([]string{}, cfg.Discovery.Seeds...), AllowedCIDRs: append([]string{}, cfg.Discovery.ManagementCIDRs...), ExcludedCIDRs: append([]string{}, cfg.Discovery.ExcludedCIDRs...), BootstrapCIDRs: []string{}, ReadManagement: true}
	for _, r := range s.Rows {
		if r.Included {
			for _, k := range r.IdentityKeys {
				if k == "manual:ts7914-core-stack-01" {
					s.Settings.Seeds = []string{r.Address}
				}
			}
		} else if p, e := prefix(r.Address); e == nil {
			s.Settings.ExcludedCIDRs = append(s.Settings.ExcludedCIDRs, p.String())
		}
	}
	s.Settings.ExcludedCIDRs, _ = CanonicalCIDRs(s.Settings.ExcludedCIDRs)
}
func (s Scope) ExcludedKeys() map[string]bool {
	out := map[string]bool{}
	for _, r := range s.Rows {
		if !r.Included {
			for _, k := range r.IdentityKeys {
				out[k] = true
			}
		}
	}
	return out
}
func AtomicWrite(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".gonet-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	return os.Rename(tmp, path)
}
func WriteJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	return AtomicWrite(path, append(b, '\n'))
}

// RetireBootstrap clears the deprecated address-supplement field that the new
// console no longer exposes, and returns the retired entries so the caller can
// back them up and record them. Only the field value is touched: the legacy
// parsing (Settings.BootstrapCIDRs), the explicit supplementation code
// (BootstrapAddresses) and their tests stay in place.
func RetireBootstrap(s *Settings) []string {
	if s == nil || len(s.BootstrapCIDRs) == 0 {
		return nil
	}
	retired := append([]string{}, s.BootstrapCIDRs...)
	s.BootstrapCIDRs = []string{}
	return retired
}

func SavePolicy(configPath, scopePath string, s *Scope) (retErr error) {
	cfg, e := config.Load(configPath)
	if e != nil {
		return e
	}
	if e = s.Settings.Validate(cfg.Discovery.MaxTargets); e != nil {
		return e
	}
	original, e := os.ReadFile(configPath)
	if e != nil {
		return e
	}
	cfg.Discovery.Seeds = append([]string{}, s.Settings.Seeds...)
	cfg.Discovery.ManagementCIDRs = append([]string{}, s.Settings.AllowedCIDRs...)
	cfg.Discovery.ExcludedCIDRs = append([]string{}, s.Settings.ExcludedCIDRs...)
	cfg.SNMP.CollectManagementAddresses = s.Settings.ReadManagement
	if s.Settings.CollectionInterval != nil {
		interval, err := s.Settings.CollectionInterval.Duration()
		if err != nil {
			return err
		}
		if interval != cfg.InterfaceStatus.Interval.Duration {
			cfg.InterfaceStatus.Interval.Duration = interval
			cfg.InterfaceStatus.StaleAfter.Duration = 3 * interval
		}
	}
	if s.Settings.TopologyScanInterval != nil {
		interval, err := s.Settings.TopologyScanInterval.TopologyDuration()
		if err != nil {
			return err
		}
		cfg.TopologyScan.Interval.Duration = interval
	}
	routes := cfg.Identity.AddressOverrides[:0]
	for _, r := range cfg.Identity.AddressOverrides {
		addrs := []string{}
		for _, v := range r.Addresses {
			a, err := netip.ParseAddr(v)
			if err == nil && s.Settings.Allows(a) {
				addrs = append(addrs, v)
			}
		}
		if len(addrs) > 0 {
			r.Addresses = addrs
			routes = append(routes, r)
		}
	}
	cfg.Identity.AddressOverrides = routes
	rollbackSNMP, err := applySNMPSettings(cfg, configPath, s.Settings.SNMP)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			if err := rollbackSNMP(); err != nil {
				retErr = fmt.Errorf("设置保存失败，SNMP 凭据恢复失败")
			}
		}
	}()
	if e = cfg.Validate(); e != nil {
		return e
	}
	b, e := yaml.Marshal(cfg)
	if e != nil {
		return e
	}
	backupDir := filepath.Join(filepath.Dir(configPath), "outputs", "backups")
	backup := filepath.Join(backupDir, "config-before-ui.yaml")
	if _, err := os.Stat(backup); os.IsNotExist(err) {
		if e = AtomicWrite(backup, original); e != nil {
			return e
		}
	}
	// The scope JSON carries the effective access set, the exclusion set and the
	// seeds, so keep the first pre-console copy of it next to the YAML backup.
	// Best effort: a missing or unreadable scope must not block a valid save.
	if st, err := os.Stat(scopePath); err == nil && st.Mode().IsRegular() {
		if prior, err := os.ReadFile(scopePath); err == nil {
			scopeBackup := filepath.Join(backupDir, "scope-before-ui.json")
			if _, err := os.Stat(scopeBackup); os.IsNotExist(err) {
				_ = AtomicWrite(scopeBackup, prior)
			}
		}
	}
	if e = AtomicWrite(configPath, b); e != nil {
		return e
	}
	s.Mode = "lldp"
	s.UpdatedAt = time.Now()
	if e = WriteJSON(scopePath, s); e != nil {
		_ = AtomicWrite(configPath, original)
		return e
	}
	committed = true
	return nil
}
func SortedKeys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
