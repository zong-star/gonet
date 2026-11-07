// Package config implements strict YAML loading and validation for GoNet.
// Unknown fields are rejected, and secrets are referenced by environment
// variable name (never embedded as plaintext) and resolved lazily per profile.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gonet/internal/secretfile"

	"gopkg.in/yaml.v3"
)

// Duration parses Go duration strings ("3s", "15m") from YAML scalars.
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		return fmt.Errorf("duration must be a scalar string, got node kind %d", value.Kind)
	}
	v, err := time.ParseDuration(value.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", value.Value, err)
	}
	d.Duration = v
	return nil
}

func (d Duration) MarshalYAML() (any, error) {
	return d.Duration.String(), nil
}

// Config is the root configuration object (section 10.1).
type Config struct {
	baseDir         string
	TopologyScan    TopologyScanConfig    `yaml:"topology_scan"`
	InterfaceStatus InterfaceStatusConfig `yaml:"interface_status"`
	Version         int                   `yaml:"version"`
	Database        DatabaseConfig        `yaml:"database"`
	Discovery       DiscoveryConfig       `yaml:"discovery"`
	SNMP            SNMPConfig            `yaml:"snmp"`
	Identity        IdentityConfig        `yaml:"identity"`
	Classification  ClassificationConfig  `yaml:"classification"`
	Ports           PortsConfig           `yaml:"ports"`
	Logging         LoggingConfig         `yaml:"logging"`
	History         HistoryConfig         `yaml:"history"`
}

type TopologyScanConfig struct {
	Interval Duration `yaml:"interval"`
}

type HistoryConfig struct {
	KeepScans int `yaml:"keep_scans"`
}

type DatabaseConfig struct {
	DSNEnv           string   `yaml:"dsn_env"`
	StatementTimeout Duration `yaml:"statement_timeout"`
}

type DiscoveryConfig struct {
	Preprobe              PreprobeConfig `yaml:"preprobe"`
	AllowIPv4LinkLocal    bool           `yaml:"allow_ipv4_link_local,omitempty"`
	Seeds                 []string       `yaml:"seeds"`
	ManagementCIDRs       []string       `yaml:"management_cidrs"`
	ExcludedCIDRs         []string       `yaml:"excluded_cidrs,omitempty"`
	MaxDepth              int            `yaml:"max_depth"`
	MaxDevices            int            `yaml:"max_devices"`
	MaxTargets            int            `yaml:"max_targets"`
	Workers               int            `yaml:"workers"`
	RunTimeout            Duration       `yaml:"run_timeout"`
	MaxAddressesPerDevice int            `yaml:"max_addresses_per_device"`
}

type PreprobeConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	Workers          int      `yaml:"workers" json:"workers"`
	Timeout          Duration `yaml:"timeout" json:"timeout"`
	Retries          int      `yaml:"retries" json:"retries"`
	HostTimeout      Duration `yaml:"host_timeout" json:"host_timeout"`
	MaxHostsPerRun   int      `yaml:"max_hosts_per_run" json:"max_hosts_per_run"`
	KnownHostsPerRun int      `yaml:"known_hosts_per_run" json:"known_hosts_per_run"`
	PhaseTimeout     Duration `yaml:"phase_timeout" json:"phase_timeout"`
	RefreshInterval  Duration `yaml:"refresh_interval" json:"refresh_interval"`
}

func (p *PreprobeConfig) defaults() {
	if p.Workers == 0 {
		p.Workers = 8
	}
	if p.Timeout.Duration == 0 {
		p.Timeout.Duration = time.Second
	}
	if p.HostTimeout.Duration == 0 {
		p.HostTimeout.Duration = 3 * time.Second
	}
	if p.MaxHostsPerRun == 0 {
		p.MaxHostsPerRun = 256
	}
	if p.KnownHostsPerRun == 0 {
		p.KnownHostsPerRun = 64
	}
	if p.PhaseTimeout.Duration == 0 {
		p.PhaseTimeout.Duration = time.Minute
	}
	if p.RefreshInterval.Duration == 0 {
		p.RefreshInterval.Duration = 15 * time.Minute
	}
}

type SNMPConfig struct {
	LAGTimeout                 Duration                 `yaml:"lag_timeout"`
	LAGMaxPDUs                 int                      `yaml:"lag_max_pdus"`
	CollectManagementAddresses bool                     `yaml:"collect_management_addresses"`
	Adapters                   []string                 `yaml:"adapters"`
	Port                       uint16                   `yaml:"port"`
	DefaultProfile             string                   `yaml:"default_profile"`
	Timeout                    Duration                 `yaml:"timeout"`
	Retries                    int                      `yaml:"retries"`
	DeviceTimeout              Duration                 `yaml:"device_timeout"`
	MaxRepetitions             uint32                   `yaml:"max_repetitions"`
	MaxPDUsPerDevice           int                      `yaml:"max_pdus_per_device"`
	MaxNeighborsPerDevice      int                      `yaml:"max_neighbors_per_device"`
	ConsistencyRetries         int                      `yaml:"consistency_retries"`
	StartupGrace               Duration                 `yaml:"startup_grace"`
	ViewVerified               bool                     `yaml:"view_verified"`
	Profiles                   map[string]ProfileConfig `yaml:"profiles"`
	ProfileRules               []ProfileRule            `yaml:"profile_rules"`
}

type ProfileConfig struct {
	CommunityFile   string `yaml:"community_file,omitempty"`
	Version         string `yaml:"version"` // "2c" or "3"
	SecurityLevel   string `yaml:"security_level"`
	CommunityEnv    string `yaml:"community_env"`
	UsernameEnv     string `yaml:"username_env"`
	AuthProtocol    string `yaml:"auth_protocol"`
	AuthPasswordEnv string `yaml:"auth_password_env"`
	PrivProtocol    string `yaml:"priv_protocol"`
	PrivPasswordEnv string `yaml:"priv_password_env"`
	ContextName     string `yaml:"context_name"`
}

type ProfileRule struct {
	CIDR    string `yaml:"cidr"`
	Profile string `yaml:"profile"`
}

type IdentityConfig struct {
	AllowNetworkAddressChassis bool               `yaml:"allow_network_address_chassis"`
	Overrides                  []IdentityOverride `yaml:"overrides"`
	AddressOverrides           []AddressOverride  `yaml:"address_overrides"`
}

type IdentityOverride struct {
	MatchChassis MatchChassis `yaml:"match_chassis"`
	CanonicalKey string       `yaml:"canonical_key"`
	Reason       string       `yaml:"reason"`
}

type MatchChassis struct {
	Subtype int    `yaml:"subtype"`
	RawHex  string `yaml:"raw_hex"`
}

type AddressOverride struct {
	IdentityKey string   `yaml:"identity_key"`
	Addresses   []string `yaml:"addresses"`
	Reason      string   `yaml:"reason"`
}

type ClassificationConfig struct {
	RulesFile string                   `yaml:"rules_file"`
	Overrides []ClassificationOverride `yaml:"overrides"`
}

type ClassificationOverride struct {
	IdentityKey string `yaml:"identity_key"`
	Result      string `yaml:"result"`
	Reason      string `yaml:"reason"`
}

type PortsConfig struct {
	RulesFile string         `yaml:"rules_file"`
	Overrides []PortOverride `yaml:"overrides"`
}

type PortOverride struct {
	IdentityKey      string   `yaml:"identity_key"`
	CanonicalPortKey string   `yaml:"canonical_port_key"`
	AliasKeys        []string `yaml:"alias_keys"`
	Physical         bool     `yaml:"physical"`
	Reason           string   `yaml:"reason"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// SNMPProfile is the resolved (env-expanded) credential profile handed to the
// collector. It contains no plaintext in logs or snapshots.
type SNMPProfile struct {
	Name           string
	Version        string // "2c" or "3"
	Community      string
	SecurityLevel  string
	Username       string
	AuthProtocol   string
	AuthPassphrase string
	PrivProtocol   string
	PrivPassphrase string
	ContextName    string
}

// Load reads, strictly parses and structurally validates the config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("CONFIG_INVALID: expected one YAML document")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg.baseDir = filepath.Dir(path)
	return &cfg, nil
}

// InterfaceStatusConfig controls the independent operational poller.
type InterfaceStatusConfig struct {
	Disabled            bool     `yaml:"disabled"`
	Interval            Duration `yaml:"interval"`
	StaleAfter          Duration `yaml:"stale_after"`
	Workers             int      `yaml:"workers"`
	InferenceStaleAfter Duration `yaml:"inference_stale_after"`
}

// Validate checks configuration without reading credentials.
func (c *Config) Validate() error {
	if d := c.TopologyScan.Interval.Duration; d < 0 || d > time.Duration(1<<63-1)/3 || d > 0 && (d < time.Minute || d%time.Minute != 0) {
		return errors.New("CONFIG_INVALID: topology_scan.interval must be zero or whole minutes")
	}
	if c.InterfaceStatus.Interval.Duration == 0 {
		c.InterfaceStatus.Interval.Duration = 4 * time.Minute
	}
	if c.InterfaceStatus.StaleAfter.Duration == 0 {
		c.InterfaceStatus.StaleAfter.Duration = 12 * time.Minute
	}
	if c.InterfaceStatus.InferenceStaleAfter.Duration == 0 {
		c.InterfaceStatus.InferenceStaleAfter.Duration = 72 * time.Hour
	}
	if c.InterfaceStatus.Workers == 0 {
		c.InterfaceStatus.Workers = 4
	}
	if c.InterfaceStatus.Interval.Duration < time.Second || c.InterfaceStatus.StaleAfter.Duration < c.InterfaceStatus.Interval.Duration || c.InterfaceStatus.Workers < 1 || c.InterfaceStatus.Workers > 64 || c.InterfaceStatus.InferenceStaleAfter.Duration < time.Second {
		return errors.New("CONFIG_INVALID: invalid interface_status settings")
	}

	if c.SNMP.LAGTimeout.Duration == 0 {
		c.SNMP.LAGTimeout.Duration = 3 * time.Second
	}
	if c.SNMP.LAGMaxPDUs == 0 {
		c.SNMP.LAGMaxPDUs = 32
	}
	if c.SNMP.LAGTimeout.Duration < time.Millisecond || c.SNMP.LAGTimeout.Duration > time.Minute || c.SNMP.LAGMaxPDUs < 4 || c.SNMP.LAGMaxPDUs > 512 {
		return errors.New("CONFIG_INVALID: invalid snmp LAG budgets")
	}
	c.Discovery.Preprobe.defaults()
	p := c.Discovery.Preprobe
	if p.Workers < 1 || p.Workers > 64 || p.Timeout.Duration <= 0 || p.HostTimeout.Duration <= 0 || p.PhaseTimeout.Duration <= 0 || p.RefreshInterval.Duration <= 0 || p.Retries < 0 || p.Retries > 2 || p.MaxHostsPerRun < 1 || p.MaxHostsPerRun > 100000 || p.KnownHostsPerRun < 1 {
		return errors.New("CONFIG_INVALID: invalid discovery.preprobe budgets or timeouts")
	}
	if c.History.KeepScans == 0 {
		c.History.KeepScans = 500
	}
	if c.History.KeepScans < 2 || c.History.KeepScans > 100000 {
		return errors.New("CONFIG_INVALID: history.keep_scans must be 2..100000 (default 500)")
	}
	for _, name := range c.SNMP.Adapters {
		if name != "sundray_ts7914_chassis38_20251010" && name != "sundray_rs39_20251011" && name != "huawei_s5735_qa2_v200r023_lag" && name != "h3c_s5560_6628p47_lag" && name != "lldp_dot3_lag" {
			return fmt.Errorf("CONFIG_INVALID: unknown SNMP adapter %q", name)
		}
	}
	if c.Version != 1 {
		return fmt.Errorf("CONFIG_INVALID: unsupported config version %d (want 1)", c.Version)
	}
	if c.Discovery.RunTimeout.Duration <= 0 || c.SNMP.Timeout.Duration <= 0 || c.SNMP.DeviceTimeout.Duration <= 0 {
		return errors.New("CONFIG_INVALID: run_timeout, timeout and device_timeout must be positive")
	}
	if c.SNMP.Retries < 0 || c.SNMP.ConsistencyRetries < 0 || c.SNMP.ConsistencyRetries > 1 || c.SNMP.StartupGrace.Duration < 0 {
		return errors.New("CONFIG_INVALID: retries/startup_grace must be nonnegative; consistency_retries must be 0..1")
	}
	if c.Discovery.Workers < 1 || c.Discovery.Workers > 64 {
		return fmt.Errorf("CONFIG_INVALID: discovery.workers must be 1..64, got %d", c.Discovery.Workers)
	}
	if c.Discovery.MaxDepth < 0 || c.Discovery.MaxDepth > 32 {
		return fmt.Errorf("CONFIG_INVALID: discovery.max_depth must be 0..32, got %d", c.Discovery.MaxDepth)
	}
	if c.Discovery.MaxDevices <= 0 || c.Discovery.MaxTargets <= 0 ||
		c.Discovery.MaxAddressesPerDevice <= 0 {
		return errors.New("CONFIG_INVALID: discovery budgets must be positive")
	}
	if c.SNMP.Port < 1 || c.SNMP.Port > 65535 {
		return fmt.Errorf("CONFIG_INVALID: snmp.port must be 1..65535, got %d", c.SNMP.Port)
	}
	if c.SNMP.DeviceTimeout.Duration > 0 && c.Discovery.RunTimeout.Duration > 0 &&
		c.SNMP.DeviceTimeout.Duration > c.Discovery.RunTimeout.Duration {
		return errors.New("CONFIG_INVALID: snmp.device_timeout must not exceed discovery.run_timeout")
	}
	if c.SNMP.MaxRepetitions == 0 {
		return errors.New("CONFIG_INVALID: snmp.max_repetitions must be positive")
	}
	if c.SNMP.MaxPDUsPerDevice <= 0 || c.SNMP.MaxNeighborsPerDevice <= 0 {
		return errors.New("CONFIG_INVALID: snmp budgets must be positive")
	}
	if c.SNMP.DefaultProfile == "" {
		return errors.New("CONFIG_INVALID: snmp.default_profile is required")
	}
	if len(c.SNMP.Profiles) == 0 {
		return errors.New("CONFIG_INVALID: at least one snmp profile is required")
	}
	if _, ok := c.SNMP.Profiles[c.SNMP.DefaultProfile]; !ok {
		return fmt.Errorf("CONFIG_INVALID: default_profile %q is not defined", c.SNMP.DefaultProfile)
	}
	for name, p := range c.SNMP.Profiles {
		if err := validateProfile(name, p); err != nil {
			return err
		}
	}
	// management_cidrs must contain at least one valid CIDR; collect uses it
	// to scope the target.
	if len(c.Discovery.ManagementCIDRs) == 0 {
		return errors.New("CONFIG_INVALID: at least one discovery.management_cidrs entry is required")
	}
	for _, cidr := range c.Discovery.ManagementCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("CONFIG_INVALID: bad management_cidrs entry %q: %w", cidr, err)
		}
	}
	for _, cidr := range c.Discovery.ExcludedCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("CONFIG_INVALID: bad excluded_cidrs entry %q", cidr)
		}
	}
	seen := map[string]struct{}{}
	for _, s := range c.Discovery.Seeds {
		if _, err := netip.ParseAddr(s); err != nil {
			return fmt.Errorf("CONFIG_INVALID: bad seed %q: %w", s, err)
		}
		seen[s] = struct{}{}
	}
	if len(seen) > c.Discovery.MaxDevices {
		return fmt.Errorf("CONFIG_INVALID: %d unique seeds exceed max_devices %d", len(seen), c.Discovery.MaxDevices)
	}
	profileScopes := map[netip.Prefix]string{}
	for _, r := range c.SNMP.ProfileRules {
		pfx, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			return fmt.Errorf("CONFIG_INVALID: bad profile_rules cidr %q: %w", r.CIDR, err)
		}
		pfx = pfx.Masked()
		if prev, ok := profileScopes[pfx]; ok && prev != r.Profile {
			return errors.New("CONFIG_INVALID: conflicting profile_rules")
		}
		profileScopes[pfx] = r.Profile
		if _, ok := c.SNMP.Profiles[r.Profile]; !ok {
			return fmt.Errorf("CONFIG_INVALID: profile_rules references unknown profile %q", r.Profile)
		}
	}
	for _, o := range c.Identity.AddressOverrides {
		if o.IdentityKey == "" || o.Reason == "" || len(o.Addresses) == 0 {
			return errors.New("CONFIG_INVALID: address override requires identity, addresses and reason")
		}
		for _, text := range o.Addresses {
			a, err := netip.ParseAddr(text)
			if err != nil || !c.InManagementScope(a) {
				return errors.New("CONFIG_INVALID: address override outside management_cidrs or invalid")
			}
		}
	}
	return nil
}

func validateProfile(name string, p ProfileConfig) error {
	switch p.Version {
	case "2c":
		if p.CommunityEnv == "" && p.CommunityFile == "" {
			return fmt.Errorf("CONFIG_INVALID: profile %q (v2c) requires community_env or community_file", name)
		}
	case "3":
		if p.UsernameEnv == "" {
			return fmt.Errorf("CONFIG_INVALID: profile %q (v3) requires username_env", name)
		}
		level := strings.ToLower(p.SecurityLevel)
		if level == "" {
			level = "noauthnopriv"
		}
		switch level {
		case "noauthnopriv":
		case "authnopriv":
			if p.AuthProtocol == "" || p.AuthPasswordEnv == "" {
				return fmt.Errorf("CONFIG_INVALID: profile %q (authNoPriv) requires auth_protocol and auth_password_env", name)
			}
		case "authpriv":
			if p.AuthProtocol == "" || p.AuthPasswordEnv == "" ||
				p.PrivProtocol == "" || p.PrivPasswordEnv == "" {
				return fmt.Errorf("CONFIG_INVALID: profile %q (authPriv) requires auth and priv fields", name)
			}
		default:
			return fmt.Errorf("CONFIG_INVALID: profile %q has unknown security_level %q", name, p.SecurityLevel)
		}
	default:
		return fmt.Errorf("CONFIG_INVALID: profile %q has unknown version %q (want 2c or 3)", name, p.Version)
	}
	return nil
}

// ResolveProfile expands the named profile's environment secrets.
func (c *Config) ResolveProfile(name string) (*SNMPProfile, error) {
	p, ok := c.SNMP.Profiles[name]
	if !ok {
		return nil, fmt.Errorf("CONFIG_INVALID: unknown profile %q", name)
	}
	out := &SNMPProfile{Name: name, Version: p.Version}
	switch p.Version {
	case "2c":
		var community string
		var err error
		if p.CommunityFile != "" {
			path := p.CommunityFile
			if !filepath.IsAbs(path) {
				path = filepath.Join(c.baseDir, path)
			}
			community, err = secretfile.Read(path)
		} else {
			community, err = readSecret(p.CommunityEnv)
		}
		if err != nil {
			return nil, err
		}
		out.Community = community
	case "3":
		out.SecurityLevel = p.SecurityLevel
		out.ContextName = p.ContextName
		username, err := readSecret(p.UsernameEnv)
		if err != nil {
			return nil, err
		}
		out.Username = username
		level := strings.ToLower(p.SecurityLevel)
		switch level {
		case "authnopriv":
			out.AuthProtocol = p.AuthProtocol
			out.AuthPassphrase, err = readSecret(p.AuthPasswordEnv)
			if err != nil {
				return nil, err
			}
		case "authpriv":
			out.AuthProtocol = p.AuthProtocol
			out.AuthPassphrase, err = readSecret(p.AuthPasswordEnv)
			if err != nil {
				return nil, err
			}
			out.PrivProtocol = p.PrivProtocol
			out.PrivPassphrase, err = readSecret(p.PrivPasswordEnv)
			if err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// ResolveProfileForAddr picks a profile for addr via longest-prefix match over
// profile_rules, falling back to default_profile on no match.
func (c *Config) ResolveProfileForAddr(addr netip.Addr) (string, error) {
	bestLen := -1
	best := ""
	for _, r := range c.SNMP.ProfileRules {
		pfx, err := netip.ParsePrefix(r.CIDR)
		if err != nil {
			return "", fmt.Errorf("CONFIG_INVALID: bad profile_rules cidr %q", r.CIDR)
		}
		if pfx.Contains(addr) {
			if pfx.Bits() == bestLen && best != r.Profile {
				return "", fmt.Errorf("CONFIG_INVALID: profile_rules conflict at prefix length %d for %s", pfx.Bits(), addr)
			}
			if pfx.Bits() > bestLen {
				bestLen = pfx.Bits()
				best = r.Profile
			}
		}
	}
	if best == "" {
		return c.SNMP.DefaultProfile, nil
	}
	return best, nil
}

// ResolveAllProfiles validates that every defined profile's secrets resolve.
func (c *Config) ResolveAllProfiles() error {
	for name := range c.SNMP.Profiles {
		if _, err := c.ResolveProfile(name); err != nil {
			return err
		}
	}
	return nil
}

// ManagementCIDRs returns the parsed management CIDRs.
func (c *Config) ManagementCIDRs() ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(c.Discovery.ManagementCIDRs))
	for _, cidr := range c.Discovery.ManagementCIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("CONFIG_INVALID: bad management_cidrs %q", cidr)
		}
		out = append(out, p)
	}
	return out, nil
}

// Seeds returns the parsed seed addresses.
func (c *Config) Seeds() ([]netip.Addr, error) {
	out := make([]netip.Addr, 0, len(c.Discovery.Seeds))
	for _, s := range c.Discovery.Seeds {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("CONFIG_INVALID: bad seed %q: %w", s, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// InManagementScope reports whether addr is within an allowed management CIDR.
func (c *Config) InManagementScope(addr netip.Addr) bool {
	for _, cidr := range c.Discovery.ExcludedCIDRs {
		if p, err := netip.ParsePrefix(cidr); err == nil && p.Contains(addr.Unmap()) {
			return false
		}
	}
	for _, cidr := range c.Discovery.ManagementCIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// SanitizedSummary returns the non-secret configuration summary stored with a
// scan row. It contains seeds, allowed CIDRs, thresholds and the rule source,
// never community/auth/priv values.
func (c *Config) SanitizedSummary() map[string]any {
	return map[string]any{
		"history_keep_scans":           c.History.KeepScans,
		"classification":               c.Classification,
		"identity":                     c.Identity,
		"ports":                        c.Ports,
		"profile_rules":                c.SNMP.ProfileRules,
		"profiles":                     c.SNMP.Profiles,
		"default_profile":              c.SNMP.DefaultProfile,
		"rule_hashes":                  c.ruleHashes(),
		"version":                      c.Version,
		"seeds":                        c.Discovery.Seeds,
		"management_cidrs":             c.Discovery.ManagementCIDRs,
		"allow_ipv4_link_local":        c.Discovery.AllowIPv4LinkLocal,
		"excluded_cidrs":               c.Discovery.ExcludedCIDRs,
		"max_depth":                    c.Discovery.MaxDepth,
		"max_devices":                  c.Discovery.MaxDevices,
		"max_targets":                  c.Discovery.MaxTargets,
		"preprobe":                     c.Discovery.Preprobe,
		"preprobe_mode":                "full_range",
		"workers":                      c.Discovery.Workers,
		"run_timeout":                  c.Discovery.RunTimeout.Duration.String(),
		"max_addresses_per_device":     c.Discovery.MaxAddressesPerDevice,
		"snmp_port":                    c.SNMP.Port,
		"snmp_timeout":                 c.SNMP.Timeout.Duration.String(),
		"snmp_retries":                 c.SNMP.Retries,
		"device_timeout":               c.SNMP.DeviceTimeout.Duration.String(),
		"max_repetitions":              c.SNMP.MaxRepetitions,
		"max_pdus_per_device":          c.SNMP.MaxPDUsPerDevice,
		"max_neighbors_per_device":     c.SNMP.MaxNeighborsPerDevice,
		"consistency_retries":          c.SNMP.ConsistencyRetries,
		"startup_grace":                c.SNMP.StartupGrace.Duration.String(),
		"view_verified":                c.SNMP.ViewVerified,
		"collect_management_addresses": c.SNMP.CollectManagementAddresses,
		"adapters":                     c.SNMP.Adapters,
		"lag_timeout":                  c.SNMP.LAGTimeout.Duration.String(),
		"lag_max_pdus":                 c.SNMP.LAGMaxPDUs,
		"rules_file":                   c.Classification.RulesFile,
	}
}

func (c *Config) ruleHashes() map[string]string {
	out := map[string]string{}
	for _, path := range []string{c.Classification.RulesFile, c.Ports.RulesFile} {
		if path == "" {
			continue
		}
		b, err := os.ReadFile(path)
		if err != nil {
			out[path] = "unreadable"
			continue
		}
		h := sha256.Sum256(b)
		out[path] = hex.EncodeToString(h[:])
	}
	return out
}

// ConfigDigest is the SHA-256 of the sanitized summary (rule source included,
// secrets excluded).
func (c *Config) ConfigDigest() (string, error) {
	b, err := json.Marshal(c.SanitizedSummary())
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// DatabaseDSN resolves the DSN from the configured environment variable. It is
// only required by database commands (migrate, scan persist, topology export).
func (c *Config) DatabaseDSN() (string, error) {
	if c.Database.DSNEnv == "" {
		return "", fmt.Errorf("CONFIG_INVALID: database.dsn_env is required")
	}
	v := os.Getenv(c.Database.DSNEnv)
	if v == "" {
		return "", fmt.Errorf("SECRET_MISSING: environment variable %s is empty or unset", c.Database.DSNEnv)
	}
	return v, nil
}

func readSecret(envName string) (string, error) {
	v := os.Getenv(envName)
	if v == "" {
		return "", fmt.Errorf("SECRET_MISSING: environment variable %s is empty or unset", envName)
	}
	return v, nil
}
