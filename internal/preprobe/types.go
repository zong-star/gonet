package preprobe

import (
	"context"
	"net/netip"
	"time"

	"gonet/internal/model"
)

// Attempt contains only directly observed facts, never inferred links or credentials.
type Attempt struct {
	IP          netip.Addr       `json:"probe_ip"`
	ResponseIP  netip.Addr       `json:"response_ip"`
	Facts       model.DeviceInfo `json:"facts"`
	Reachable   bool             `json:"reachable"`
	Attempted   bool             `json:"attempted"`
	Profile     string           `json:"profile_name"`
	ErrorCode   string           `json:"error_code,omitempty"`
	ErrorReason string           `json:"error_reason,omitempty"`
	At          time.Time        `json:"at"`
	PDUs        int              `json:"pdus"`
	Elapsed     time.Duration    `json:"elapsed_ns"`
}
type Prober interface {
	Probe(context.Context, netip.Addr) Attempt
}

type Record struct {
	ResponseIP          netip.Addr        `json:"response_ip"`
	Source              string            `json:"source"`
	IP                  netip.Addr        `json:"probe_ip"`
	Identity            string            `json:"normalized_identity"`
	Facts               *model.DeviceInfo `json:"last_successful_facts,omitempty"`
	PreviousFacts       *model.DeviceInfo `json:"previous_successful_facts,omitempty"`
	Kind                string            `json:"device_kind_hint"`
	Rule                string            `json:"classification_rule"`
	Profile             string            `json:"profile_name"`
	Status              string            `json:"probe_status"`
	FailureCode         string            `json:"failure_code,omitempty"`
	FailureReason       string            `json:"failure_reason,omitempty"`
	Conflict            bool              `json:"identity_conflict"`
	FirstSeen           time.Time         `json:"first_seen_at"`
	LastAttempt         time.Time         `json:"last_attempt_at"`
	LastSuccess         *time.Time        `json:"last_success_at,omitempty"`
	LastIdentitySuccess *time.Time        `json:"last_identity_success_at,omitempty"`
	LastScanID          *int64            `json:"last_scan_id,omitempty"`
	MatchedDeviceID     *int64            `json:"matched_device_id,omitempty"`
}
type Cursor struct {
	ScopeDigest string `json:"scope_digest"`
	Next        uint64 `json:"next_offset"`
	Covered     uint64 `json:"covered_hosts"`
	Cycles      uint64 `json:"completed_cycles"`
	KnownNext   uint64 `json:"known_offset"`
}
type Summary struct {
	FullRange       bool          `json:"full_range,omitempty"`
	RefreshInterval time.Duration `json:"refresh_interval_ns"`
	Termination     string        `json:"termination_reason,omitempty"`
	Enabled         bool          `json:"enabled"`
	RangeHosts      uint64        `json:"range_hosts"`
	Queued          int           `json:"probe_queued"`
	Completed       int           `json:"probe_completed"`
	Failed          int           `json:"probe_failed"`
	Identified      int           `json:"identified"`
	Deferred        uint64        `json:"deferred"`
	PoolAddresses   int           `json:"pool_addresses"`
	PoolIdentities  int           `json:"pool_identities"`
	PDUs            int           `json:"pdus"`
	Elapsed         time.Duration `json:"elapsed_ns"`
	Cursor          Cursor        `json:"cursor"`
}
