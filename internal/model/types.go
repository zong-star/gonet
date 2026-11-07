// Package model holds the core domain types shared across collector, identity,
// topology and storage layers. M1 only produces a single-device DeviceSnapshot;
// the discovery/storage types are declared here as the starting contract so all
// packages share one definition of raw bytes and completeness fields.
package model

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"time"
)

// SchemaVersion is the fixed JSON schema version emitted by the M1 snapshot.
const SchemaVersion = 1

// DevRef and PortRef are temporary in-memory identifiers. They are never used
// as database primary keys (M4 introduces ref_to_id mapping).
type DevRef uint64
type PortRef uint64

// TypedID preserves a raw identifier together with its LLDP subtype. Raw bytes
// are the identity source of truth; JSON encodes them as base64 and also emits
// a hex form for human review.
type TypedID struct {
	Subtype uint8
	Raw     []byte
}

// MarshalJSON emits subtype, base64 raw bytes and a raw_hex convenience field.
// Raw is never reused after return: callers must copy it into the snapshot.
func (t TypedID) MarshalJSON() ([]byte, error) {
	type wire struct {
		Subtype uint8  `json:"subtype"`
		Raw     []byte `json:"raw"`
		RawHex  string `json:"raw_hex"`
	}
	return json.Marshal(wire{Subtype: t.Subtype, Raw: t.Raw, RawHex: hex.EncodeToString(t.Raw)})
}

// Issue is a structured, non-fatal diagnostic attached to a component or the
// whole snapshot. Retryable only applies to transport-level failures.
type Issue struct {
	Code      string `json:"code"`
	Component string `json:"component"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}

// VerificationDetails describes the latest attempt, including failures which
// remain retryable in a later run. It contains no SNMP credentials.
type VerificationDetails struct {
	Status        string     `json:"verification_status"`
	SelectedIP    string     `json:"selected_snmp_ip,omitempty"`
	FailureCode   string     `json:"failure_code,omitempty"`
	FailureReason string     `json:"failure_reason,omitempty"`
	LastAttemptAt *time.Time `json:"last_verification_at,omitempty"`
}

// ComponentStatus records supportability, walk completion and decode completion
// for one MIB component, plus any issues encountered.
type ComponentStatus struct {
	State          string  `json:"state,omitempty"`
	Requests       int     `json:"requests,omitempty"`
	VarbindCount   int     `json:"varbind_count,omitempty"`
	ElapsedMS      int64   `json:"elapsed_ms,omitempty"`
	Skipped        bool    `json:"skipped,omitempty"`
	Supported      bool    `json:"supported"`
	WalkComplete   bool    `json:"walk_complete"`
	DecodeComplete bool    `json:"decode_complete"`
	Issues         []Issue `json:"issues"`
}

// Interface is a row of IF-MIB (ifIndex/ifDescr/ifType/ifPhysAddress) joined
// with IF-MIB ifName/ifAlias where present.
type Interface struct {
	InterfaceStatus
	IfIndex        int32  `json:"if_index"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	Alias          string `json:"alias"`
	AliasCollected bool   `json:"alias_collected,omitempty"`
	Type           int32  `json:"type"`
	PhysAddress    []byte `json:"phys_address"`
	PhysAddressHex string `json:"phys_address_hex"`
}

// LAGMember is device-local evidence within a single snapshot.
type LAGMember struct {
	Configured       *bool    `json:"configured,omitempty"`
	Selected         *bool    `json:"selected,omitempty"`
	Attached         *bool    `json:"attached,omitempty"`
	Sources          []string `json:"sources,omitempty"`
	AggregateIfIndex int32    `json:"aggregate_if_index"`
	MemberIfIndex    int32    `json:"member_if_index"`
	Source           string   `json:"source"`
	Mode             string   `json:"mode"`
	Status           string   `json:"status"`
}

// LocalPort is one lldpLocPortTable row. Number is the LLDP local port number
// (locPortNum) and is NOT an ifIndex. IfIndex is filled only when the port ID
// can be unambiguously associated with an interface.
type LocalPort struct {
	Number      uint32  `json:"number"`
	ID          TypedID `json:"id"`
	Description string  `json:"description"`
	IfIndex     *int32  `json:"if_index"`
	Physical    bool    `json:"physical"`
	MappingRule string  `json:"mapping_rule"`
}

// NeighborIndex is the full LLDP remote row index (timeMark, localPortNum,
// remIndex). timeMark is never treated as a permanent neighbor ID.
type NeighborIndex struct {
	TimeMark     uint32 `json:"time_mark"`
	LocalPortNum uint32 `json:"local_port_num"`
	RemoteIndex  uint32 `json:"remote_index"`
}

// LLDPNeighbor is one assembled lldpRemTable row plus its management addresses.
type LLDPNeighbor struct {
	OriginalPort    *TypedID      `json:"original_port,omitempty"`
	EncodingAdapter string        `json:"encoding_adapter,omitempty"`
	Index           NeighborIndex `json:"index"`
	Chassis         TypedID       `json:"chassis"`
	Port            TypedID       `json:"port"`
	PortDescription string        `json:"port_description"`
	SysName         string        `json:"sys_name"`
	SysDescription  string        `json:"sys_description"`
	MgmtAddresses   []netip.Addr  `json:"mgmt_addresses"`
	CapSupported    []byte        `json:"cap_supported"`
	CapEnabled      []byte        `json:"cap_enabled"`
	CapNames        []string      `json:"cap_enabled_names"`
	Issues          []Issue       `json:"issues"`
}

// DeviceInfo is the identity/classification-relevant view of the collected
// device. Uptime and LLDP lastChange are captured before and after for
// snapshot stability.
type DeviceInfo struct {
	Target            netip.Addr `json:"target"`
	Chassis           TypedID    `json:"chassis"`
	SysName           string     `json:"sys_name"`
	SysDescription    string     `json:"sys_description"`
	SysObjectID       string     `json:"sys_object_id"`
	UptimeBefore      uint32     `json:"uptime_before"`
	UptimeAfter       uint32     `json:"uptime_after"`
	LastChangeBefore  uint32     `json:"lldp_last_change_before"`
	LastChangeAfter   uint32     `json:"lldp_last_change_after"`
	CapSupported      []byte     `json:"cap_supported"`
	CapEnabled        []byte     `json:"cap_enabled"`
	CapSupportedNames []string   `json:"cap_supported_names"`
	CapEnabledNames   []string   `json:"cap_enabled_names"`
}

// DeviceSnapshot is the immutable, single-device fact snapshot produced by the
// collector. It is transport-independent and JSON-serializable.
type DeviceSnapshot struct {
	LAGGroups          []LAGGroup                 `json:"lag_groups,omitempty"`
	LAGEvidence        []LAGEvidence              `json:"lag_evidence,omitempty"`
	LAGAdvertisements  []LAGAdvertisement         `json:"lag_advertisements,omitempty"`
	LACPPorts          []LACPPort                 `json:"lacp_ports,omitempty"`
	RequestPDUs        int                        `json:"request_pdus"`
	SchemaVersion      int                        `json:"schema_version"`
	Device             DeviceInfo                 `json:"device"`
	Interfaces         []Interface                `json:"interfaces"`
	LAGMembers         []LAGMember                `json:"lag_members,omitempty"`
	LocalPorts         []LocalPort                `json:"local_ports"`
	Neighbors          []LLDPNeighbor             `json:"neighbors"`
	Components         map[string]ComponentStatus `json:"components"`
	CollectionComplete bool                       `json:"collection_complete"`
	SnapshotStable     bool                       `json:"snapshot_stable"`
	AbsenceEligible    bool                       `json:"absence_eligible"`
	StartedAt          time.Time                  `json:"started_at"`
	CollectedAt        time.Time                  `json:"collected_at"`
	Issues             []Issue                    `json:"issues"`
}

// DiscoveryTarget names a device to collect and the identity expectation used
// when closing recursion (M2+). M1 always uses an empty ExpectedIdentity.
type DiscoveryTarget struct {
	Address          netip.Addr `json:"address"`
	Depth            int        `json:"depth"`
	ExpectedIdentity string     `json:"expected_identity,omitempty"`
	CandidateRef     DevRef     `json:"candidate_ref,omitempty"`
	Profile          string     `json:"profile,omitempty"`
}

// ScanOutcome pairs a target with its (possibly partial) snapshot.
type ScanOutcome struct {
	Outcome  string          `json:"outcome,omitempty"`
	Device   DevRef          `json:"device"`
	Target   DiscoveryTarget `json:"target"`
	Snapshot *DeviceSnapshot `json:"snapshot,omitempty"`
	Issues   []Issue         `json:"issues"`
}

// LinkObservation is one directed LLDP edge observation.
type LinkObservation struct {
	Observer   DevRef        `json:"observer"`
	Remote     DevRef        `json:"remote"`
	LocalPort  PortRef       `json:"local_port"`
	RemotePort PortRef       `json:"remote_port"`
	Row        NeighborIndex `json:"row"`
	At         time.Time     `json:"at"`
	Raw        LLDPNeighbor  `json:"raw"`
}

// LinkKey is the canonical four-tuple link key (device, port, device, port).
type LinkKey struct {
	A  DevRef  `json:"device_a"`
	PA PortRef `json:"port_a"`
	B  DevRef  `json:"device_b"`
	PB PortRef `json:"port_b"`
}

// LinkEvidence aggregates observed directions for one link key in one round.
type LinkEvidence struct {
	Key       LinkKey   `json:"key"`
	SeenFromA bool      `json:"seen_from_a"`
	SeenFromB bool      `json:"seen_from_b"`
	FirstAt   time.Time `json:"first_at"`
	LastAt    time.Time `json:"last_at"`
}

// Confidence reports bidirectional only when both directions were observed in
// the same round; otherwise single_sided. It never stitches rounds.
func (e LinkEvidence) Confidence() string {
	if e.SeenFromA && e.SeenFromB {
		return "bidirectional"
	}
	return "single_sided"
}

// ScanResult is the immutable result of one discovery round (M3+).
type ScanResult struct {
	SchemaVersion int
	Status        string
	Outcomes      []ScanOutcome
	Observations  []LinkObservation
	Links         []LinkEvidence
	Issues        []Issue
}

// Collector gathers one device snapshot. A non-nil snapshot with a non-nil
// error is a partial result and must not be discarded.
type Collector interface {
	Collect(context.Context, DiscoveryTarget) (*DeviceSnapshot, error)
}

// Repository persists a finished round atomically (M4+). scanID refers to an
// already-committed running scan_runs row.
type Repository interface {
	CommitResult(context.Context, int64, *ScanResult) error
}
