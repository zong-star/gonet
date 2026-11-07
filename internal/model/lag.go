package model

import "time"

// AggregationGroup is a query-derived group. Inferred groups never acquire a
// synthetic interface index and are never persisted as collected membership.
type AggregationGroup struct {
	AggregationSource   string     `json:"aggregation_source"`
	LocalDeviceID       int64      `json:"local_device_id,string"`
	RemoteDeviceID      *int64     `json:"remote_device_id,string,omitempty"`
	RemoteAggregationID *string    `json:"remote_aggregation_id,omitempty"`
	MemberInterfaces    []int32    `json:"member_interfaces"`
	EvidenceLinkIDs     []int64    `json:"evidence_link_ids"`
	InferenceStatus     string     `json:"inference_status"`
	InferredAt          *time.Time `json:"inferred_at"`

	GroupID          string                `json:"group_id"`
	DeviceID         int64                 `json:"device_id,string"`
	AggregateIfIndex *int32                `json:"aggregate_if_index"`
	InterfaceName    *string               `json:"interface_name"`
	DisplayName      string                `json:"display_name"`
	EvidenceType     string                `json:"evidence_type"`
	Mode             string                `json:"mode"`
	Sources          []string              `json:"sources"`
	InferredFrom     *AggregationInference `json:"inferred_from,omitempty"`
}

type AggregationInference struct {
	DeviceID int64  `json:"device_id,string"`
	GroupID  string `json:"group_id"`
	ScanID   int64  `json:"scan_id,string"`
}

// Interface indices remain device-local and scan-local. SourceGroupID and
// advertised AggregateID are opaque identifiers, never substitute ifIndex.
type LAGGroup struct {
	SourceGroupID    string `json:"source_group_id"`
	AggregateIfIndex *int32 `json:"aggregate_if_index"`
	Source           string `json:"source"`
	Mode             string `json:"mode"`
	Complete         bool   `json:"complete"`
}

type LAGFact struct {
	OID   string `json:"oid"`
	Type  string `json:"type"`
	Value any    `json:"value"`
}

type LAGEvidence struct {
	Source      string          `json:"source"`
	AdapterID   string          `json:"adapter_id,omitempty"`
	Root        string          `json:"root"`
	CollectedAt time.Time       `json:"collected_at"`
	Status      ComponentStatus `json:"status"`
	Facts       []LAGFact       `json:"facts"`
}

type LAGAdvertisement struct {
	Direction     string        `json:"direction"`
	Index         NeighborIndex `json:"index"`
	MemberIfIndex *int32        `json:"member_if_index"`
	AggregateID   uint32        `json:"aggregate_id"`
	Capable       bool          `json:"capable"`
	Enabled       bool          `json:"enabled"`
	RawStatus     []byte        `json:"raw_status"`
}

type LACPPort struct {
	SelectedAggID *uint32 `json:"selected_agg_id,omitempty"`
	Stable        bool    `json:"stable"`
	MemberIfIndex int32   `json:"member_if_index"`
	ActorKey      *uint32 `json:"actor_key,omitempty"`
	PartnerKey    *uint32 `json:"partner_key,omitempty"`
	ActorPort     *uint32 `json:"actor_port,omitempty"`
	PartnerPort   *uint32 `json:"partner_port,omitempty"`
	ActorSystem   []byte  `json:"actor_system,omitempty"`
	PartnerSystem []byte  `json:"partner_system,omitempty"`
	ActorState    []byte  `json:"actor_state,omitempty"`
	PartnerState  []byte  `json:"partner_state,omitempty"`
}
