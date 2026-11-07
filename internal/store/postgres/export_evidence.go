package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"gonet/internal/model"
)

type ObservationRef struct {
	ID, ObserverID int64
}

type LinkEndpointEvidence struct {
	IfIndex *int32
	Name    *string // Legacy display fallback, including ifDescr.
	IfName  *string
	IfAlias *string
	// Set only by evidence that validates the LLDP subtype, model, and endpoint.
	LLDPInterfaceName *string
}

type PhysicalLinkEvidence struct {
	Advertisements []LAGAdvertisementEvidence
	LACPA, LACPB   *model.LACPPort
	A, B           LinkEndpointEvidence
	Observations   []ObservationRef
}

type LAGAdvertisementEvidence struct {
	ObserverID    int64                  `json:"observer_device_id,string"`
	Advertisement model.LAGAdvertisement `json:"advertisement"`
}

type LAGMemberEvidence struct {
	model.LAGMember
	AggregateName string
	Endpoint      LinkEndpointEvidence
}

type DeviceLAGEvidence struct {
	Groups         []model.LAGGroup
	Sources        []model.LAGEvidence
	Advertisements []model.LAGAdvertisement
	LACPPorts      []model.LACPPort
	Complete       bool
	Members        []LAGMemberEvidence
}

type TopologyEvidence struct {
	Collection     *ScanCollection
	Links          map[int64]PhysicalLinkEvidence
	LAG            map[int64]DeviceLAGEvidence
	LatestScan     *ScanState
	DeviceCoverage map[int64]DeviceScanCoverage
}

type ScanState struct {
	ID         int64      `json:"scan_id"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
}

type DeviceScanCoverage struct {
	Outcome            string
	AbsenceEligible    bool
	CollectionComplete bool
	SnapshotStable     bool
	TargetIP           string
	CollectedAt        *time.Time
	Components         map[string]model.ComponentStatus
	Issues             []model.Issue
}

// ScanCollection belongs to the committed snapshot, not the latest running scan.
type ScanCollection struct {
	Counts             map[string]int     `json:"counts"`
	Issues             []model.Issue      `json:"-"`
	TerminationReasons []string           `json:"termination_reasons"`
	ViewVerified       bool               `json:"view_verified"`
	Targets            []CollectionTarget `json:"targets"`
}

type CollectionTarget struct {
	DeviceID   int64  `json:"device_id,omitempty"`
	Address    string `json:"address"`
	Status     string `json:"status"`
	ReasonCode string `json:"reason_code"`
}

func loadTopologyEvidence(ctx context.Context, tx pgx.Tx, scanID int64, state string) (*TopologyEvidence, error) {
	out := &TopologyEvidence{Links: map[int64]PhysicalLinkEvidence{}, LAG: map[int64]DeviceLAGEvidence{}}
	latest := &ScanState{}
	err := tx.QueryRow(ctx, `SELECT id, status, started_at, finished_at FROM scan_runs ORDER BY id DESC LIMIT 1`).Scan(&latest.ID, &latest.Status, &latest.StartedAt, &latest.FinishedAt)
	if err == nil {
		out.LatestScan = latest
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if scanID != 0 {
		var summary, issues, termination []byte
		collection := &ScanCollection{}
		if err := tx.QueryRow(ctx, `SELECT summary,error_summary,termination_reasons,
			coalesce((config_summary->>'view_verified')::boolean,false)
			FROM scan_runs WHERE id=$1`, scanID).Scan(&summary, &issues, &termination, &collection.ViewVerified); err != nil {
			return nil, err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(summary, &fields); err != nil {
			return nil, err
		}
		collection.Counts = map[string]int{}
		for k, v := range fields {
			var n int
			if json.Unmarshal(v, &n) == nil {
				collection.Counts[k] = n
			}
		}
		if raw := fields["collection_targets"]; raw != nil {
			if err := json.Unmarshal(raw, &collection.Targets); err != nil {
				return nil, err
			}
		}
		if err := json.Unmarshal(issues, &collection.Issues); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(termination, &collection.TerminationReasons); err != nil {
			return nil, err
		}
		out.Collection = collection
	}
	rows, err := tx.Query(ctx, `SELECT l.id, ia.if_index, coalesce(nullif(ia.if_name,''),nullif(ia.if_descr,'')),
		nullif(ia.if_name,''), CASE WHEN ia.if_alias_collected THEN ia.if_alias ELSE nullif(ia.if_alias,'') END,
		ib.if_index, coalesce(nullif(ib.if_name,''),nullif(ib.if_descr,'')),
		nullif(ib.if_name,''), CASE WHEN ib.if_alias_collected THEN ib.if_alias ELSE nullif(ib.if_alias,'') END,
		o.id, o.observer_device_id
		FROM links l
		LEFT JOIN scan_interface_facts ia ON (ia.scan_id,ia.device_id,ia.port_id)=(l.last_seen_scan_id,l.device_a_id,l.port_a_id)
		LEFT JOIN scan_interface_facts ib ON (ib.scan_id,ib.device_id,ib.port_id)=(l.last_seen_scan_id,l.device_b_id,l.port_b_id)
		LEFT JOIN LATERAL (
			SELECT DISTINCT ON (observer_device_id) id, observer_device_id FROM observations
			WHERE link_id=l.id AND scan_id=l.last_seen_scan_id AND observer_device_id IN (l.device_a_id,l.device_b_id)
			ORDER BY observer_device_id, id DESC
		) o ON true WHERE $1 <> 'active' OR l.discovery_state='active'`, state)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var linkID int64
		var item PhysicalLinkEvidence
		var observationID, observerID *int64
		if err := rows.Scan(&linkID, &item.A.IfIndex, &item.A.Name, &item.A.IfName, &item.A.IfAlias,
			&item.B.IfIndex, &item.B.Name, &item.B.IfName, &item.B.IfAlias, &observationID, &observerID); err != nil {
			rows.Close()
			return nil, err
		}
		if observationID != nil && observerID != nil {
			item.Observations = append(out.Links[linkID].Observations, ObservationRef{*observationID, *observerID})
		}
		out.Links[linkID] = item
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = tx.Query(ctx, `SELECT device_id, outcome, absence_eligible, collection_complete,
		snapshot_stable,coalesce(host(target_ip),''),collected_at,reasons,component_status
		FROM scan_devices WHERE scan_id=$1`, scanID)
	if err != nil {
		return nil, err
	}
	out.DeviceCoverage = make(map[int64]DeviceScanCoverage)
	for rows.Next() {
		var deviceID int64
		var coverage DeviceScanCoverage
		var raw, reasons []byte
		if err := rows.Scan(&deviceID, &coverage.Outcome, &coverage.AbsenceEligible, &coverage.CollectionComplete,
			&coverage.SnapshotStable, &coverage.TargetIP, &coverage.CollectedAt, &reasons, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(raw, &coverage.Components); err != nil {
			rows.Close()
			return nil, err
		}
		if err := json.Unmarshal(reasons, &coverage.Issues); err != nil {
			rows.Close()
			return nil, err
		}
		out.DeviceCoverage[deviceID] = coverage
		status := coverage.Components["lag_membership"]
		out.LAG[deviceID] = DeviceLAGEvidence{Complete: status.Supported && status.WalkComplete && status.DecodeComplete}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `SELECT m.device_id, m.aggregate_if_index, m.member_if_index, m.source, m.mode, m.status,
		coalesce(nullif(a.if_name,''),a.if_descr), nullif(a.if_name,''),
		CASE WHEN a.if_alias_collected THEN a.if_alias ELSE nullif(a.if_alias,'') END
		FROM scan_lag_members m
		JOIN scan_interface_facts a ON (a.scan_id,a.device_id,a.if_index)=(m.scan_id,m.device_id,m.aggregate_if_index)
		WHERE m.scan_id=$1 ORDER BY m.device_id,m.member_if_index,m.aggregate_if_index`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var deviceID int64
		var member LAGMemberEvidence
		if err := rows.Scan(&deviceID, &member.AggregateIfIndex, &member.MemberIfIndex, &member.Source,
			&member.Mode, &member.Status, &member.AggregateName, &member.Endpoint.IfName, &member.Endpoint.IfAlias); err != nil {
			return nil, err
		}
		member.Endpoint.IfIndex = &member.AggregateIfIndex
		item := out.LAG[deviceID]
		item.Members = append(item.Members, member)
		out.LAG[deviceID] = item
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if err := loadVendorLAG(ctx, tx, scanID, out); err != nil {
		return nil, err
	}
	normalizeLegacyLAGModes(out)
	return out, nil
}

func normalizeLegacyLAGModes(out *TopologyEvidence) {
	// Previous collectors equated LACP_DISABLED with configured static mode.
	// Keep the stored historical fact intact, but do not expose that heuristic
	// as verified configuration without an explicit vendor mode source.
	for id, facts := range out.LAG {
		for i := range facts.Members {
			m := &facts.Members[i]
			if m.Mode == "static" && m.Source != "h3c_private" && !slices.Contains(m.Sources, "h3c_private") {
				m.Mode = "unknown"
			}
		}
		out.LAG[id] = facts
	}
}
