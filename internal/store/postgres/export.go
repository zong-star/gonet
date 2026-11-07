package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gonet/internal/model"
	"gonet/internal/preprobe"
	"gonet/internal/topology"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// TopologyExport is the stable JSON document produced by `gonet topology export`.
type TopologyExport struct {
	ProbePool            []preprobe.Record      `json:"probe_pool"`
	ProbeSummary         preprobe.Summary       `json:"probe_summary"`
	PendingNodes         []topology.PendingNode `json:"pending_nodes"`
	PendingLinks         []topology.PendingLink `json:"pending_links"`
	SchemaVersion        int                    `json:"schema_version"`
	GeneratedAt          time.Time              `json:"generated_at"`
	State                string                 `json:"state"`
	LatestScanID         int64                  `json:"latest_scan_id"`
	LatestScanStatus     string                 `json:"latest_scan_status"`
	LatestScanFinishedAt *time.Time             `json:"latest_scan_finished_at,omitempty"`
	Fresh                bool                   `json:"fresh"`
	CoverageGap          bool                   `json:"coverage_gap"`
	Devices              []ExportDevice         `json:"devices"`
	Links                []ExportLink           `json:"links"`
	Evidence             *TopologyEvidence      `json:"-"`
}

// ExportDevice is one formal device in the export.
type ExportDevice struct {
	InterfaceCollectionState string            `json:"-"`
	InterfaceAttemptedAt     *time.Time        `json:"-"`
	InterfaceStatusError     string            `json:"-"`
	Interfaces               []model.Interface `json:"-"`
	DiscoveryDepth           *int              `json:"discovery_depth,omitempty"`
	Chassis                  model.TypedID     `json:"chassis"`
	IdentityKeys             []string          `json:"identity_keys"`
	AccessAddresses          []string          `json:"access_addresses"`
	ID                       int64             `json:"id"`
	IdentityState            string            `json:"identity_state"`
	ClassificationRule       string            `json:"classification_rule"`
	Kind                     string            `json:"device_kind"`
	SysName                  string            `json:"sys_name"`
	SysObjectID              string            `json:"sys_object_id"`
	LastSeenAt               time.Time         `json:"last_seen_at"`
}

// ExportLink is one formal link with its lifecycle and coverage fields.
type ExportLink struct {
	model.LinkInterfaceStatus
	SourceInterfaceStatus model.InterfaceStatus `json:"-"`
	TargetInterfaceStatus model.InterfaceStatus `json:"-"`
	PortAKey              string                `json:"port_a_key"`
	PortBKey              string                `json:"port_b_key"`
	ID                    int64                 `json:"id"`
	DeviceAID             int64                 `json:"device_a_id"`
	DeviceAName           string                `json:"device_a_name"`
	PortAID               int64                 `json:"port_a_id"`
	PortAName             string                `json:"port_a_name"`
	DeviceBID             int64                 `json:"device_b_id"`
	DeviceBName           string                `json:"device_b_name"`
	PortBID               int64                 `json:"port_b_id"`
	PortBName             string                `json:"port_b_name"`
	Confidence            string                `json:"confidence"`
	DiscoveryState        string                `json:"discovery_state"`
	MissedCompleteScans   int                   `json:"missed_complete_scans"`
	FirstSeenAt           time.Time             `json:"first_seen_at"`
	LastSeenAt            time.Time             `json:"last_seen_at"`
	LastSeenScanID        *int64                `json:"last_seen_scan_id"`
	Fresh                 bool                  `json:"fresh"`
	CoverageGap           bool                  `json:"coverage_gap"`
}

// ExportTopology reads the topology in one read-only consistent transaction.
// state is "active" (default) or "all" (includes suspect_stale and stale).
// Output ordering is stable (device/port ids).
func ExportTopology(ctx context.Context, conn *pgx.Conn, state string) (*TopologyExport, error) {
	return exportTopology(ctx, conn, state, false)
}

func ExportTopologyWithEvidence(ctx context.Context, conn *pgx.Conn, state string) (*TopologyExport, error) {
	return exportTopology(ctx, conn, state, true)
}

func exportTopology(ctx context.Context, conn *pgx.Conn, state string, withEvidence bool) (*TopologyExport, error) {
	if state != "active" && state != "all" {
		return nil, fmt.Errorf("state must be 'active' or 'all', got %q", state)
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var latestID int64
	var latestStatus string
	var latestFinished *time.Time
	err = tx.QueryRow(ctx, `SELECT id, status, finished_at FROM scan_runs
		WHERE status IN ('completed','partial') AND finished_at IS NOT NULL
		ORDER BY id DESC LIMIT 1`).Scan(&latestID, &latestStatus, &latestFinished)
	if errors.Is(err, pgx.ErrNoRows) {
		latestID, latestStatus = 0, ""
	} else if err != nil {
		return nil, err
	}

	devices := make([]ExportDevice, 0)
	rows, err := tx.Query(ctx, `SELECT d.id, d.identity_state, d.classification_rule,
		coalesce(d.sys_name,''), coalesce(d.sys_object_id,''), d.last_seen_at,
		COALESCE(i.subtype,0),i.raw_value,CASE WHEN sd.outcome IN ('success','partial') THEN sd.depth END,d.device_kind
		FROM devices d LEFT JOIN LATERAL (SELECT subtype,raw_value FROM device_identities WHERE device_id=d.id ORDER BY first_seen_at,identity_key LIMIT 1) i ON true
		LEFT JOIN scan_devices sd ON sd.device_id=d.id AND sd.scan_id=$1 ORDER BY d.id`, latestID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d ExportDevice
		if err := rows.Scan(&d.ID, &d.IdentityState, &d.ClassificationRule, &d.SysName, &d.SysObjectID, &d.LastSeenAt, &d.Chassis.Subtype, &d.Chassis.Raw, &d.DiscoveryDepth, &d.Kind); err != nil {
			rows.Close()
			return nil, err
		}
		devices = append(devices, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	query := `SELECT l.id, l.device_a_id, coalesce(da.sys_name,''), l.port_a_id, pa.display_name,
		l.device_b_id, coalesce(db.sys_name,''), l.port_b_id, pb.display_name,
		l.confidence, l.discovery_state, l.missed_complete_scans,
		l.first_seen_at, l.last_seen_at, l.last_seen_scan_id, pa.port_key, pb.port_key
		FROM links l
		JOIN devices da ON da.id = l.device_a_id
		JOIN ports pa ON pa.id = l.port_a_id
		JOIN devices db ON db.id = l.device_b_id
		JOIN ports pb ON pb.id = l.port_b_id`
	if state == "active" {
		query += ` WHERE l.discovery_state = 'active'`
	}
	query += ` ORDER BY l.device_a_id, l.port_a_id, l.device_b_id, l.port_b_id`

	links := make([]ExportLink, 0)
	lrows, err := tx.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	for lrows.Next() {
		var l ExportLink
		if err := lrows.Scan(&l.ID, &l.DeviceAID, &l.DeviceAName, &l.PortAID, &l.PortAName,
			&l.DeviceBID, &l.DeviceBName, &l.PortBID, &l.PortBName,
			&l.Confidence, &l.DiscoveryState, &l.MissedCompleteScans,
			&l.FirstSeenAt, &l.LastSeenAt, &l.LastSeenScanID, &l.PortAKey, &l.PortBKey); err != nil {
			lrows.Close()
			return nil, err
		}
		l.Fresh = latestID != 0 && l.LastSeenScanID != nil && *l.LastSeenScanID == latestID
		l.CoverageGap = !l.Fresh
		links = append(links, l)
	}
	lrows.Close()
	if err := lrows.Err(); err != nil {
		return nil, err
	}

	coverageGap := latestID == 0
	for _, l := range links {
		if l.CoverageGap {
			coverageGap = true
			break
		}
	}
	known := map[string]uint64{}
	byID := map[uint64]*ExportDevice{}
	for i := range devices {
		devices[i].IdentityKeys = []string{}
		devices[i].AccessAddresses = []string{}
		byID[uint64(devices[i].ID)] = &devices[i]
	}
	keyRows, err := tx.Query(ctx, `SELECT identity_key,device_id FROM device_identities ORDER BY identity_key`)
	if err != nil {
		return nil, err
	}
	for keyRows.Next() {
		var key string
		var id uint64
		if err := keyRows.Scan(&key, &id); err != nil {
			keyRows.Close()
			return nil, err
		}
		known[key] = id
		if d := byID[id]; d != nil {
			d.IdentityKeys = append(d.IdentityKeys, key)
		}
	}
	err = keyRows.Err()
	keyRows.Close()
	if err != nil {
		return nil, err
	}
	ar, err := tx.Query(ctx, `SELECT device_id,host(address) FROM device_addresses WHERE state='verified' ORDER BY device_id,address`)
	if err != nil {
		return nil, err
	}
	for ar.Next() {
		var id uint64
		var addr string
		if err := ar.Scan(&id, &addr); err != nil {
			ar.Close()
			return nil, err
		}
		if d := byID[id]; d != nil {
			d.AccessAddresses = append(d.AccessAddresses, addr)
		}
	}
	err = ar.Err()
	ar.Close()
	if err != nil {
		return nil, err
	}
	var pending []topology.UnresolvedObservation
	pr, err := tx.Query(ctx, `SELECT id,COALESCE(observer_device_id,0),raw_neighbor,collected_at,reason_codes,resolution
		FROM observations WHERE scan_id=$1 AND resolution IN ('unresolved','conflict') ORDER BY observer_device_id,local_port_num,remote_index,id`, latestID)
	if err != nil {
		return nil, err
	}
	for pr.Next() {
		var u topology.UnresolvedObservation
		var raw, reasons []byte
		var resolution string
		if err := pr.Scan(&u.ObservationID, &u.Observer, &raw, &u.At, &reasons, &resolution); err != nil {
			pr.Close()
			return nil, err
		}
		if err := json.Unmarshal(raw, &u.Raw); err != nil {
			pr.Close()
			return nil, err
		}
		u.Row = u.Raw.Index
		var codes []string
		if err := json.Unmarshal(reasons, &codes); err != nil {
			pr.Close()
			return nil, err
		}
		u.Reason = strings.Join(codes, "; ")
		u.ReasonCodes, u.Conflict = codes, resolution == "conflict"
		pending = append(pending, u)
	}
	err = pr.Err()
	pr.Close()
	if err != nil {
		return nil, err
	}
	pendingNodes, pendingLinks := topology.PendingProjection(pending, known)
	if err := enrichPending(ctx, tx, pendingNodes); err != nil {
		return nil, err
	}
	if len(pendingLinks) > 0 {
		coverageGap = true
	}

	probePool, probeSummary, err := loadProbes(ctx, tx)
	if err != nil {
		return nil, err
	}
	var evidence *TopologyEvidence
	if withEvidence {
		evidence, err = loadTopologyEvidence(ctx, tx, latestID, state)
		if err != nil {
			return nil, err
		}
	}
	if err := loadInterfaceStatus(ctx, tx, devices, links); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &TopologyExport{
		ProbePool: probePool, ProbeSummary: probeSummary,
		PendingNodes: pendingNodes, PendingLinks: pendingLinks,
		SchemaVersion:        1,
		GeneratedAt:          time.Now().UTC(),
		State:                state,
		LatestScanID:         latestID,
		LatestScanStatus:     latestStatus,
		LatestScanFinishedAt: latestFinished,
		Fresh:                latestID != 0,
		CoverageGap:          coverageGap,
		Devices:              devices,
		Links:                links,
		Evidence:             evidence,
	}, nil
}
