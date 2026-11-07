package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"gonet/internal/discovery"
	"gonet/internal/model"
	"gonet/internal/preprobe"
)

type probeQuery interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func loadProbes(ctx context.Context, q probeQuery) ([]preprobe.Record, preprobe.Summary, error) {
	pool := []preprobe.Record{}
	rows, err := q.Query(ctx, `SELECT record,last_scan_id,matched_device_id FROM snmp_probe_results ORDER BY probe_ip`)
	if err != nil {
		return nil, preprobe.Summary{}, err
	}
	for rows.Next() {
		var r preprobe.Record
		var raw []byte
		var scan, device *int64
		if err = rows.Scan(&raw, &scan, &device); err != nil {
			rows.Close()
			return nil, preprobe.Summary{}, err
		}
		if err = json.Unmarshal(raw, &r); err != nil {
			rows.Close()
			return nil, preprobe.Summary{}, err
		}
		r.LastScanID = scan
		r.MatchedDeviceID = device
		pool = append(pool, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, preprobe.Summary{}, err
	}
	var summary preprobe.Summary
	var raw []byte
	err = q.QueryRow(ctx, `SELECT summary FROM snmp_probe_progress WHERE singleton`).Scan(&raw)
	if err == pgx.ErrNoRows {
		return pool, summary, nil
	}
	if err != nil {
		return nil, summary, err
	}
	err = json.Unmarshal(raw, &summary)
	return pool, summary, err
}

func (s *Store) LoadProbeContext(ctx context.Context) ([]preprobe.Record, preprobe.Cursor, error) {
	if !s.locked {
		return nil, preprobe.Cursor{}, fmt.Errorf("probe context requires scan lock")
	}
	pool, summary, err := loadProbes(ctx, s.conn)
	return pool, summary.Cursor, err
}

func upsertProbes(ctx context.Context, tx pgx.Tx, scanID int64, ids map[model.DevRef]int64, r *discovery.Result) error {
	for _, p := range r.Preprobe.Records {
		p.LastScanID = &scanID
		if p.Conflict {
			p.MatchedDeviceID = nil
		}
		raw, err := json.Marshal(p)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO snmp_probe_results(probe_ip,record,last_scan_id,matched_device_id)
		VALUES($1::inet,$2::jsonb,$3,$4) ON CONFLICT(probe_ip) DO UPDATE SET
		record=EXCLUDED.record,last_scan_id=EXCLUDED.last_scan_id,
		matched_device_id=CASE WHEN (EXCLUDED.record->>'identity_conflict')::boolean THEN NULL ELSE COALESCE(EXCLUDED.matched_device_id,snmp_probe_results.matched_device_id) END
		WHERE (snmp_probe_results.record->>'last_attempt_at')::timestamptz <= (EXCLUDED.record->>'last_attempt_at')::timestamptz`, p.IP.String(), string(raw), scanID, p.MatchedDeviceID)
		if err != nil {
			return err
		}
	}
	// Only a directly verified full snapshot may associate a real database ID.
	for ip, ref := range r.Preprobe.MatchedRefs {
		id, ok := ids[ref]
		if !ok {
			return fmt.Errorf("probe association has no committed device")
		}
		_, err := tx.Exec(ctx, `UPDATE snmp_probe_results SET matched_device_id=$2 WHERE probe_ip=$1::inet AND NOT COALESCE((record->>'identity_conflict')::boolean,false)`, ip, id)
		if err != nil {
			return err
		}
	}
	if r.Preprobe.Summary.Enabled {
		summary, err := json.Marshal(r.Preprobe.Summary)
		if err != nil {
			return err
		}
		cursor, err := json.Marshal(r.Preprobe.Summary.Cursor)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO snmp_probe_progress(singleton,cursor,summary,last_scan_id) VALUES(true,$1::jsonb,$2::jsonb,$3)
		ON CONFLICT(singleton) DO UPDATE SET cursor=EXCLUDED.cursor,summary=EXCLUDED.summary,last_scan_id=EXCLUDED.last_scan_id,updated_at=now()`, string(cursor), string(summary), scanID)
		return err
	}
	return nil
}
