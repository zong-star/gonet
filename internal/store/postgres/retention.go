package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

type PrunedHistory struct {
	Scans        int64 `json:"scans"`
	Observations int64 `json:"observations"`
	ScanDevices  int64 `json:"scan_devices"`
}

// PruneHistory shares the scan/migration lock. Running scans are never victims.
func (s *Store) PruneHistory(ctx context.Context, keep int) (PrunedHistory, error) {
	if keep < 2 || keep > 100000 {
		return PrunedHistory{}, fmt.Errorf("invalid history retention limit")
	}
	if !s.locked {
		ok, err := TryLock(ctx, s.conn)
		if err != nil {
			return PrunedHistory{}, err
		}
		if !ok {
			return PrunedHistory{}, ErrLocked
		}
		defer Unlock(context.WithoutCancel(ctx), s.conn)
	}
	tx, err := s.conn.Begin(ctx)
	if err != nil {
		return PrunedHistory{}, err
	}
	defer tx.Rollback(ctx)
	out, err := pruneHistory(ctx, tx, keep)
	if err != nil {
		return out, err
	}
	return out, tx.Commit(ctx)
}

func pruneHistory(ctx context.Context, tx pgx.Tx, keep int) (PrunedHistory, error) {
	if keep == 0 {
		keep = 500
	}
	var out PrunedHistory
	// Pin the latest usable topology inside the limit, so repeated failures do
	// not remove the last available graph or its unresolved-neighbor evidence.
	rows, err := tx.Query(ctx, `SELECT id FROM scan_runs WHERE status <> 'running'
		ORDER BY (id = COALESCE((SELECT max(id) FROM scan_runs WHERE status IN ('completed','partial')),0)) DESC, id DESC OFFSET $1`, keep)
	if err != nil {
		return out, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return out, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(ids) == 0 {
		return out, err
	}
	ct, err := tx.Exec(ctx, `DELETE FROM observations WHERE scan_id=ANY($1::bigint[])`, ids)
	if err != nil {
		return out, err
	}
	out.Observations = ct.RowsAffected()
	ct, err = tx.Exec(ctx, `DELETE FROM scan_devices WHERE scan_id=ANY($1::bigint[])`, ids)
	if err != nil {
		return out, err
	}
	out.ScanDevices = ct.RowsAffected()
	ct, err = tx.Exec(ctx, `DELETE FROM scan_runs WHERE id=ANY($1::bigint[]) AND status <> 'running'`, ids)
	if err != nil {
		return out, err
	}
	out.Scans = ct.RowsAffected()
	return out, nil
}
