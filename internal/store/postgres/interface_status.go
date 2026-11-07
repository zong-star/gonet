package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"gonet/internal/model"
	"slices"
	"strings"
	"time"
)

// SaveInterfaceStatus updates only the current operational cache, under
// a row lock. No discovery, asset, port, or link lifecycle is changed.
func SaveInterfaceStatus(ctx context.Context, conn *pgx.Conn, id int64, interfaces []model.Interface, attempt time.Time, collectionErr error) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var raw []byte
	var previousAttempt *time.Time
	if err = tx.QueryRow(ctx, `SELECT interface_status,status_attempted_at FROM devices WHERE id=$1 FOR UPDATE`, id).Scan(&raw, &previousAttempt); err != nil {
		return err
	}
	if previousAttempt != nil && previousAttempt.After(attempt) {
		return tx.Commit(ctx)
	}
	var old []model.Interface
	if err = json.Unmarshal(raw, &old); err != nil {
		return err
	}
	state, msg := "success", ""
	if collectionErr != nil {
		state = "failed"
		msg = "SNMP_ERROR"
		for _, code := range []string{"SNMP_TIMEOUT", "SNMP_AUTH", "WALK_LIMIT", "WALK_NONINCREASING", "MIB_UNSUPPORTED", "CANCELED"} {
			if strings.Contains(collectionErr.Error(), code) {
				msg = code
				break
			}
		}
		if errors.Is(collectionErr, context.DeadlineExceeded) {
			msg = "SNMP_TIMEOUT"
		}
		interfaces = old
	} else {
		// Missing rows retain the last success as unavailable; they cannot stay UP.
		names := map[string]int{}
		for _, i := range interfaces {
			names[interfaceKey(i)]++
		}
		for _, i := range old {
			if names[interfaceKey(i)] == 0 {
				i.StatusCollectionState = "missing"
				interfaces = append(interfaces, i)
			}
		}
	}
	for i := range interfaces {
		interfaces[i].StatusAttemptedAt = &attempt
		if collectionErr != nil {
			interfaces[i].StatusCollectionState = "failed"
			interfaces[i].StatusError = msg
		}
	}
	slices.SortFunc(interfaces, func(a, b model.Interface) int { return int(a.IfIndex - b.IfIndex) })
	raw, err = json.Marshal(interfaces)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE devices SET interface_status=$2,status_attempted_at=$3,status_collection_state=$4,status_error=$5 WHERE id=$1`, id, raw, attempt, state, msg)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func interfaceKey(i model.Interface) string {
	if i.Name != "" {
		return "name:" + i.Name
	}
	return "descr:" + i.Description
}

func loadInterfaceStatus(ctx context.Context, tx pgx.Tx, devices []ExportDevice, links []ExportLink) error {
	// Read-only exports remain usable during a rolling upgrade from older schemas.
	var available bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid='devices'::regclass AND attname='interface_status' AND NOT attisdropped)`).Scan(&available); err != nil {
		return err
	}
	if !available {
		for i := range links {
			links[i].LinkInterfaceStatus = model.LinkStatus(model.InterfaceStatus{}, model.InterfaceStatus{}, time.Now(), 12*time.Minute)
		}
		return nil
	}

	byDevice := map[int64][]model.Interface{}
	byID := map[int64]*ExportDevice{}
	for i := range devices {
		byID[devices[i].ID] = &devices[i]
	}
	rows, err := tx.Query(ctx, `SELECT id,interface_status,status_collection_state,status_attempted_at,status_error FROM devices ORDER BY id`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var raw []byte
		var state, msg string
		var attempted *time.Time
		if err = rows.Scan(&id, &raw, &state, &attempted, &msg); err != nil {
			rows.Close()
			return err
		}
		var items []model.Interface
		if err = json.Unmarshal(raw, &items); err != nil {
			rows.Close()
			return err
		}
		byDevice[id] = items
		if d := byID[id]; d != nil {
			d.Interfaces = items
			d.InterfaceCollectionState = state
			d.InterfaceAttemptedAt = attempted
			d.InterfaceStatusError = msg
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	// Expose existing interface assets even before the first successful poll.
	// Status cache is an extension of these interfaces, not another inventory.
	rows, err = tx.Query(ctx, `WITH latest AS(SELECT device_id,max(scan_id) AS scan_id FROM scan_interface_facts GROUP BY device_id) SELECT f.device_id,f.if_index,f.if_name,f.if_descr,f.if_alias,f.if_type FROM scan_interface_facts f JOIN latest ON (latest.device_id,latest.scan_id)=(f.device_id,f.scan_id) WHERE (f.if_type IN(6,161) OR EXISTS(SELECT 1 FROM scan_lag_members m WHERE (m.scan_id,m.device_id,m.aggregate_if_index)=(f.scan_id,f.device_id,f.if_index))) ORDER BY f.device_id,f.if_index`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var i model.Interface
		if err = rows.Scan(&id, &i.IfIndex, &i.Name, &i.Description, &i.Alias, &i.Type); err != nil {
			rows.Close()
			return err
		}
		d := byID[id]
		if d == nil {
			continue
		}
		exists := false
		for _, cached := range byDevice[id] {
			if interfaceKey(cached) == interfaceKey(i) {
				exists = true
				break
			}
		}
		if exists {
			continue
		}
		i.AdminStatus = "unknown"
		i.OperStatus = "unknown"
		i.StatusCollectionState = d.InterfaceCollectionState
		i.StatusAttemptedAt = d.InterfaceAttemptedAt
		i.StatusError = d.InterfaceStatusError
		byDevice[id] = append(byDevice[id], i)
		d.Interfaces = byDevice[id]
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	// Use the last verified mapping for this stable port, then match current
	// ifName. Never correlate by a recycled ifIndex or a display-only alias.
	names := map[int64]model.Interface{}
	rows, err = tx.Query(ctx, `SELECT DISTINCT ON(port_id) port_id,if_name,if_descr FROM scan_interface_facts WHERE port_id IS NOT NULL ORDER BY port_id,scan_id DESC`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var i model.Interface
		if err = rows.Scan(&id, &i.Name, &i.Description); err != nil {
			rows.Close()
			return err
		}
		names[id] = i
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	resolve := func(device, port int64) model.InterfaceStatus {
		n, ok := names[port]
		if !ok {
			return model.InterfaceStatus{}
		}
		var match model.InterfaceStatus
		count := 0
		for _, i := range byDevice[device] {
			if n.Name != "" && i.Name == n.Name || n.Name == "" && i.Name == "" && n.Description != "" && i.Description == n.Description {
				match = i.InterfaceStatus
				count++
			}
		}
		if count != 1 {
			return model.InterfaceStatus{}
		}
		return match
	}
	for i := range links {
		l := &links[i]
		l.SourceInterfaceStatus = resolve(l.DeviceAID, l.PortAID)
		l.TargetInterfaceStatus = resolve(l.DeviceBID, l.PortBID)
		l.LinkInterfaceStatus = model.LinkStatus(l.SourceInterfaceStatus, l.TargetInterfaceStatus, time.Now().UTC(), 12*time.Minute)
	}
	return nil
}
