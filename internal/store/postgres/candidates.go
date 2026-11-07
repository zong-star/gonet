package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"

	"github.com/jackc/pgx/v5"
	"gonet/internal/discovery"
	"gonet/internal/model"
	"gonet/internal/topology"
)

func upsertCandidates(ctx context.Context, tx pgx.Tx, scanID int64, ids map[model.DevRef]int64, values []discovery.Verification) error {
	// Aggregate all ports/sources for an identity before writing so a blank
	// advertisement on a second link cannot overwrite its management address.
	grouped := map[string]discovery.Verification{}
	for _, v := range values {
		sourceID := ids[v.SourceDevice]
		key := v.Key(uint64(sourceID))
		if old, ok := grouped[key]; ok {
			if v.Neighbor.SysName == "" {
				v.Neighbor.SysName = old.Neighbor.SysName
			}
			v.Neighbor.MgmtAddresses = mergeAddresses(old.Neighbor.MgmtAddresses, v.Neighbor.MgmtAddresses)
		}
		grouped[key] = v
	}
	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		v := grouped[key]
		addresses, err := json.Marshal(v.Neighbor.MgmtAddresses)
		if err != nil {
			return err
		}
		details, err := json.Marshal(v.Details)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO discovery_candidates(candidate_key,chassis_subtype,chassis_raw,sys_name,
			reported_management_addresses,verification,source_device_id,source_port,device_id,
			first_discovered_at,last_discovered_at,last_seen_scan_id)
			VALUES($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7,$8,$9,$10,$10,$11)
			ON CONFLICT(candidate_key) DO UPDATE SET chassis_subtype=EXCLUDED.chassis_subtype,
			chassis_raw=EXCLUDED.chassis_raw,sys_name=CASE WHEN EXCLUDED.sys_name='' THEN discovery_candidates.sys_name ELSE EXCLUDED.sys_name END,
			reported_management_addresses=EXCLUDED.reported_management_addresses,verification=EXCLUDED.verification,
			source_device_id=EXCLUDED.source_device_id,source_port=EXCLUDED.source_port,
			device_id=COALESCE(EXCLUDED.device_id,discovery_candidates.device_id),
			last_discovered_at=EXCLUDED.last_discovered_at,last_seen_scan_id=EXCLUDED.last_seen_scan_id`,
			key, v.Neighbor.Chassis.Subtype, v.Neighbor.Chassis.Raw, v.Neighbor.SysName, string(addresses), string(details),
			nullableDevID(ids, v.SourceDevice), int64(v.Neighbor.Index.LocalPortNum), nullableDevID(ids, v.MatchedDevice), v.DiscoveredAt, scanID)
		if err != nil {
			return fmt.Errorf("DATABASE_WRITE_FAILED: candidate: %w", err)
		}
	}
	// A later direct verification resolves aliases of older pending records,
	// including subtype 7 textual MACs which now match a subtype 4 chassis.
	_, err := tx.Exec(ctx, `UPDATE discovery_candidates c SET device_id=i.device_id
		FROM device_identities i WHERE c.candidate_key=i.identity_key AND c.device_id IS NULL
		AND COALESCE(c.verification->>'verification_status','') <> 'identity_conflict'`)
	return err
}

func mergeAddresses(a, b []netip.Addr) []netip.Addr {
	seen := map[netip.Addr]bool{}
	out := []netip.Addr{}
	for _, list := range [][]netip.Addr{a, b} {
		for _, ip := range list {
			if !seen[ip] {
				out = append(out, ip)
				seen[ip] = true
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

func enrichPending(ctx context.Context, tx pgx.Tx, nodes []topology.PendingNode) error {
	for i := range nodes {
		var verification, addresses []byte
		err := tx.QueryRow(ctx, `SELECT verification,reported_management_addresses FROM discovery_candidates WHERE candidate_key=$1`, nodes[i].Key).Scan(&verification, &addresses)
		if err == pgx.ErrNoRows {
			continue
		}
		if err != nil {
			return err
		}
		if err = json.Unmarshal(verification, &nodes[i].Verification); err != nil {
			return err
		}
		if err = json.Unmarshal(addresses, &nodes[i].ManagementAddresses); err != nil {
			return err
		}
	}
	return nil
}
