package postgres

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
	"gonet/internal/model"
)

// Schema 10 remains readable for preparing/previewing the compatible API.
// Collecting new vendor facts requires migration 11 before scans are enabled.
func loadVendorLAG(ctx context.Context, tx pgx.Tx, scanID int64, out *TopologyEvidence) error {
	var available bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('scan_lag_evidence') IS NOT NULL`).Scan(&available); err != nil {
		return err
	}
	if !available {
		return nil
	}
	rows, err := tx.Query(ctx, `SELECT device_id,facts FROM scan_lag_groups WHERE scan_id=$1 ORDER BY device_id,group_key`, scanID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var raw []byte
		if err = rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		var g model.LAGGroup
		if err = json.Unmarshal(raw, &g); err != nil {
			rows.Close()
			return err
		}
		v := out.LAG[id]
		v.Groups = append(v.Groups, g)
		out.LAG[id] = v
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT device_id,aggregate_if_index,member_if_index,configured,selected,attached,sources FROM scan_lag_members WHERE scan_id=$1`, scanID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var agg, member int32
		var configured, selected, attached *bool
		var raw []byte
		if err = rows.Scan(&id, &agg, &member, &configured, &selected, &attached, &raw); err != nil {
			rows.Close()
			return err
		}
		v := out.LAG[id]
		for i := range v.Members {
			r := &v.Members[i]
			if r.AggregateIfIndex == agg && r.MemberIfIndex == member {
				r.Configured, r.Selected, r.Attached = configured, selected, attached
				if err = json.Unmarshal(raw, &r.Sources); err != nil {
					rows.Close()
					return err
				}
			}
		}
		out.LAG[id] = v
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	rows, err = tx.Query(ctx, `SELECT device_id,kind,facts FROM scan_lag_evidence WHERE scan_id=$1 ORDER BY device_id,ordinal`, scanID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id int64
		var kind string
		var raw []byte
		if err = rows.Scan(&id, &kind, &raw); err != nil {
			rows.Close()
			return err
		}
		v := out.LAG[id]
		switch kind {
		case "source":
			var x model.LAGEvidence
			err = json.Unmarshal(raw, &x)
			v.Sources = append(v.Sources, x)
		case "advertisement":
			var x model.LAGAdvertisement
			err = json.Unmarshal(raw, &x)
			v.Advertisements = append(v.Advertisements, x)
		case "lacp":
			var x model.LACPPort
			err = json.Unmarshal(raw, &x)
			v.LACPPorts = append(v.LACPPorts, x)
		}
		if err != nil {
			rows.Close()
			return err
		}
		out.LAG[id] = v
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	// Bind advertisements through the actual observation index, not just the
	// local port: multiple LLDP neighbors can occupy that port.
	rows, err = tx.Query(ctx, `SELECT link_id,observer_device_id,row_time_mark,local_port_num,remote_index FROM observations WHERE scan_id=$1 AND link_id IS NOT NULL`, scanID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var link, id int64
		var idx model.NeighborIndex
		if err = rows.Scan(&link, &id, &idx.TimeMark, &idx.LocalPortNum, &idx.RemoteIndex); err != nil {
			rows.Close()
			return err
		}
		v := out.Links[link]
		for _, ad := range out.LAG[id].Advertisements {
			if ad.Direction == "remote" && ad.Index == idx {
				v.Advertisements = append(v.Advertisements, LAGAdvertisementEvidence{id, ad})
			}
		}
		out.Links[link] = v
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	// Endpoint orientation is established by the link record in the same query.
	rows, err = tx.Query(ctx, `SELECT id,device_a_id,device_b_id FROM links WHERE last_seen_scan_id=$1`, scanID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var link, a, b int64
		if err = rows.Scan(&link, &a, &b); err != nil {
			return err
		}
		v := out.Links[link]
		for _, r := range out.LAG[a].LACPPorts {
			if v.A.IfIndex != nil && r.MemberIfIndex == *v.A.IfIndex {
				x := r
				v.LACPA = &x
			}
		}
		for _, r := range out.LAG[b].LACPPorts {
			if v.B.IfIndex != nil && r.MemberIfIndex == *v.B.IfIndex {
				x := r
				v.LACPB = &x
			}
		}
		out.Links[link] = v
	}
	return rows.Err()
}
