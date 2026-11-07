package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/topology"
)

// LoadContext is called under the scan's dedicated session lock, before any
// SNMP I/O. Database ids are translated to fresh temporary refs; these records
// are resolution context, never additional discovery seeds.
func (s *Store) LoadContext(ctx context.Context) ([]*identity.Device, []*topology.Port, error) {
	if !s.locked {
		return nil, nil, fmt.Errorf("resolution context requires scan lock")
	}
	rows, err := s.conn.Query(ctx, `SELECT d.id,d.identity_state,d.classification_rule,
		COALESCE(d.sys_name,''),COALESCE(d.sys_object_id,''),d.first_seen_at,d.last_seen_at,
		COALESCE(i.identity_key,''),COALESCE(i.subtype,0),i.raw_value,d.device_kind
		FROM devices d LEFT JOIN LATERAL (SELECT * FROM device_identities WHERE device_id=d.id
		ORDER BY first_seen_at,identity_key LIMIT 1) i ON true ORDER BY d.id`)
	if err != nil {
		return nil, nil, err
	}
	var devices []*identity.Device
	byID := map[int64]*identity.Device{}
	for rows.Next() {
		d := &identity.Device{}
		var id int64
		if err := rows.Scan(&id, &d.State, &d.Classification.RuleID, &d.SysName, &d.SysObjectID, &d.FirstSeen, &d.LastSeen,
			&d.StrongKey, &d.Chassis.Subtype, &d.Chassis.Raw, &d.Classification.Result); err != nil {
			rows.Close()
			return nil, nil, err
		}
		d.Ref = model.DevRef(len(devices) + 1)
		devices = append(devices, d)
		byID[id] = d
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	rows, err = s.conn.Query(ctx, `SELECT device_id,identity_key FROM device_identities ORDER BY identity_key`)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var id int64
		var key string
		if err := rows.Scan(&id, &key); err != nil {
			rows.Close()
			return nil, nil, err
		}
		byID[id].IdentityKeys = append(byID[id].IdentityKeys, key)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	rows, err = s.conn.Query(ctx, `SELECT device_id,host(address),state,source FROM device_addresses ORDER BY id`)
	if err != nil {
		return nil, nil, err
	}
	for rows.Next() {
		var id int64
		var text string
		var a identity.Address
		if err := rows.Scan(&id, &text, &a.State, &a.Source); err != nil {
			rows.Close()
			return nil, nil, err
		}
		a.Addr, err = netip.ParseAddr(text)
		if err != nil {
			rows.Close()
			return nil, nil, err
		}
		byID[id].Addresses = append(byID[id].Addresses, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, nil, err
	}
	rows, err = s.conn.Query(ctx, `SELECT device_id,port_key,subtype,raw_id,aliases,display_name,if_index,
		lldp_local_num,COALESCE(if_type,0),mapping_rule,first_seen_at,last_seen_at FROM ports ORDER BY id`)
	if err != nil {
		return nil, nil, err
	}
	var ports []*topology.Port
	for rows.Next() {
		p := &topology.Port{}
		var id int64
		var aliases []byte
		if err := rows.Scan(&id, &p.Key, &p.Subtype, &p.RawID, &aliases, &p.DisplayName, &p.IfIndex, &p.LLDPPortNum,
			&p.IfType, &p.MappingRule, &p.FirstSeen, &p.LastSeen); err != nil {
			rows.Close()
			return nil, nil, err
		}
		if err := json.Unmarshal(aliases, &p.Aliases); err != nil {
			rows.Close()
			return nil, nil, err
		}
		p.Ref = model.PortRef(len(ports) + 1)
		p.Device = byID[id].Ref
		ports = append(ports, p)
	}
	err = rows.Err()
	rows.Close()
	return devices, ports, err
}
