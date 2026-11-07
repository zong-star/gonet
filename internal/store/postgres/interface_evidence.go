package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"gonet/internal/discovery"
	"gonet/internal/model"
	"gonet/internal/topology"
)

func insertInterfaceEvidence(ctx context.Context, tx pgx.Tx, scanID int64, result *discovery.Result, devices map[model.DevRef]int64, ports map[model.PortRef]int64) error {
	type interfaceKey struct {
		device model.DevRef
		index  int32
	}
	physical := map[interfaceKey]int64{}
	for _, port := range result.Ports {
		id := ports[port.Ref]
		if id == 0 || !port.Physical || port.Resolution != topology.PortVerified || port.IfIndex == nil {
			continue
		}
		key := interfaceKey{port.Device, *port.IfIndex}
		if previous, ok := physical[key]; ok && previous != id {
			physical[key] = 0
		} else {
			physical[key] = id
		}
	}
	// Multiple snapshots for the same device make its per-scan ifIndex
	// namespace ambiguous. Leave that device's interface facts unavailable.
	snapshots := map[model.DevRef]int{}
	for _, outcome := range result.Outcomes {
		if outcome.Snapshot != nil {
			snapshots[outcome.Device]++
		}
	}
	var facts, members [][]any
	var groups, evidence [][]any
	for _, outcome := range result.Outcomes {
		deviceID, snap := devices[outcome.Device], outcome.Snapshot
		if deviceID == 0 || snap == nil || snapshots[outcome.Device] != 1 {
			continue
		}
		for _, iface := range snap.Interfaces {
			port := physical[interfaceKey{outcome.Device, iface.IfIndex}]
			var portID any
			if port != 0 {
				portID = port
			}
			facts = append(facts, []any{scanID, deviceID, iface.IfIndex, interfaceText(iface.Name),
				interfaceText(iface.Description), interfaceText(iface.Alias), iface.Type, portID, snap.CollectedAt, iface.AliasCollected})
		}
		for _, member := range snap.LAGMembers {
			sources, err := json.Marshal(member.Sources)
			if err != nil {
				return err
			}
			members = append(members, []any{scanID, deviceID, member.AggregateIfIndex, member.MemberIfIndex, member.Source, member.Mode, member.Status, member.Configured, member.Selected, member.Attached, sources})
		}
		for _, group := range snap.LAGGroups {
			b, err := json.Marshal(group)
			if err != nil {
				return err
			}
			groups = append(groups, []any{scanID, deviceID, group.SourceGroupID, group.AggregateIfIndex, b})
		}
		ordinal := 0
		addEvidence := func(kind string, fact any) error {
			b, err := json.Marshal(fact)
			if err != nil {
				return err
			}
			ordinal++
			evidence = append(evidence, []any{scanID, deviceID, ordinal, kind, b})
			return nil
		}
		for _, fact := range snap.LAGEvidence {
			if err := addEvidence("source", fact); err != nil {
				return err
			}
		}
		for _, fact := range snap.LAGAdvertisements {
			if err := addEvidence("advertisement", fact); err != nil {
				return err
			}
		}
		for _, fact := range snap.LACPPorts {
			if err := addEvidence("lacp", fact); err != nil {
				return err
			}
		}
	}
	if len(facts) != 0 {
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"scan_interface_facts"},
			[]string{"scan_id", "device_id", "if_index", "if_name", "if_descr", "if_alias", "if_type", "port_id", "collected_at", "if_alias_collected"}, pgx.CopyFromRows(facts))
		if err != nil {
			return fmt.Errorf("store scan interface facts: %w", err)
		}
	}
	if len(members) != 0 {
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"scan_lag_members"},
			[]string{"scan_id", "device_id", "aggregate_if_index", "member_if_index", "source", "mode", "status", "configured", "selected", "attached", "sources"}, pgx.CopyFromRows(members))
		if err != nil {
			return fmt.Errorf("store scan LAG members: %w", err)
		}
	}
	if len(groups) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"scan_lag_groups"}, []string{"scan_id", "device_id", "group_key", "aggregate_if_index", "facts"}, pgx.CopyFromRows(groups)); err != nil {
			return fmt.Errorf("store LAG groups: %w", err)
		}
	}
	if len(evidence) > 0 {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"scan_lag_evidence"}, []string{"scan_id", "device_id", "ordinal", "kind", "facts"}, pgx.CopyFromRows(evidence)); err != nil {
			return fmt.Errorf("store LAG evidence: %w", err)
		}
	}
	return nil
}

func interfaceText(value string) string {
	return strings.ToValidUTF8(strings.ReplaceAll(value, "\x00", ""), "\uFFFD")
}
