package cli

import (
	"log/slog"

	"gonet/internal/discovery"
	"gonet/internal/preprobe"
	"gonet/internal/store/postgres"
)

func probeLogger(logger *slog.Logger, scanID int64) func(preprobe.Attempt, preprobe.Record) {
	return func(a preprobe.Attempt, r preprobe.Record) {
		logger.Info("SNMP preprobe", "scan_id", scanID, "stage", "preprobe", "probe_ip", a.IP, "profile", a.Profile, "raw_chassis", a.Facts.Chassis, "normalized_chassis", r.Identity, "sys_name", a.Facts.SysName, "probe_result", r.Status, "match_result", "await_lldp", "matched_device_id", r.MatchedDeviceID, "error_code", r.FailureCode, "next_action", "match_core_lldp", "pdus", a.PDUs, "elapsed", a.Elapsed.String())
	}
}

func discoveryLogger(logger *slog.Logger, scanID int64) func(discovery.Event) {
	return func(e discovery.Event) {
		logger.Info("neighbor verification", "event", "lldp_verification", "scan_id", scanID, "stage", "neighbor_match",
			"source_device", e.SourceDevice, "source_port", e.SourcePort,
			"remote_sys_name", e.RemoteSysName, "remote_chassis_id", e.RemoteChassis,
			"reported_management_ip", e.ReportedIPs, "selected_snmp_ip", e.SelectedIP,
			"verification_result", e.Result, "verification_error", e.ErrorCode,
			"error_detail", e.Error, "matched_device_ref", e.MatchedDevice, "next_action", e.NextAction)
	}
}

func logCommittedNeighbors(logger *slog.Logger, scanID int64, store *postgres.Store, r *discovery.Result) {
	for ip, ref := range r.Preprobe.MatchedRefs {
		if id, ok := store.CommittedDeviceID(ref); ok {
			logger.Info("probe association committed", "scan_id", scanID, "stage", "saving", "probe_ip", ip, "match_result", "verified", "matched_device_id", id, "next_action", "refresh_next_scan")
		}
	}
	for _, v := range r.Verifications {
		id, ok := store.CommittedDeviceID(v.MatchedDevice)
		if !ok {
			continue
		}
		sourceID, _ := store.CommittedDeviceID(v.SourceDevice)
		logger.Info("neighbor linked", "event", "device_linked", "scan_id", scanID,
			"source_device", sourceID, "source_port", v.Neighbor.Index.LocalPortNum,
			"remote_sys_name", v.Neighbor.SysName, "remote_chassis_id", v.Neighbor.Chassis,
			"reported_management_ip", v.Neighbor.MgmtAddresses, "selected_snmp_ip", v.Details.SelectedIP,
			"verification_result", v.Details.Status, "verification_error", v.Details.FailureCode,
			"matched_device_ref", v.MatchedDevice, "matched_device_id", id, "next_action", "device_and_topology_committed")
	}
}
