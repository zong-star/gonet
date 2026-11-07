package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"gonet/internal/discovery"
	"gonet/internal/identity"
	"gonet/internal/model"
	"gonet/internal/topology"
)

// Store owns one dedicated PostgreSQL session for a scan. The session holds the
// advisory lock for its whole lifetime (section 2.2).
type Store struct {
	conn               *pgx.Conn
	locked             bool
	keepScans          int
	committedDeviceIDs map[model.DevRef]int64
}

// CommittedDeviceID exposes the ref-to-ID mapping only after a successful
// result transaction; temporary discovery refs must never be logged as DB IDs.
func (s *Store) CommittedDeviceID(ref model.DevRef) (int64, bool) {
	id, ok := s.committedDeviceIDs[ref]
	return id, ok
}

// Open connects a dedicated session.
func Open(ctx context.Context, dsn string) (*Store, error) {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return nil, err
	}
	return &Store{conn: conn}, nil
}

// Close releases the advisory lock and closes the session.
func (s *Store) Close(ctx context.Context) error {
	s.releaseLock(ctx)
	return s.conn.Close(ctx)
}

// releaseLock releases the session advisory lock once the scan row is no longer
// running, so the same session can host a later scan.
func (s *Store) releaseLock(ctx context.Context) {
	if s.locked {
		Unlock(ctx, s.conn)
		s.locked = false
	}
}

// Conn exposes the underlying session (tests/diagnostics).
func (s *Store) Conn() *pgx.Conn { return s.conn }

// ScanInput seeds one running scan row.
type ScanInput struct {
	StartedAt     time.Time
	Seeds         []netip.Addr
	ConfigDigest  string
	ConfigSummary []byte
	KeepScans     int
}

// BeginScan takes the advisory lock, aborts any stale running scan, and inserts
// a new running scan_runs row.
func (s *Store) BeginScan(ctx context.Context, in ScanInput) (int64, error) {
	keep := in.KeepScans
	if keep == 0 {
		keep = 500
	}
	if keep < 2 || keep > 100000 {
		return 0, fmt.Errorf("invalid history retention limit")
	}
	if s.locked {
		return 0, fmt.Errorf("scan already started on this session")
	}
	ok, err := TryLock(ctx, s.conn)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, ErrLocked
	}
	s.locked = true
	s.keepScans = keep

	// Crash recovery: a leftover running scan is aborted without aging.
	if _, err := s.conn.Exec(ctx, `UPDATE scan_runs
		SET status='aborted', finished_at=now(),
		    termination_reasons = termination_reasons || '["aborted_stale_running"]'::jsonb
		WHERE status='running'`); err != nil {
		return 0, err
	}

	seeds := make([]string, 0, len(in.Seeds))
	for _, a := range in.Seeds {
		seeds = append(seeds, a.Unmap().String())
	}
	summary := in.ConfigSummary
	if len(summary) == 0 {
		summary = []byte("{}")
	}
	started := in.StartedAt
	if started.IsZero() {
		started = time.Now().UTC()
	}
	var id int64
	if err := s.conn.QueryRow(ctx, `INSERT INTO scan_runs(started_at, seed_ips, config_digest, config_summary)
		VALUES($1, $2::inet[], $3, $4::jsonb) RETURNING id`,
		started, seeds, in.ConfigDigest, string(summary)).Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

// MarkFailed marks a running scan failed in a short transaction. It is used
// after a failed result commit so the row never stays ambiguous.
func (s *Store) MarkFailed(ctx context.Context, scanID int64, code, detail string) error {
	if !s.locked {
		return fmt.Errorf("scan write requires session lock")
	}
	payload, _ := json.Marshal([]model.Issue{{Code: code, Component: "store", Message: detail}})
	tx, err := s.conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `UPDATE scan_runs
		SET status='failed', finished_at=now(), error_summary=$2::jsonb
		WHERE id=$1 AND status='running'`, scanID, string(payload))
	if err != nil {
		return err
	}
	if _, err = pruneHistory(ctx, tx, s.keepScans); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// CommitResult writes the whole round in one transaction. A re-submit for a
// non-running scan is an idempotent no-op.
func (s *Store) CommitResult(ctx context.Context, scanID int64, r *discovery.Result) error {
	tx, err := s.conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var status string
	if err := tx.QueryRow(ctx, `SELECT status FROM scan_runs WHERE id=$1 FOR UPDATE`, scanID).Scan(&status); err != nil {
		return err
	}
	if status != "running" {
		// Already committed (or failed/aborted): no side effects.
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		s.releaseLock(ctx)
		return nil
	}
	if !s.locked {
		return fmt.Errorf("scan write requires session lock")
	}

	devIDs := map[model.DevRef]int64{}
	for _, d := range r.Devices {
		id, err := upsertDevice(ctx, tx, d)
		if err != nil {
			return err
		}
		devIDs[d.Ref] = id
	}
	if err := upsertCandidates(ctx, tx, scanID, devIDs, r.Verifications); err != nil {
		return err
	}
	if err := upsertProbes(ctx, tx, scanID, devIDs, r); err != nil {
		return err
	}
	portIDs := map[model.PortRef]int64{}
	for _, p := range r.Ports {
		if p.Resolution == topology.PortUnresolved {
			continue
		}
		did, ok := devIDs[p.Device]
		if !ok {
			continue
		}
		id, err := upsertPort(ctx, tx, did, p)
		if err != nil {
			return err
		}
		portIDs[p.Ref] = id
	}

	targetByDev := map[model.DevRef]netip.Addr{}
	for _, o := range r.Outcomes {
		if o.Target.Address.IsValid() {
			targetByDev[o.Device] = o.Target.Address
		}
	}
	for _, o := range r.Outcomes {
		did, ok := devIDs[o.Device]
		if !ok {
			continue
		}
		if err := insertScanDevice(ctx, tx, scanID, did, o); err != nil {
			return err
		}
	}
	if err := insertInterfaceEvidence(ctx, tx, scanID, r, devIDs, portIDs); err != nil {
		return err
	}

	linkIDs := map[model.LinkKey]int64{}
	for _, l := range r.Links {
		for _, endpoint := range []struct {
			dev  model.DevRef
			port model.PortRef
		}{{l.Key.A, l.Key.PA}, {l.Key.B, l.Key.PB}} {
			var validDev, validPort bool
			for _, d := range r.Devices {
				if d.Ref == endpoint.dev {
					validDev = d.Classification.Managed() && d.State != identity.StateConflict
				}
			}
			for _, p := range r.Ports {
				if p.Ref == endpoint.port {
					validPort = p.Device == endpoint.dev && p.Physical && p.Resolution != topology.PortConflict && p.Resolution != topology.PortUnresolved
				}
			}
			if !validDev || !validPort {
				return fmt.Errorf("link endpoint is not a confirmed managed device and physical port")
			}
		}
		a, okA := devIDs[l.Key.A]
		pa, okPA := portIDs[l.Key.PA]
		b, okB := devIDs[l.Key.B]
		pb, okPB := portIDs[l.Key.PB]
		if !okA || !okPA || !okB || !okPB {
			return fmt.Errorf("link %+v references a device/port outside this result", l.Key)
		}
		id, err := upsertLink(ctx, tx, scanID, a, pa, b, pb, l)
		if err != nil {
			return err
		}
		linkIDs[l.Key] = id
	}

	for _, o := range r.Observations {
		if err := insertObservation(ctx, tx, scanID, devIDs, linkIDs, targetByDev, o); err != nil {
			return err
		}
	}
	for _, u := range r.Unresolved {
		if err := insertUnresolved(ctx, tx, scanID, devIDs, u); err != nil {
			return err
		}
	}
	for _, c := range r.Candidates {
		if c.Disposition != "excluded" {
			continue
		}
		if err := insertDiagnostic(ctx, tx, scanID, devIDs, topology.UnresolvedObservation{Observer: c.Observer, Row: c.Row, Raw: c.Raw, At: c.At, Reason: c.Classification.Reason}, "excluded"); err != nil {
			return err
		}
	}

	// Negative aging runs only for a closed round (completed or partial), and
	// only for links whose both endpoints were absence-eligible this round
	// (section 7.3). "positive-first" is enforced because seen links carry
	// last_seen_scan_id/last_evaluated_scan_id = this scan.
	if r.Status == "completed" || r.Status == "partial" {
		if err := applyAbsence(ctx, tx, scanID); err != nil {
			return err
		}
	}

	summary, _ := json.Marshal(r.Counts)
	var summaryFields map[string]any
	_ = json.Unmarshal(summary, &summaryFields)
	targets := make([]CollectionTarget, 0, len(r.CollectionTargets))
	for _, target := range r.CollectionTargets {
		targets = append(targets, CollectionTarget{DeviceID: devIDs[target.Device], Address: target.Address, Status: target.Status, ReasonCode: target.ReasonCode})
	}
	summaryFields["collection_targets"] = targets
	summary, _ = json.Marshal(summaryFields)
	issues, _ := json.Marshal(r.Issues)
	termination, _ := json.Marshal([]string{r.Termination})
	if _, err := tx.Exec(ctx, `UPDATE scan_runs
		SET status=$2, finished_at=now(), summary=$3::jsonb, error_summary=$4::jsonb, termination_reasons=$5::jsonb
		WHERE id=$1`, scanID, r.Status, string(summary), string(issues), string(termination)); err != nil {
		return err
	}
	if _, err := pruneHistory(ctx, tx, s.keepScans); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.committedDeviceIDs = devIDs
	s.releaseLock(ctx)
	return nil
}

// applyAbsence is the parameterized negative update from section 7.3. It only
// ages links not seen this round whose two endpoints are both eligible. A link
// with an unscanned or ineligible endpoint is frozen (no miss, no state change).
func applyAbsence(ctx context.Context, tx pgx.Tx, scanID int64) error {
	_, err := tx.Exec(ctx, `UPDATE links AS l
		SET missed_complete_scans = l.missed_complete_scans + 1,
		    discovery_state = CASE
		      WHEN l.missed_complete_scans + 1 >= 3 THEN 'stale'
		      ELSE 'suspect_stale' END,
		    last_evaluated_scan_id = $1,
		    updated_at = now()
		FROM scan_devices a, scan_devices b
		WHERE a.scan_id = $1 AND b.scan_id = $1
		  AND a.device_id = l.device_a_id
		  AND b.device_id = l.device_b_id
		  AND a.absence_eligible AND b.absence_eligible
		  AND l.last_seen_scan_id IS DISTINCT FROM $1
		  AND l.last_evaluated_scan_id IS DISTINCT FROM $1`, scanID)
	return err
}

func upsertDevice(ctx context.Context, tx pgx.Tx, d *identity.Device) (int64, error) {
	if !d.Classification.Managed() {
		return 0, fmt.Errorf("device is not a confirmed managed kind")
	}
	var id int64
	if d.StrongKey != "" {
		err := tx.QueryRow(ctx, `SELECT device_id FROM device_identities WHERE identity_key=$1`, d.StrongKey).Scan(&id)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return 0, err
		}
	}
	for _, a := range d.Addresses {
		if a.State != identity.AddrVerified {
			continue
		}
		var addressID int64
		var state string
		err := tx.QueryRow(ctx, `SELECT device_id, state FROM device_addresses
			WHERE address=$1::inet AND state IN ('verified','conflict')`, a.Addr.String()).Scan(&addressID, &state)
		if err == nil {
			if state == "conflict" || (id != 0 && id != addressID) {
				return 0, fmt.Errorf("ADDRESS_CONFLICT: address is bound to another identity")
			}
			var different bool
			if d.StrongKey != "" && id == 0 {
				if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM device_identities WHERE device_id=$1 AND identity_key<>$2)`, addressID, d.StrongKey).Scan(&different); err != nil {
					return 0, err
				}
				if different {
					return 0, fmt.Errorf("ADDRESS_CONFLICT: existing device has another strong identity")
				}
			}
			id = addressID
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return 0, err
		}
	}

	if id == 0 {
		if err := tx.QueryRow(ctx, `INSERT INTO devices(identity_state, classification_rule, sys_name, sys_object_id,device_kind,
		first_seen_at, last_seen_at)
		VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
			string(d.State), d.Classification.RuleID, d.SysName, d.SysObjectID, d.Classification.Result,
			d.FirstSeen, d.LastSeen).Scan(&id); err != nil {
			return 0, fmt.Errorf("insert device: %w", err)
		}
	} else {
		if _, err := tx.Exec(ctx, `UPDATE devices SET identity_state=$2, classification_rule=$3,
			sys_name=$4, sys_object_id=$5, last_seen_at=GREATEST(last_seen_at,$6),device_kind=$7, updated_at=now() WHERE id=$1`,
			id, string(d.State), d.Classification.RuleID, d.SysName, d.SysObjectID, d.LastSeen, d.Classification.Result); err != nil {
			return 0, err
		}
	}
	keys := append([]string{d.StrongKey}, d.IdentityKeys...)
	for _, key := range keys {
		if key == "" {
			continue
		}
		source := "lldp"
		if strings.HasPrefix(key, "manual:") {
			source = "manual"
		}
		var owner int64
		e := tx.QueryRow(ctx, `SELECT device_id FROM device_identities WHERE identity_key=$1`, key).Scan(&owner)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return 0, e
		}
		if owner != 0 && owner != id {
			return 0, fmt.Errorf("IDENTITY_CONFLICT: normalized alias belongs to another device")
		}
		subtype, raw := d.Chassis.Subtype, d.Chassis.Raw
		if key != d.StrongKey {
			parts := strings.Split(key, ":")
			if len(parts) == 3 {
				if parts[1] == "4" {
					subtype = 4
				} else if parts[1] == "7" {
					subtype = 7
				}
				if b, e := hex.DecodeString(parts[2]); e == nil {
					raw = b
				}
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO device_identities(identity_key, device_id, source, subtype, raw_value)
			VALUES($1,$2,$3,$4,$5) ON CONFLICT(identity_key) DO UPDATE SET last_seen_at=now()`, key, id, source, subtype, raw); err != nil {
			return 0, fmt.Errorf("insert identity: %w", err)
		}
	}
	for _, a := range d.Addresses {
		if a.State == identity.AddrRetired {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO device_addresses(device_id, address, state, source, verified_at)
			VALUES($1,$2::inet,$3,$4,now()) ON CONFLICT(address) WHERE state IN ('verified','conflict')
			DO UPDATE SET state=CASE WHEN device_addresses.state='conflict' THEN 'conflict' ELSE EXCLUDED.state END,
			source=CASE WHEN device_addresses.state='conflict' THEN device_addresses.source ELSE EXCLUDED.source END,
			last_success_at=CASE WHEN EXCLUDED.state='verified' THEN now() ELSE device_addresses.last_success_at END`, id, a.Addr.String(), string(a.State), a.Source); err != nil {
			return 0, fmt.Errorf("insert address: %w", err)
		}
	}
	return id, nil
}

func upsertPort(ctx context.Context, tx pgx.Tx, deviceID int64, p *topology.Port) (int64, error) {
	var id int64
	aliases := []byte("[]")
	if len(p.Aliases) > 0 {
		aliases, _ = json.Marshal(p.Aliases)
	}
	keys := []string{string(p.Key)}
	for _, key := range p.Aliases {
		keys = append(keys, string(key))
	}
	// A verified scoped alias can retire a pure name-only placeholder. These
	// rows have never supplied a physical endpoint and no link references them;
	// raw LLDP observations remain intact. Keep the canonical port and link IDs.
	// The overlap check below still rejects mapped/linked/other port records,
	// and any failure rolls this narrow cleanup back with the result transaction.
	if p.Physical && p.IfIndex != nil && p.Resolution == topology.PortVerified && topology.HasVerifiedAliases(p.MappingRule) {
		if _, err := tx.Exec(ctx, `DELETE FROM ports p WHERE p.device_id=$1 AND p.port_key<>$2
			AND (p.port_key=ANY($3::text[]) OR p.aliases ?| $3::text[])
			AND p.if_index IS NULL AND NOT p.is_physical AND p.mapping_rule='provisional-ifname'
			AND NOT EXISTS(SELECT 1 FROM links l WHERE l.port_a_id=p.id OR l.port_b_id=p.id)
			AND NOT EXISTS(SELECT 1 FROM scan_interface_facts f WHERE f.port_id=p.id)`, deviceID, string(p.Key), keys); err != nil {
			return 0, err
		}
	}
	var overlapping bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM ports WHERE device_id=$1 AND port_key<>$2
		AND (port_key=ANY($3::text[]) OR aliases ?| $3::text[]))`, deviceID, string(p.Key), keys).Scan(&overlapping); err != nil {
		return 0, err
	}
	if overlapping {
		return 0, fmt.Errorf("PORT_ID_CHANGED: port alias already belongs to another record")
	}
	err := tx.QueryRow(ctx, `SELECT id FROM ports WHERE device_id=$1 AND port_key=$2`, deviceID, string(p.Key)).Scan(&id)
	if err == nil {
		_, err = tx.Exec(ctx, `UPDATE ports SET if_index=$2, if_type=$3, is_physical=$4, mapping_rule=$5, last_seen_at=$6,
			resolution=$7, lldp_local_num=$8, display_name=$9,
			aliases=(SELECT COALESCE(jsonb_agg(DISTINCT value ORDER BY value),'[]'::jsonb) FROM jsonb_array_elements(ports.aliases || $10::jsonb)) WHERE id=$1`, id, nullableInt32(p.IfIndex), p.IfType, p.Physical, p.MappingRule, p.LastSeen,
			string(p.Resolution), nullableUint32(p.LLDPPortNum), p.DisplayName, string(aliases))
		return id, err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, err
	}
	err = tx.QueryRow(ctx, `INSERT INTO ports(device_id, port_key, subtype, raw_id, aliases, display_name,
		if_index, lldp_local_num, if_type, resolution, is_physical, mapping_rule, first_seen_at, last_seen_at)
		VALUES($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id`,
		deviceID, string(p.Key), p.Subtype, p.RawID, string(aliases), p.DisplayName,
		nullableInt32(p.IfIndex), nullableUint32(p.LLDPPortNum), p.IfType, string(p.Resolution),
		p.Physical, p.MappingRule, p.FirstSeen, p.LastSeen).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("insert port %s: %w", p.Key, err)
	}
	return id, nil
}

func insertScanDevice(ctx context.Context, tx pgx.Tx, scanID, deviceID int64, o model.ScanOutcome) error {
	outcome := "partial"
	if o.Snapshot == nil && (o.Outcome == "failed" || o.Outcome == "unscanned") {
		outcome = o.Outcome
	}
	var cc, ss, ae bool
	components := []byte("{}")
	var collectedAt any
	if o.Snapshot != nil {
		cc = o.Snapshot.CollectionComplete
		ss = o.Snapshot.SnapshotStable
		ae = o.Snapshot.AbsenceEligible
		if cc {
			outcome = "success"
		}
		if o.Snapshot.Components != nil {
			components, _ = json.Marshal(o.Snapshot.Components)
		}
		if !o.Snapshot.CollectedAt.IsZero() {
			collectedAt = o.Snapshot.CollectedAt
		}
	}
	reasons, _ := json.Marshal(o.Issues)
	var targetIP any
	if o.Target.Address.IsValid() {
		targetIP = o.Target.Address.Unmap().String()
	}
	_, err := tx.Exec(ctx, `INSERT INTO scan_devices(scan_id, device_id, depth, target_ip, outcome,
		collection_complete, snapshot_stable, absence_eligible, reasons, component_status, collected_at)
		VALUES($1,$2,$3,$4::inet,$5,$6,$7,$8,$9::jsonb,$10::jsonb,$11)
		ON CONFLICT(scan_id,device_id) DO UPDATE SET depth=LEAST(scan_devices.depth,EXCLUDED.depth),
		collection_complete=scan_devices.collection_complete AND EXCLUDED.collection_complete,
		snapshot_stable=scan_devices.snapshot_stable AND EXCLUDED.snapshot_stable,
		absence_eligible=scan_devices.absence_eligible AND EXCLUDED.absence_eligible,
		outcome=CASE WHEN scan_devices.collection_complete AND EXCLUDED.collection_complete THEN 'success' ELSE 'partial' END`,
		scanID, deviceID, o.Target.Depth, targetIP, outcome, cc, ss, ae, string(reasons), string(components), collectedAt)
	if err != nil {
		return fmt.Errorf("insert scan_device: %w", err)
	}
	return nil
}

func upsertLink(ctx context.Context, tx pgx.Tx, scanID, a, pa, b, pb int64, l model.LinkEvidence) (int64, error) {
	if a > b {
		a, pa, b, pb = b, pb, a, pa
	}
	firstAt := l.FirstAt
	lastAt := l.LastAt
	if firstAt.IsZero() {
		firstAt = lastAt
	}
	if lastAt.IsZero() {
		lastAt = firstAt
	}
	var id int64
	err := tx.QueryRow(ctx, `INSERT INTO links(device_a_id, port_a_id, device_b_id, port_b_id, confidence,
		discovery_state, missed_complete_scans, first_seen_at, last_seen_at, last_seen_scan_id, last_evaluated_scan_id)
		VALUES($1,$2,$3,$4,$5,'active',0,$6,$7,$8,$8)
		ON CONFLICT (device_a_id, port_a_id, device_b_id, port_b_id) DO UPDATE
		SET confidence=EXCLUDED.confidence,
		    discovery_state='active',
		    missed_complete_scans=0,
		    last_seen_at=GREATEST(links.last_seen_at, EXCLUDED.last_seen_at),
		    last_seen_scan_id=EXCLUDED.last_seen_scan_id,
		    last_evaluated_scan_id=EXCLUDED.last_evaluated_scan_id,
		    updated_at=now()
		RETURNING id`,
		a, pa, b, pb, l.Confidence(), firstAt, lastAt, scanID).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("upsert link: %w", err)
	}
	return id, nil
}

func insertObservation(ctx context.Context, tx pgx.Tx, scanID int64, devIDs map[model.DevRef]int64,
	linkIDs map[model.LinkKey]int64, targetByDev map[model.DevRef]netip.Addr, o model.LinkObservation) error {
	lk, err := topology.Canonical(o.Observer, o.LocalPort, o.Remote, o.RemotePort)
	if err != nil {
		return err
	}
	linkID, ok := linkIDs[lk]
	if !ok {
		return fmt.Errorf("observation has no link for key %+v", lk)
	}
	seenFrom := "b"
	if devIDs[o.Observer] < devIDs[o.Remote] {
		seenFrom = "a"
	}
	raw, _ := json.Marshal(o.Raw)
	key := observationKey(targetByDev[o.Observer], o)
	_, err = tx.Exec(ctx, `INSERT INTO observations(scan_id, observer_device_id, observation_key, collected_at,
		row_time_mark, local_port_num, remote_index, raw_neighbor, resolution, link_id, seen_from)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,'resolved',$9,$10) ON CONFLICT(scan_id,observation_key) DO NOTHING`,
		scanID, nullableDevID(devIDs, o.Observer), key, o.At, o.Row.TimeMark, o.Row.LocalPortNum, o.Row.RemoteIndex,
		string(raw), linkID, seenFrom)
	if err != nil {
		return fmt.Errorf("insert observation: %w", err)
	}
	return nil
}

func insertUnresolved(ctx context.Context, tx pgx.Tx, scanID int64, devIDs map[model.DevRef]int64, u topology.UnresolvedObservation) error {
	return insertDiagnostic(ctx, tx, scanID, devIDs, u, "unresolved")
}

func insertDiagnostic(ctx context.Context, tx pgx.Tx, scanID int64, devIDs map[model.DevRef]int64, u topology.UnresolvedObservation, resolution string) error {
	raw, _ := json.Marshal(u.Raw)
	target := netip.Addr{}
	key := observationKey(target, model.LinkObservation{Observer: u.Observer, Row: u.Row})
	reasons, _ := json.Marshal(append(append([]string{}, u.ReasonCodes...), u.Reason))
	_, err := tx.Exec(ctx, `INSERT INTO observations(scan_id, observer_device_id, observation_key, collected_at,
		row_time_mark, local_port_num, remote_index, raw_neighbor, resolution, reason_codes)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$10,$9::jsonb) ON CONFLICT(scan_id,observation_key) DO NOTHING`,
		scanID, nullableDevID(devIDs, u.Observer), key, u.At, u.Row.TimeMark, u.Row.LocalPortNum, u.Row.RemoteIndex,
		string(raw), string(reasons), resolution)
	if err != nil {
		return fmt.Errorf("insert unresolved observation: %w", err)
	}
	return nil
}

func observationKey(target netip.Addr, o model.LinkObservation) string {
	tuple := fmt.Sprintf(`{"target":%q,"observer":%d,"row":[%d,%d,%d]}`,
		target.String(), o.Observer, o.Row.TimeMark, o.Row.LocalPortNum, o.Row.RemoteIndex)
	sum := sha256.Sum256([]byte(tuple))
	return hex.EncodeToString(sum[:])
}

func nullableInt32(p *int32) any {
	if p == nil {
		return nil
	}
	return *p
}

func nullableUint32(p *uint32) any {
	if p == nil {
		return nil
	}
	return int64(*p)
}

func nullableDevID(devIDs map[model.DevRef]int64, ref model.DevRef) any {
	if id, ok := devIDs[ref]; ok && id != 0 {
		return id
	}
	return nil
}
