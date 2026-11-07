-- Expiring a scan must not delete or refresh a current/historical physical link.
-- Its timestamps, stable ID, confidence and miss state remain unchanged.
ALTER TABLE links DROP CONSTRAINT links_last_seen_scan_id_fkey;
ALTER TABLE links DROP CONSTRAINT links_last_evaluated_scan_id_fkey;
ALTER TABLE links ALTER COLUMN last_seen_scan_id DROP NOT NULL;
ALTER TABLE links ALTER COLUMN last_evaluated_scan_id DROP NOT NULL;
ALTER TABLE links ADD CONSTRAINT links_last_seen_scan_id_fkey
  FOREIGN KEY (last_seen_scan_id) REFERENCES scan_runs(id) ON DELETE SET NULL;
ALTER TABLE links ADD CONSTRAINT links_last_evaluated_scan_id_fkey
  FOREIGN KEY (last_evaluated_scan_id) REFERENCES scan_runs(id) ON DELETE SET NULL;
