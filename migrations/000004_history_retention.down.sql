-- Refuse to fabricate provenance if expired scans are no longer available.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM links WHERE last_seen_scan_id IS NULL OR last_evaluated_scan_id IS NULL) THEN
    RAISE EXCEPTION 'cannot roll back retention while links have expired scan references';
  END IF;
END $$;
ALTER TABLE links DROP CONSTRAINT links_last_seen_scan_id_fkey;
ALTER TABLE links DROP CONSTRAINT links_last_evaluated_scan_id_fkey;
ALTER TABLE links ALTER COLUMN last_seen_scan_id SET NOT NULL;
ALTER TABLE links ALTER COLUMN last_evaluated_scan_id SET NOT NULL;
ALTER TABLE links ADD CONSTRAINT links_last_seen_scan_id_fkey FOREIGN KEY (last_seen_scan_id) REFERENCES scan_runs(id);
ALTER TABLE links ADD CONSTRAINT links_last_evaluated_scan_id_fkey FOREIGN KEY (last_evaluated_scan_id) REFERENCES scan_runs(id);
