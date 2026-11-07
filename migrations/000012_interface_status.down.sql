DROP INDEX ix_scan_interface_device_scan;
ALTER TABLE devices DROP COLUMN interface_status, DROP COLUMN status_attempted_at, DROP COLUMN status_collection_state, DROP COLUMN status_error;
