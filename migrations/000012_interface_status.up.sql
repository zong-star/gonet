ALTER TABLE devices
 ADD COLUMN interface_status JSONB NOT NULL DEFAULT '[]'::jsonb,
 ADD COLUMN status_attempted_at TIMESTAMPTZ,
 ADD COLUMN status_collection_state TEXT NOT NULL DEFAULT 'unknown',
 ADD COLUMN status_error TEXT NOT NULL DEFAULT '';
COMMENT ON COLUMN devices.interface_status IS 'Current IF-MIB status cache using model.Interface, matched by ifName; not a second interface asset table. Last successful values survive collection failure.';

CREATE INDEX ix_scan_interface_device_scan ON scan_interface_facts(device_id,scan_id DESC);
