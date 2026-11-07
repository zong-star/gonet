-- Positive access evidence has no fabricated LLDP observer and no unique
-- chassis constraint. A row is one access IP; typed facts stay together in JSONB.
ALTER TABLE device_addresses DROP CONSTRAINT device_addresses_source_check;
ALTER TABLE device_addresses ADD CONSTRAINT device_addresses_source_check CHECK
    (source IN ('seed','lldp','manual','snmp_preprobe','probe_cache','manual_supplement'));
CREATE TABLE snmp_probe_results (
    probe_ip inet PRIMARY KEY,
    record jsonb NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    last_scan_id bigint REFERENCES scan_runs(id) ON DELETE SET NULL,
    matched_device_id bigint REFERENCES devices(id) ON DELETE SET NULL
);
CREATE INDEX snmp_probe_identity_idx ON snmp_probe_results ((record->>'normalized_identity'));
CREATE INDEX snmp_probe_status_idx ON snmp_probe_results ((record->>'probe_status'));
CREATE TABLE snmp_probe_progress (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    cursor jsonb NOT NULL,
    summary jsonb NOT NULL,
    last_scan_id bigint REFERENCES scan_runs(id) ON DELETE SET NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
