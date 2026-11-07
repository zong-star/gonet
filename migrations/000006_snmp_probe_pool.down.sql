DROP TABLE IF EXISTS snmp_probe_progress;
DROP TABLE IF EXISTS snmp_probe_results;
UPDATE device_addresses SET source=CASE WHEN source='manual_supplement' THEN 'manual' ELSE 'lldp' END
    WHERE source IN ('snmp_preprobe','probe_cache','manual_supplement');
ALTER TABLE device_addresses DROP CONSTRAINT device_addresses_source_check;
ALTER TABLE device_addresses ADD CONSTRAINT device_addresses_source_check CHECK (source IN ('seed','lldp','manual'));
