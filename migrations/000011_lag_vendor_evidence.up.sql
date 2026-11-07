ALTER TABLE scan_lag_members DROP CONSTRAINT scan_lag_members_source_check;
ALTER TABLE scan_lag_members ADD CONSTRAINT scan_lag_members_source_check
    CHECK (source IN ('if_stack','ieee_lag','huawei_private','h3c_private'));
ALTER TABLE scan_lag_members ADD COLUMN configured BOOLEAN;
ALTER TABLE scan_lag_members ADD COLUMN selected BOOLEAN;
ALTER TABLE scan_lag_members ADD COLUMN attached BOOLEAN;
ALTER TABLE scan_lag_members ADD COLUMN sources JSONB NOT NULL DEFAULT '[]';

CREATE TABLE scan_lag_groups (
    scan_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    group_key TEXT NOT NULL,
    aggregate_if_index INTEGER,
    facts JSONB NOT NULL,
    PRIMARY KEY (scan_id,device_id,group_key),
    FOREIGN KEY (scan_id,device_id) REFERENCES scan_devices(scan_id,device_id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id,device_id,aggregate_if_index)
        REFERENCES scan_interface_facts(scan_id,device_id,if_index) ON DELETE CASCADE
);

CREATE TABLE scan_lag_evidence (
    scan_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal > 0),
    kind TEXT NOT NULL CHECK (kind IN ('source','advertisement','lacp')),
    facts JSONB NOT NULL,
    PRIMARY KEY (scan_id,device_id,ordinal),
    FOREIGN KEY (scan_id,device_id) REFERENCES scan_devices(scan_id,device_id) ON DELETE CASCADE
);
