CREATE TABLE scan_interface_facts (
    scan_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    if_index INTEGER NOT NULL CHECK (if_index > 0),
    if_name TEXT NOT NULL,
    if_descr TEXT NOT NULL,
    if_alias TEXT NOT NULL,
    if_type INTEGER NOT NULL,
    port_id BIGINT,
    collected_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scan_id, device_id, if_index),
    UNIQUE (scan_id, device_id, port_id),
    FOREIGN KEY (scan_id, device_id) REFERENCES scan_devices(scan_id, device_id) ON DELETE CASCADE,
    FOREIGN KEY (device_id, port_id) REFERENCES ports(device_id, id) ON DELETE RESTRICT
);

CREATE TABLE scan_lag_members (
    scan_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    aggregate_if_index INTEGER NOT NULL,
    member_if_index INTEGER NOT NULL,
    source TEXT NOT NULL CHECK (source IN ('if_stack', 'ieee_lag')),
    mode TEXT NOT NULL CHECK (mode IN ('lacp', 'static', 'unknown')),
    status TEXT NOT NULL CHECK (status IN ('confirmed', 'conflict')),
    CHECK (aggregate_if_index <> member_if_index),
    PRIMARY KEY (scan_id, device_id, member_if_index, aggregate_if_index),
    FOREIGN KEY (scan_id, device_id, aggregate_if_index)
        REFERENCES scan_interface_facts(scan_id, device_id, if_index) ON DELETE CASCADE,
    FOREIGN KEY (scan_id, device_id, member_if_index)
        REFERENCES scan_interface_facts(scan_id, device_id, if_index) ON DELETE CASCADE
);

CREATE INDEX ix_observations_link_scan
    ON observations (link_id, scan_id, observer_device_id, id DESC) WHERE link_id IS NOT NULL;
