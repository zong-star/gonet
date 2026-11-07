-- gonet initial schema (eight domain tables). The migration runner wraps this
-- file in a transaction; do not add BEGIN/COMMIT here.

CREATE TABLE scan_runs (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  status text NOT NULL DEFAULT 'running'
    CHECK (status IN
      ('running','completed','partial','failed','aborted')),
  seed_ips inet[] NOT NULL,
  config_digest text NOT NULL,
  config_summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  summary jsonb NOT NULL DEFAULT '{}'::jsonb,
  termination_reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
  error_summary jsonb NOT NULL DEFAULT '[]'::jsonb,
  CHECK ((status = 'running') = (finished_at IS NULL)),
  CHECK (finished_at IS NULL OR finished_at >= started_at)
);

CREATE TABLE devices (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  identity_state text NOT NULL
    CHECK (identity_state IN ('provisional','verified','conflict')),
  classification_rule text NOT NULL,
  sys_name text,
  sys_descr text,
  sys_object_id text,
  vendor text,
  model text,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  last_collected_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (last_seen_at >= first_seen_at)
);

CREATE TABLE device_identities (
  identity_key text PRIMARY KEY CHECK (length(identity_key) > 0),
  device_id bigint NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  source text NOT NULL CHECK (source IN ('lldp','manual')),
  subtype smallint,
  raw_value bytea,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  CHECK (source <> 'lldp' OR
    (subtype IS NOT NULL AND subtype BETWEEN 1 AND 7
     AND raw_value IS NOT NULL AND octet_length(raw_value) > 0))
);
CREATE INDEX ix_identity_device ON device_identities(device_id);

CREATE TABLE device_addresses (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  device_id bigint NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  address inet NOT NULL,
  state text NOT NULL
    CHECK (state IN ('verified','retired','conflict')),
  source text NOT NULL CHECK (source IN ('seed','lldp','manual')),
  verified_at timestamptz NOT NULL,
  last_success_at timestamptz,
  retired_at timestamptz,
  CHECK (masklen(address) =
    CASE family(address) WHEN 4 THEN 32 ELSE 128 END),
  CHECK ((state = 'retired') = (retired_at IS NOT NULL))
);
CREATE UNIQUE INDEX uq_address_live ON device_addresses(address)
  WHERE state IN ('verified','conflict');
CREATE INDEX ix_address_device ON device_addresses(device_id);

CREATE TABLE ports (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  device_id bigint NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  port_key text NOT NULL CHECK (length(port_key) > 0),
  subtype smallint NOT NULL CHECK (subtype BETWEEN 1 AND 7),
  raw_id bytea NOT NULL CHECK (octet_length(raw_id) > 0),
  aliases jsonb NOT NULL DEFAULT '[]'::jsonb,
  display_name text NOT NULL,
  if_index integer CHECK (if_index > 0),
  lldp_local_num integer CHECK (lldp_local_num > 0),
  if_type integer,
  resolution text NOT NULL
    CHECK (resolution IN ('provisional','verified','conflict')),
  is_physical boolean NOT NULL,
  mapping_rule text NOT NULL,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (device_id, port_key),
  UNIQUE (device_id, id),
  CHECK (jsonb_typeof(aliases) = 'array')
);

CREATE TABLE links (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  device_a_id bigint NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  port_a_id bigint NOT NULL,
  device_b_id bigint NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  port_b_id bigint NOT NULL,
  protocol text NOT NULL DEFAULT 'lldp' CHECK (protocol = 'lldp'),
  confidence text NOT NULL
    CHECK (confidence IN ('single_sided','bidirectional')),
  discovery_state text NOT NULL DEFAULT 'active'
    CHECK (discovery_state IN ('active','suspect_stale','stale')),
  missed_complete_scans integer NOT NULL DEFAULT 0
    CHECK (missed_complete_scans >= 0),
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  last_seen_scan_id bigint NOT NULL REFERENCES scan_runs(id),
  last_evaluated_scan_id bigint NOT NULL REFERENCES scan_runs(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (device_a_id < device_b_id),
  CHECK (last_seen_at >= first_seen_at),
  CHECK ((discovery_state = 'active' AND missed_complete_scans = 0)
    OR (discovery_state = 'suspect_stale'
      AND missed_complete_scans BETWEEN 1 AND 2)
    OR (discovery_state = 'stale' AND missed_complete_scans >= 3)),
  FOREIGN KEY (device_a_id, port_a_id)
    REFERENCES ports(device_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (device_b_id, port_b_id)
    REFERENCES ports(device_id, id) ON DELETE RESTRICT,
  UNIQUE (device_a_id, port_a_id, device_b_id, port_b_id)
);
CREATE INDEX ix_links_b ON links(device_b_id);
CREATE INDEX ix_links_state_seen ON links(discovery_state,last_seen_at);
CREATE INDEX ix_links_port_a ON links(port_a_id);
CREATE INDEX ix_links_port_b ON links(port_b_id);

CREATE TABLE scan_devices (
  scan_id bigint NOT NULL REFERENCES scan_runs(id) ON DELETE RESTRICT,
  device_id bigint NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  depth integer NOT NULL CHECK (depth >= 0),
  target_ip inet,
  outcome text NOT NULL
    CHECK (outcome IN ('success','partial','failed','unscanned')),
  collection_complete boolean NOT NULL DEFAULT false,
  snapshot_stable boolean NOT NULL DEFAULT false,
  absence_eligible boolean NOT NULL DEFAULT false,
  reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
  component_status jsonb NOT NULL DEFAULT '{}'::jsonb,
  attempts jsonb NOT NULL DEFAULT '[]'::jsonb,
  collected_at timestamptz,
  PRIMARY KEY (scan_id,device_id),
  CHECK (NOT absence_eligible OR
    (collection_complete AND snapshot_stable AND outcome = 'success')),
  CHECK (target_ip IS NULL OR masklen(target_ip) =
    CASE family(target_ip) WHEN 4 THEN 32 ELSE 128 END)
);
CREATE INDEX ix_scan_devices_device ON scan_devices(device_id,scan_id);

CREATE TABLE observations (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  scan_id bigint NOT NULL REFERENCES scan_runs(id) ON DELETE RESTRICT,
  observer_device_id bigint REFERENCES devices(id) ON DELETE RESTRICT,
  observation_key text NOT NULL,
  collected_at timestamptz NOT NULL,
  row_time_mark bigint NOT NULL CHECK (row_time_mark BETWEEN 0 AND 4294967295),
  local_port_num integer NOT NULL CHECK (local_port_num > 0),
  remote_index integer NOT NULL CHECK (remote_index > 0),
  raw_neighbor jsonb NOT NULL,
  resolution text NOT NULL
    CHECK (resolution IN ('resolved','unresolved','excluded','conflict')),
  reason_codes jsonb NOT NULL DEFAULT '[]'::jsonb,
  link_id bigint REFERENCES links(id) ON DELETE RESTRICT,
  seen_from text CHECK (seen_from IN ('a','b')),
  UNIQUE (scan_id,observation_key),
  CHECK ((resolution = 'resolved') =
    (link_id IS NOT NULL AND seen_from IS NOT NULL)),
  CHECK ((link_id IS NULL) = (seen_from IS NULL))
);
CREATE INDEX ix_observation_scan ON observations(scan_id,resolution);
CREATE INDEX ix_observation_link ON observations(link_id);
CREATE INDEX ix_runs_started ON scan_runs(started_at DESC);
CREATE INDEX ix_devices_seen ON devices(last_seen_at);
