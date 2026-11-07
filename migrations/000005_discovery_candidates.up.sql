-- Additive migration: retain all devices, ports, links and raw observations.
-- A candidate is an identity, never a management IP. Multiple physical edges
-- remain separate observations; this row stores their aggregate access state.
CREATE TABLE discovery_candidates (
  candidate_key text PRIMARY KEY,
  chassis_subtype smallint NOT NULL,
  chassis_raw bytea,
  sys_name text NOT NULL DEFAULT '',
  reported_management_addresses jsonb NOT NULL DEFAULT '[]'::jsonb,
  verification jsonb NOT NULL DEFAULT '{}'::jsonb,
  source_device_id bigint REFERENCES devices(id) ON DELETE RESTRICT,
  source_port bigint NOT NULL CHECK (source_port BETWEEN 0 AND 4294967295),
  device_id bigint REFERENCES devices(id) ON DELETE RESTRICT,
  first_discovered_at timestamptz NOT NULL,
  last_discovered_at timestamptz NOT NULL,
  last_seen_scan_id bigint REFERENCES scan_runs(id) ON DELETE SET NULL
);
CREATE INDEX ix_candidate_device ON discovery_candidates(device_id);

-- Backfill the latest retained unresolved observations. Opaque chassis values
-- stay scoped to their source and port; an IP/name never becomes an identity.
INSERT INTO discovery_candidates(candidate_key,chassis_subtype,chassis_raw,sys_name,
  reported_management_addresses,source_device_id,source_port,
  first_discovered_at,last_discovered_at,last_seen_scan_id)
SELECT DISTINCT ON (candidate_key) candidate_key,subtype,raw_id,sys_name,addresses,
  observer_device_id,local_port_num,collected_at,collected_at,scan_id
FROM (
  SELECT CASE
    WHEN subtype=4 AND octet_length(raw_id)=6 AND get_byte(raw_id,0)%2=0 AND raw_id<>decode('000000000000','hex')
      THEN 'lldp:4:' || encode(raw_id,'hex')
    WHEN subtype IN (4,7) AND encode(raw_id,'escape') ~* '^([0-9a-f]{12}|([0-9a-f]{2}:){5}[0-9a-f]{2}|([0-9a-f]{2}-){5}[0-9a-f]{2}|([0-9a-f]{4}[.]){2}[0-9a-f]{4}|([0-9a-f]{4}-){2}[0-9a-f]{4})$'
      THEN 'lldp:' || subtype::text || ':' || lower(regexp_replace(encode(raw_id,'escape'),'[^0-9a-fA-F]','','g'))
    ELSE 'unresolved:' || COALESCE(observer_device_id,0)::text || ':' || local_port_num::text || ':' || remote_index::text || ':lldp:' || subtype::text || ':' || encode(raw_id,'hex')
    END AS candidate_key, historical.*
  FROM (
    SELECT COALESCE((raw_neighbor->'chassis'->>'subtype')::smallint,0) AS subtype,
      decode(COALESCE(raw_neighbor->'chassis'->>'raw',''),'base64') AS raw_id,
      COALESCE(raw_neighbor->>'sys_name','') AS sys_name,
      COALESCE(NULLIF(raw_neighbor->'mgmt_addresses','null'::jsonb),'[]'::jsonb) AS addresses,
      observer_device_id,local_port_num,remote_index,collected_at,scan_id
    FROM observations WHERE resolution IN ('unresolved','conflict')
      AND scan_id=(SELECT max(id) FROM scan_runs WHERE status IN ('completed','partial'))
  ) historical
) normalized
ORDER BY candidate_key,collected_at DESC;
