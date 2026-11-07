-- LLDP row indexes are transient uint32 values, not device identifiers.
ALTER TABLE observations ALTER COLUMN remote_index TYPE bigint;
ALTER TABLE observations ADD CONSTRAINT ck_observation_remote_uint32
    CHECK (remote_index BETWEEN 1 AND 4294967295);
