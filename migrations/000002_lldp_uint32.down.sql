-- Refuse narrowing if an actual uint32 index cannot fit int32.
ALTER TABLE observations DROP CONSTRAINT ck_observation_remote_uint32;
ALTER TABLE observations ALTER COLUMN remote_index TYPE integer;
