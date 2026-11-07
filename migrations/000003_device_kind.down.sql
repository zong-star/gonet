-- Refuse a rollback that would silently reclassify routers/controllers as switches.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM devices WHERE device_kind <> 'switch') THEN
    RAISE EXCEPTION 'cannot remove device_kind while non-switch devices exist';
  END IF;
END $$;
ALTER TABLE devices DROP COLUMN device_kind;
