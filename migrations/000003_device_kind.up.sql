-- Existing formal records are switches; new kinds retain the same identities.
ALTER TABLE devices ADD COLUMN device_kind text NOT NULL DEFAULT 'switch'
  CHECK (device_kind IN ('switch','router','wireless_controller'));
