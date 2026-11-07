-- Down migration for the initial schema. Only valid on an empty temporary test
-- database; the production CLI does not expose automatic down migrations.
DROP TABLE IF EXISTS observations;
DROP TABLE IF EXISTS scan_devices;
DROP TABLE IF EXISTS links;
DROP TABLE IF EXISTS ports;
DROP TABLE IF EXISTS device_addresses;
DROP TABLE IF EXISTS device_identities;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS scan_runs;
