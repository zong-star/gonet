ALTER TABLE scan_interface_facts
    ADD COLUMN if_alias_collected boolean NOT NULL DEFAULT false;
