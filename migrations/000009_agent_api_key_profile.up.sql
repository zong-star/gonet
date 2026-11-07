ALTER TABLE agent_api_keys ADD COLUMN profile TEXT NOT NULL DEFAULT 'topology_read'
    CHECK (profile IN ('topology_read', 'topology_compact'));
