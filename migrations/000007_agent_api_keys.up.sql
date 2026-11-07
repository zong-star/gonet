CREATE TABLE agent_api_keys (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    key_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(key_hash) = 32),
    key_preview VARCHAR(48) NOT NULL,
    allowed_ips CIDR[] NOT NULL CHECK (cardinality(allowed_ips) > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Record the one-time runtime import independently of any individual Key so
-- an emergency deletion cannot bring the legacy credential back on restart.
CREATE TABLE agent_api_legacy_import (
    singleton BOOLEAN PRIMARY KEY CHECK (singleton),
    imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
