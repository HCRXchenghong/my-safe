CREATE TABLE IF NOT EXISTS agents (
    id VARCHAR(64) PRIMARY KEY,
    machine_id VARCHAR(128) NOT NULL UNIQUE,
    hostname VARCHAR(255) NOT NULL,
    version VARCHAR(64) NOT NULL,
    platform VARCHAR(32) NOT NULL,
    architecture VARCHAR(32) NOT NULL,
    credential_hash BYTEA NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL
);

-- mysafe:statement
CREATE TABLE IF NOT EXISTS security_events (
    id VARCHAR(128) PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL REFERENCES agents(id),
    kind VARCHAR(128) NOT NULL,
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    summary TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    evidence JSONB NOT NULL
);

-- mysafe:statement
CREATE INDEX IF NOT EXISTS security_events_received_idx ON security_events (received_at DESC);

-- mysafe:statement
CREATE INDEX IF NOT EXISTS security_events_severity_received_idx ON security_events (severity, received_at DESC);
