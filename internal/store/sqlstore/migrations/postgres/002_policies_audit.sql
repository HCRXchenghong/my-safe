CREATE TABLE IF NOT EXISTS agent_policies (
    id VARCHAR(64) PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL UNIQUE REFERENCES agents(id),
    revision BIGINT NOT NULL CHECK (revision > 0),
    file_integrity_enabled BOOLEAN NOT NULL,
    file_watch_paths JSONB NOT NULL,
    ssh_auth_enabled BOOLEAN NOT NULL,
    ssh_threshold INTEGER NOT NULL,
    ssh_window_seconds INTEGER NOT NULL,
    runtime_watch_enabled BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- mysafe:statement
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(128) PRIMARY KEY,
    actor VARCHAR(128) NOT NULL,
    action VARCHAR(128) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    details JSONB NOT NULL
);

-- mysafe:statement
CREATE INDEX IF NOT EXISTS audit_logs_occurred_idx ON audit_logs (occurred_at DESC);
