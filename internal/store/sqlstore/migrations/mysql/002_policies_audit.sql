CREATE TABLE IF NOT EXISTS agent_policies (
    id VARCHAR(64) PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL UNIQUE,
    revision BIGINT NOT NULL,
    file_integrity_enabled BOOLEAN NOT NULL,
    file_watch_paths JSON NOT NULL,
    ssh_auth_enabled BOOLEAN NOT NULL,
    ssh_threshold INTEGER NOT NULL,
    ssh_window_seconds INTEGER NOT NULL,
    runtime_watch_enabled BOOLEAN NOT NULL,
    updated_at DATETIME(6) NOT NULL,
    CONSTRAINT agent_policies_agent_fk FOREIGN KEY (agent_id) REFERENCES agents(id),
    CHECK (revision > 0)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- mysafe:statement
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(128) PRIMARY KEY,
    actor VARCHAR(128) NOT NULL,
    action VARCHAR(128) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    occurred_at DATETIME(6) NOT NULL,
    details JSON NOT NULL,
    INDEX audit_logs_occurred_idx (occurred_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
