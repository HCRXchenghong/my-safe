CREATE TABLE IF NOT EXISTS agents (
    id VARCHAR(64) PRIMARY KEY,
    machine_id VARCHAR(128) NOT NULL UNIQUE,
    hostname VARCHAR(255) NOT NULL,
    version VARCHAR(64) NOT NULL,
    platform VARCHAR(32) NOT NULL,
    architecture VARCHAR(32) NOT NULL,
    credential_hash BINARY(32) NOT NULL,
    registered_at DATETIME(6) NOT NULL,
    last_seen_at DATETIME(6) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- mysafe:statement
CREATE TABLE IF NOT EXISTS security_events (
    id VARCHAR(128) PRIMARY KEY,
    agent_id VARCHAR(64) NOT NULL,
    kind VARCHAR(128) NOT NULL,
    severity VARCHAR(16) NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    summary TEXT NOT NULL,
    occurred_at DATETIME(6) NOT NULL,
    received_at DATETIME(6) NOT NULL,
    evidence JSON NOT NULL,
    CONSTRAINT security_events_agent_fk FOREIGN KEY (agent_id) REFERENCES agents(id),
    INDEX security_events_received_idx (received_at DESC),
    INDEX security_events_severity_received_idx (severity, received_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
