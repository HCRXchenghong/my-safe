package domain

import "time"

// Severity is an ordered security finding severity.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func (s Severity) Valid() bool {
	switch s {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// Agent is the control-plane representation of an installed server agent.
// CredentialHash is never serialized or returned through the API.
type Agent struct {
	ID             string    `json:"id"`
	MachineID      string    `json:"machine_id"`
	Hostname       string    `json:"hostname"`
	Version        string    `json:"version"`
	Platform       string    `json:"platform"`
	Architecture   string    `json:"architecture"`
	CredentialHash []byte    `json:"-"`
	RegisteredAt   time.Time `json:"registered_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
}

// Heartbeat contains intentionally small, non-sensitive liveness metadata.
type Heartbeat struct {
	AgentVersion string    `json:"agent_version"`
	QueueDepth   int       `json:"queue_depth"`
	SentAt       time.Time `json:"sent_at"`
}

// Event is a normalized, minimal security observation. Evidence must already
// be minimized by the agent and is redacted again by the control plane.
type Event struct {
	ID         string         `json:"id"`
	AgentID    string         `json:"agent_id"`
	Kind       string         `json:"kind"`
	Severity   Severity       `json:"severity"`
	Summary    string         `json:"summary"`
	OccurredAt time.Time      `json:"occurred_at"`
	ReceivedAt time.Time      `json:"received_at"`
	Evidence   map[string]any `json:"evidence,omitempty"`
}

// AlertFilter bounds alert listing. Limit is normalized by the store.
type AlertFilter struct {
	Severity Severity
	Limit    int
}

// Policy is a bounded Agent security policy. Revision is monotonically
// increased through optimistic concurrency in the repository.
type Policy struct {
	ID                   string    `json:"id"`
	AgentID              string    `json:"agent_id"`
	Revision             int64     `json:"revision"`
	FileIntegrityEnabled bool      `json:"file_integrity_enabled"`
	FileWatchPaths       []string  `json:"file_watch_paths"`
	SSHAuthEnabled       bool      `json:"ssh_auth_enabled"`
	SSHThreshold         int       `json:"ssh_threshold"`
	SSHWindowSeconds     int       `json:"ssh_window_seconds"`
	RuntimeWatchEnabled  bool      `json:"runtime_watch_enabled"`
	UpdatedAt            time.Time `json:"updated_at"`
}

type AuditLog struct {
	ID         string         `json:"id"`
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	OccurredAt time.Time      `json:"occurred_at"`
	Details    map[string]any `json:"details,omitempty"`
}
