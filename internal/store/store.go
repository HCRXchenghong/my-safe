package store

import (
	"context"
	"errors"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

// Store is the transactional boundary used by the control plane. Database
// implementations must provide the same idempotency guarantees as Memory.
type Store interface {
	CreateAgent(context.Context, domain.Agent) error
	AgentByID(context.Context, string) (domain.Agent, error)
	AgentByMachineID(context.Context, string) (domain.Agent, error)
	UpdateHeartbeat(context.Context, string, domain.Heartbeat) error
	ListAgents(context.Context, int) ([]domain.Agent, error)
	SaveEvents(context.Context, []domain.Event) (int, error)
	ListAlerts(context.Context, domain.AlertFilter) ([]domain.Event, error)
	PolicyForAgent(context.Context, string) (domain.Policy, error)
	SavePolicyAndAudit(context.Context, domain.Policy, int64, domain.AuditLog) error
	ListAuditLogs(context.Context, int) ([]domain.AuditLog, error)
}
