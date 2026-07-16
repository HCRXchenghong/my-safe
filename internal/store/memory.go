package store

import (
	"context"
	"sort"
	"sync"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

// Memory is a concurrency-safe development store and contract-test oracle.
// It is never selected implicitly for a production configuration.
type Memory struct {
	mu             sync.RWMutex
	agents         map[string]domain.Agent
	agentByMachine map[string]string
	events         map[string]domain.Event
	policies       map[string]domain.Policy
	audits         map[string]domain.AuditLog
}

func NewMemory() *Memory {
	return &Memory{
		agents:         make(map[string]domain.Agent),
		agentByMachine: make(map[string]string),
		events:         make(map[string]domain.Event),
		policies:       make(map[string]domain.Policy),
		audits:         make(map[string]domain.AuditLog),
	}
}

func (m *Memory) PolicyForAgent(_ context.Context, agentID string) (domain.Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	policy, ok := m.policies[agentID]
	if !ok {
		return domain.Policy{}, ErrNotFound
	}
	policy.FileWatchPaths = append([]string(nil), policy.FileWatchPaths...)
	return policy, nil
}

func (m *Memory) SavePolicyAndAudit(_ context.Context, policy domain.Policy, expectedRevision int64, audit domain.AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, exists := m.policies[policy.AgentID]
	if (!exists && expectedRevision != 0) || (exists && current.Revision != expectedRevision) || policy.Revision != expectedRevision+1 {
		return ErrConflict
	}
	if _, exists := m.audits[audit.ID]; exists {
		return ErrConflict
	}
	policy.FileWatchPaths = append([]string(nil), policy.FileWatchPaths...)
	audit.Details = cloneMap(audit.Details)
	m.policies[policy.AgentID] = policy
	m.audits[audit.ID] = audit
	return nil
}

func (m *Memory) ListAuditLogs(_ context.Context, limit int) ([]domain.AuditLog, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit = normalizeLimit(limit)
	logs := make([]domain.AuditLog, 0, len(m.audits))
	for _, audit := range m.audits {
		audit.Details = cloneMap(audit.Details)
		logs = append(logs, audit)
	}
	sort.Slice(logs, func(i, j int) bool { return logs[i].OccurredAt.After(logs[j].OccurredAt) })
	if len(logs) > limit {
		logs = logs[:limit]
	}
	return logs, nil
}

func (m *Memory) CreateAgent(_ context.Context, agent domain.Agent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.agents[agent.ID]; exists {
		return ErrConflict
	}
	if _, exists := m.agentByMachine[agent.MachineID]; exists {
		return ErrConflict
	}
	agent.CredentialHash = append([]byte(nil), agent.CredentialHash...)
	m.agents[agent.ID] = agent
	m.agentByMachine[agent.MachineID] = agent.ID
	return nil
}

func (m *Memory) AgentByID(_ context.Context, id string) (domain.Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	agent, ok := m.agents[id]
	if !ok {
		return domain.Agent{}, ErrNotFound
	}
	agent.CredentialHash = append([]byte(nil), agent.CredentialHash...)
	return agent, nil
}

func (m *Memory) AgentByMachineID(_ context.Context, machineID string) (domain.Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.agentByMachine[machineID]
	if !ok {
		return domain.Agent{}, ErrNotFound
	}
	agent := m.agents[id]
	agent.CredentialHash = append([]byte(nil), agent.CredentialHash...)
	return agent, nil
}

func (m *Memory) UpdateHeartbeat(_ context.Context, id string, heartbeat domain.Heartbeat) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	agent, ok := m.agents[id]
	if !ok {
		return ErrNotFound
	}
	agent.LastSeenAt = heartbeat.SentAt
	if heartbeat.AgentVersion != "" {
		agent.Version = heartbeat.AgentVersion
	}
	m.agents[id] = agent
	return nil
}

func (m *Memory) ListAgents(_ context.Context, limit int) ([]domain.Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit = normalizeLimit(limit)
	agents := make([]domain.Agent, 0, len(m.agents))
	for _, agent := range m.agents {
		agent.CredentialHash = nil
		agents = append(agents, agent)
	}
	sort.Slice(agents, func(i, j int) bool {
		return agents[i].RegisteredAt.After(agents[j].RegisteredAt)
	})
	if len(agents) > limit {
		agents = agents[:limit]
	}
	return agents, nil
}

func (m *Memory) SaveEvents(_ context.Context, events []domain.Event) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inserted := 0
	for _, event := range events {
		if _, exists := m.events[event.ID]; exists {
			continue
		}
		event.Evidence = cloneMap(event.Evidence)
		m.events[event.ID] = event
		inserted++
	}
	return inserted, nil
}

func (m *Memory) ListAlerts(_ context.Context, filter domain.AlertFilter) ([]domain.Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	limit := normalizeLimit(filter.Limit)
	events := make([]domain.Event, 0, len(m.events))
	for _, event := range m.events {
		if filter.Severity != "" && event.Severity != filter.Severity {
			continue
		}
		event.Evidence = cloneMap(event.Evidence)
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		return events[i].ReceivedAt.After(events[j].ReceivedAt)
	})
	if len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 500 {
		return 500
	}
	return limit
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = cloneValue(value)
	}
	return output
}

func cloneValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return cloneMap(typed)
	case []any:
		cloned := make([]any, len(typed))
		for index := range typed {
			cloned[index] = cloneValue(typed[index])
		}
		return cloned
	default:
		return value
	}
}
