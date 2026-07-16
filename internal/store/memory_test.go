package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

func TestMemoryStoreAgentAndEventContracts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC()
	memory := NewMemory()
	agent := domain.Agent{
		ID:             "agent-1",
		MachineID:      "machine-1",
		Hostname:       "server-1",
		Version:        "test",
		Platform:       "linux",
		Architecture:   "amd64",
		CredentialHash: []byte("hash"),
		RegisteredAt:   now,
		LastSeenAt:     now,
	}
	if err := memory.CreateAgent(ctx, agent); err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}
	if err := memory.CreateAgent(ctx, agent); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate CreateAgent() error = %v, want conflict", err)
	}
	gotAgent, err := memory.AgentByMachineID(ctx, "machine-1")
	if err != nil || gotAgent.ID != agent.ID {
		t.Fatalf("AgentByMachineID() = %#v, %v", gotAgent, err)
	}

	event := domain.Event{
		ID:         "event-1",
		AgentID:    agent.ID,
		Kind:       "host.scan",
		Severity:   domain.SeverityInfo,
		Summary:    "scan completed",
		OccurredAt: now,
		ReceivedAt: now,
		Evidence:   map[string]any{"platform": "linux"},
	}
	inserted, err := memory.SaveEvents(ctx, []domain.Event{event, event})
	if err != nil || inserted != 1 {
		t.Fatalf("SaveEvents() = %d, %v; want 1, nil", inserted, err)
	}
	alerts, err := memory.ListAlerts(ctx, domain.AlertFilter{Limit: 10})
	if err != nil || len(alerts) != 1 || alerts[0].ID != event.ID {
		t.Fatalf("ListAlerts() = %#v, %v", alerts, err)
	}
	event.Evidence["platform"] = "mutated"
	alerts[0].Evidence["platform"] = "also-mutated"
	again, err := memory.ListAlerts(ctx, domain.AlertFilter{Limit: 10})
	if err != nil || again[0].Evidence["platform"] != "linux" {
		t.Fatalf("stored evidence was mutated through an external map: %#v, %v", again, err)
	}
}
