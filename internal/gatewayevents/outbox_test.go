package gatewayevents

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

func TestOfflineEventPersistsThenFlushes(t *testing.T) {
	t.Parallel()
	online := false
	received := make([]domain.Event, 0)
	now := time.Date(2026, 7, 16, 16, 0, 0, 0, time.UTC)
	outbox, err := New(Config{
		StateDir: t.TempDir(), SocketPath: "/tmp/test-mysafe-events.sock", Now: func() time.Time { return now },
		Send: func(_ context.Context, _ string, event domain.Event) error {
			if !online {
				return errors.New("Agent offline")
			}
			received = append(received, event)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	event := gatewayEvent(now, "evt_gateway_offline")
	if err := outbox.Emit(event); err != nil {
		t.Fatal(err)
	}
	files, err := outboxFiles(outbox.directory)
	if err != nil || len(files) != 1 {
		t.Fatalf("outbox files = %#v, %v", files, err)
	}
	online = true
	flushed, err := outbox.Flush(context.Background(), 10)
	if err != nil || flushed != 1 || len(received) != 1 || received[0].ID != event.ID {
		t.Fatalf("Flush() = %d, %v; received=%#v", flushed, err, received)
	}
	files, err = outboxFiles(outbox.directory)
	if err != nil || len(files) != 0 {
		t.Fatalf("outbox after flush = %#v, %v", files, err)
	}
}

func TestOutboxLimitDoesNotDiscardOldestEvent(t *testing.T) {
	t.Parallel()
	outbox, err := New(Config{
		StateDir: t.TempDir(), SocketPath: "/tmp/test-mysafe-events.sock", MaxEvents: 1,
		Send: func(context.Context, string, domain.Event) error { return errors.New("offline") },
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := outbox.Emit(gatewayEvent(now, "evt_gateway_one")); err != nil {
		t.Fatal(err)
	}
	if err := outbox.Emit(gatewayEvent(now, "evt_gateway_two")); err == nil {
		t.Fatal("full outbox silently discarded an event")
	}
	files, err := outboxFiles(outbox.directory)
	if err != nil || len(files) != 1 {
		t.Fatalf("outbox files = %#v, %v", files, err)
	}
}

func gatewayEvent(now time.Time, eventID string) domain.Event {
	return domain.Event{
		ID: eventID, Kind: "gateway.waf.rule_match", Severity: domain.SeverityHigh,
		Summary: "WAF rule matched", OccurredAt: now,
		Evidence: map[string]any{"rule_id": 942100, "mode": "block", "disruptive": true},
	}
}
