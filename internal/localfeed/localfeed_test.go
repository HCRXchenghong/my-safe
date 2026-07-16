package localfeed

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

func TestDecodeRejectsUnknownAndServerOwnedFields(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 16, 0, 0, 0, time.UTC)
	event := testEvent(now)
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(encoded, now); err != nil {
		t.Fatal(err)
	}
	withUnknown := strings.TrimSuffix(string(encoded), "}") + `,"unknown":true}`
	if _, err := Decode([]byte(withUnknown), now); err == nil {
		t.Fatal("local event with an unknown field was accepted")
	}
	event.AgentID = "spoofed-agent"
	if err := Validate(event, now); err == nil {
		t.Fatal("local event spoofed a server-owned Agent ID")
	}
}

func TestUnixDatagramRoundTrip(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not provide the production Unix datagram permission model")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "events.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	received := make(chan domain.Event, 1)
	errors := make(chan error, 1)
	go func() {
		errors <- Listen(ctx, path, func(event domain.Event) error {
			received <- event
			return nil
		})
	}()
	for attempt := 0; attempt < 100; attempt++ {
		if _, err := os.Lstat(path); err == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	event := testEvent(time.Now().UTC())
	if err := Send(context.Background(), path, event); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if got.ID != event.ID || got.Kind != event.Kind {
			t.Fatalf("received event = %#v", got)
		}
	case err := <-errors:
		t.Fatalf("listener stopped early: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for local event")
	}
	cancel()
	select {
	case err := <-errors:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("listener did not stop")
	}
}

func testEvent(now time.Time) domain.Event {
	return domain.Event{
		ID: "evt_gateway_test", Kind: "gateway.waf.rule_match", Severity: domain.SeverityHigh,
		Summary: "WAF rule matched", OccurredAt: now,
		Evidence: map[string]any{"rule_id": 942100, "disruptive": true},
	}
}
