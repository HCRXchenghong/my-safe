package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

func TestEncryptedQueuePersistsWithoutPlaintext(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	queue, err := OpenEncryptedQueue(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	marker := "PLAINTEXT-SENTINEL-MUST-NOT-APPEAR"
	event := domain.Event{
		ID:         "evt-queue-1",
		Kind:       "host.scan",
		Severity:   domain.SeverityInfo,
		Summary:    marker,
		OccurredAt: time.Now().UTC(),
		Evidence:   map[string]any{"safe": true},
	}
	if err := queue.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	files, err := queueFiles(filepath.Join(stateDir, queueDirectory))
	if err != nil || len(files) != 1 {
		t.Fatalf("queue files = %#v, %v", files, err)
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, queueDirectory, files[0]))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(marker)) {
		t.Fatal("queued event contains plaintext summary")
	}

	reopened, err := OpenEncryptedQueue(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	batch, err := reopened.Peek(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Events) != 1 || batch.Events[0].Summary != marker {
		t.Fatalf("Peek() = %#v", batch.Events)
	}
	if err := reopened.Ack(batch); err != nil {
		t.Fatal(err)
	}
	length, err := reopened.Len()
	if err != nil || length != 0 {
		t.Fatalf("Len() = %d, %v", length, err)
	}
}

func TestIdentityPersistsRegistrationCredentials(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	identity, err := LoadIdentity(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if identity.MachineID == "" || identity.Registered() {
		t.Fatalf("initial identity = %#v", identity)
	}
	identity.AgentID = "agent-1"
	identity.Credential = "credential-1"
	if err := SaveCredentials(stateDir, identity); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadIdentity(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded != identity {
		t.Fatalf("reloaded identity = %#v, want %#v", reloaded, identity)
	}
}
