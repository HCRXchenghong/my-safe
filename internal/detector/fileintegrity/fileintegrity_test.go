package fileintegrity

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBaselineThenDetectsCreateModifyDeleteWithoutFileContent(t *testing.T) {
	t.Parallel()
	watch := t.TempDir()
	state := t.TempDir()
	firstPath := filepath.Join(watch, "app.conf")
	secret := "database-password-must-not-leak"
	if err := os.WriteFile(firstPath, []byte("initial"), 0o640); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	detector, err := New(Config{StateDir: state, Paths: []string{watch}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	initial, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(initial.Events) != 0 {
		t.Fatalf("initial scan events = %#v", initial.Events)
	}
	if err := initial.Commit(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(firstPath, []byte(secret), 0o640); err != nil {
		t.Fatal(err)
	}
	createdPath := filepath.Join(watch, "new.conf")
	if err := os.WriteFile(createdPath, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(changed.Events) != 2 {
		t.Fatalf("changed events = %#v", changed.Events)
	}
	for _, event := range changed.Events {
		encoded, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), secret) {
			t.Fatal("file content leaked into integrity event")
		}
		if event.Kind != "file.integrity.changed" || event.Evidence["path"] == "" {
			t.Fatalf("change event = %#v", event)
		}
	}

	// Baseline advancement is explicit. Until Commit succeeds, the same
	// observation produces the same idempotency keys.
	repeated, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(repeated.Events) != 2 || repeated.Events[0].ID != changed.Events[0].ID || repeated.Events[1].ID != changed.Events[1].ID {
		t.Fatalf("uncommitted repeat = %#v", repeated.Events)
	}
	if err := changed.Commit(); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(firstPath); err != nil {
		t.Fatal(err)
	}
	deleted, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(deleted.Events) != 1 || deleted.Events[0].Evidence["change"] != "deleted" {
		t.Fatalf("deleted events = %#v", deleted.Events)
	}
	if err := deleted.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestFileLimitDoesNotCommitPartialBaseline(t *testing.T) {
	t.Parallel()
	watch := t.TempDir()
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(watch, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	state := t.TempDir()
	detector, err := New(Config{StateDir: state, Paths: []string{watch}, MaxFiles: 1})
	if err != nil {
		t.Fatal(err)
	}
	result, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 || result.Events[0].Kind != "file.integrity.coverage_limited" {
		t.Fatalf("limited scan events = %#v", result.Events)
	}
	if err := result.Commit(); err != nil {
		t.Fatal(err)
	}
	_, err = os.Stat(filepath.Join(state, "detectors", baselineFilename))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial baseline was persisted: %v", err)
	}
}

func TestCorruptBaselineIsRejected(t *testing.T) {
	t.Parallel()
	watch := t.TempDir()
	state := t.TempDir()
	directory := filepath.Join(state, "detectors")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, baselineFilename), []byte(`{"schema_version":1,"entries":{},"unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	detector, err := New(Config{StateDir: state, Paths: []string{watch}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := detector.Scan(context.Background()); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("corrupt baseline error = %v", err)
	}
}
